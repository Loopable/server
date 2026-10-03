package server

import (
	"context"
	"errors"

	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/events"
)

// usernamePageSize bounds one page of the lifecycle scan behind the
// availability check.
const usernamePageSize = 512

// checkUsername enforces the instance-local registration rules of 40.2 and
// 40.3 on the two events that claim a name. The caller holds Server.usernameMu,
// so this check and the store that answers it form one critical section and two
// accounts cannot claim one name.
func (s *Server) checkUsername(ctx context.Context, event events.Event) error {
	var stored []StoredEvent
	switch event.EventType {
	case 0:
		homeInstance, err := eventBodyBytes(event.Body, 2)
		if err != nil {
			return err
		}
		if !s.instanceDocument().Hosts(homeInstance) {
			// 40.2 is instance-local: the same username on another instance is
			// a different account (11.4) and does not occupy this namespace.
			return nil
		}
	case 4:
		accountEvents, err := s.cfg.Events.EventsForAccount(ctx, event.AccountID)
		if err != nil {
			return err
		}
		_, homeInstance, err := accountGenesis(accountEvents)
		if err != nil {
			return err
		}
		if !s.instanceDocument().Hosts(homeInstance) {
			return nil
		}
		stored = accountEvents
	}

	username, err := eventBodyText(event.Body, 1)
	if err != nil {
		return err
	}
	if event.EventType == 4 {
		if err := s.checkReleasedUsername(stored, event); err != nil {
			return err
		}
	}

	claims, err := s.usernameClaims(ctx)
	if err != nil {
		return err
	}
	if !accounts.UsernameAvailable(claims, username, event.AccountID, s.cfg.Now()) {
		return accounts.ErrUsernameUnavailable
	}
	return nil
}

// checkReleasedUsername enforces 34.7: the change must release the account's
// current canonical username. Without that, the 40.3 reservation would be taken
// from a name the account never held and block its real owner for 90 days.
func (s *Server) checkReleasedUsername(stored []StoredEvent, event events.Event) error {
	released, err := eventBodyText(event.Body, 0)
	if err != nil {
		return err
	}
	state, err := accounts.DeriveAccountUsernames(storedEvents(stored))
	if err != nil {
		return err
	}
	if accounts.NormalizeUsername(released) != state.Current {
		return asInvalidRequest(accounts.ErrUsernameMismatch)
	}
	return nil
}

// usernameClaims derives this instance's username state from the event log.
// The log is the only state: no index can drift from the events that justify
// it, and accounts registered before this check existed are accounted for
// without a migration. The scan is linear in the account lifecycle events,
// which registration is rare enough to absorb.
func (s *Server) usernameClaims(ctx context.Context) ([]accounts.UsernameClaim, error) {
	lifecycle := make([]events.Event, 0, usernamePageSize)
	var cursor uint64
	for {
		page, more, err := s.cfg.Events.EventsAfter(ctx, cursor, accounts.UsernameEventTypes(), usernamePageSize)
		if err != nil {
			return nil, err
		}
		for _, item := range page {
			lifecycle = append(lifecycle, item.Event)
		}
		if !more {
			return accounts.DeriveUsernameClaims(lifecycle, s.instanceDocument().InstanceID)
		}
		if len(page) == 0 {
			return nil, errors.New("username scan did not advance its cursor")
		}
		cursor = page[len(page)-1].Seq
	}
}

func storedEvents(stored []StoredEvent) []events.Event {
	out := make([]events.Event, len(stored))
	for i, item := range stored {
		out[i] = item.Event
	}
	return out
}
