package accounts

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"loopable.party/server/internal/protocol/events"
)

// ReservationPeriod is how long a released username stays reserved for the
// account that gave it up, per 40.3: exactly 90 days from the effective time
// of the event that released it.
const ReservationPeriod = 90 * 24 * time.Hour

var (
	// ErrUsernameUnavailable reports that another account holds the username
	// or has an unexpired reservation on it, per 40.2.
	ErrUsernameUnavailable = errors.New("username is unavailable on this instance")
	// ErrUsernameMismatch reports that a username change does not release the
	// account's current username, per 34.7.
	ErrUsernameMismatch = errors.New("username change does not release the current username")
)

// UsernameClaim is one username of an instance and the account that owns it. A
// held username is registered, so nobody else may take it. A reserved username
// was released and stays blocked for its former account until ReservedUntil,
// per 40.3.
type UsernameClaim struct {
	Username      string
	AccountID     []byte
	Held          bool
	ReservedUntil time.Time
}

// UsernameEventTypes returns the event types that decide who owns a username:
// the genesis that registers one (34.3), the change that moves one (34.7), and
// the deletion that releases one (40.4).
func UsernameEventTypes() []uint64 {
	return []uint64{0, 4, 5}
}

// RegistersUsername reports whether an event type claims a username on this
// instance.
func RegistersUsername(eventType uint64) bool {
	return eventType == 0 || eventType == 4
}

// UsernameState is one account's username state: the name it currently answers
// to and the names it has released, each reserved until its expiry.
type UsernameState struct {
	Current  string
	Reserved map[string]time.Time
}

// DeriveAccountUsernames replays one account's lifecycle events into its
// username state. Events must be in publish order.
func DeriveAccountUsernames(stored []events.Event) (UsernameState, error) {
	account := newAccountUsernames(nil)
	for _, event := range stored {
		if err := account.apply(event); err != nil {
			return UsernameState{}, fmt.Errorf("account %x: %w", event.AccountID, err)
		}
	}
	return account.state(), nil
}

// DeriveUsernameClaims replays the lifecycle events of every account homed on
// localInstance into that instance's username state, per 40.2 and 40.3. Events
// must be in publish order.
//
// Availability is instance-local, and the same username on another instance
// belongs to a different account (11.4), so accounts homed elsewhere are left
// out even though their events are stored here for federation.
func DeriveUsernameClaims(stored []events.Event, localInstance []byte) ([]UsernameClaim, error) {
	order := make([]string, 0, 8)
	accounts := make(map[string]*accountUsernames)
	for _, event := range stored {
		key := string(event.AccountID)
		account, ok := accounts[key]
		if !ok {
			account = newAccountUsernames(event.AccountID)
			accounts[key] = account
			order = append(order, key)
		}
		if err := account.apply(event); err != nil {
			return nil, fmt.Errorf("account %x: %w", event.AccountID, err)
		}
	}

	claims := make([]UsernameClaim, 0, len(order))
	for _, key := range order {
		account := accounts[key]
		if !bytes.Equal(account.home, localInstance) {
			continue
		}
		state := account.state()
		if state.Current != "" {
			claims = append(claims, UsernameClaim{Username: state.Current, AccountID: account.accountID, Held: true})
		}
		for username, until := range state.Reserved {
			if username == state.Current {
				continue
			}
			claims = append(claims, UsernameClaim{Username: username, AccountID: account.accountID, ReservedUntil: until})
		}
	}
	slices.SortFunc(claims, func(left, right UsernameClaim) int {
		if order := cmp.Compare(left.Username, right.Username); order != 0 {
			return order
		}
		return bytes.Compare(left.AccountID, right.AccountID)
	})
	return claims, nil
}

// UsernameAvailable reports whether an account may register a username on this
// instance now, per 40.2 and 40.3. A name another account holds is never
// available, a name another account released is available only once its
// reservation expires, and an account may reclaim a name it holds or reserved.
func UsernameAvailable(claims []UsernameClaim, username string, accountID []byte, now time.Time) bool {
	username = NormalizeUsername(username)
	for _, claim := range claims {
		if claim.Username != username || bytes.Equal(claim.AccountID, accountID) {
			continue
		}
		if claim.Held || now.Before(claim.ReservedUntil) {
			return false
		}
	}
	return true
}

// accountUsernames accumulates one account's username state as its lifecycle
// events arrive in publish order.
type accountUsernames struct {
	accountID []byte
	home      []byte
	current   string
	reserved  map[string]time.Time
}

func newAccountUsernames(accountID []byte) *accountUsernames {
	return &accountUsernames{accountID: bytes.Clone(accountID), reserved: make(map[string]time.Time)}
}

func (a *accountUsernames) apply(event events.Event) error {
	switch event.EventType {
	case 0:
		home, err := bodyBytes(event.Body, 2)
		if err != nil {
			return fmt.Errorf("genesis: %w", err)
		}
		username, err := bodyText(event.Body, 1)
		if err != nil {
			return fmt.Errorf("genesis: %w", err)
		}
		a.home = home
		a.current = NormalizeUsername(username)
	case 4:
		released, err := bodyText(event.Body, 0)
		if err != nil {
			return fmt.Errorf("username change: %w", err)
		}
		claimed, err := bodyText(event.Body, 1)
		if err != nil {
			return fmt.Errorf("username change: %w", err)
		}
		// 40.3 reserves the released name for 90 days. A name this account
		// does not currently hold is reserved too, so inconsistent history can
		// never release a name some other account is still answering to.
		a.reserved[NormalizeUsername(released)] = reservationExpiry(event.CreatedAt)
		a.current = NormalizeUsername(claimed)
	case 5:
		// 40.4 releases a deleted account's username to the same reservation.
		if a.current != "" {
			a.reserved[a.current] = reservationExpiry(event.CreatedAt)
			a.current = ""
		}
	}
	return nil
}

func (a *accountUsernames) state() UsernameState {
	return UsernameState{Current: a.current, Reserved: maps.Clone(a.reserved)}
}

// reservationExpiry is the end of a 90-day reservation, measured from the
// effective time of the event that released the name, per 40.3.
func reservationExpiry(createdAt uint64) time.Time {
	return time.Unix(int64(createdAt), 0).UTC().Add(ReservationPeriod)
}

func bodyText(body map[uint64]any, key uint64) (string, error) {
	value, ok := body[key]
	if !ok {
		return "", fmt.Errorf("body field %d is missing", key)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("body field %d is not text", key)
	}
	return text, nil
}

func bodyBytes(body map[uint64]any, key uint64) ([]byte, error) {
	value, ok := body[key]
	if !ok {
		return nil, fmt.Errorf("body field %d is missing", key)
	}
	buffer, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("body field %d is not bytes", key)
	}
	return buffer, nil
}
