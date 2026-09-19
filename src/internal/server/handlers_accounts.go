package server

import (
	"bytes"
	"errors"
	"net/http"

	"loopable.party/server/internal/protocol/identifiers"
	storepkg "loopable.party/server/internal/store"
)

// handleAccountLookup serves the account lookup of 60.8/13.6: full data for
// public profiles and for members requesting the lookup, and "as if not
// found" for everyone else.
func (s *Server) handleAccountLookup(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "lookup", func() {
		requestID := requestContextID(r)
		accountID, err := s.parsePathID(identifiers.AccountID, r.PathValue("account_id"))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		response, err := s.accountLookup(r, accountID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		if response == nil {
			writeError(w, ErrEventNotFound, requestID)
			return
		}
		_ = s.writeCBOR(w, http.StatusOK, response)
	})
}

// accountLookup assembles the lookup map, returning nil when the requester is
// not permitted to see the account (which maps to E_NOT_FOUND per 91-privacy).
func (s *Server) accountLookup(r *http.Request, accountID []byte) (map[uint64]any, error) {
	stored, err := s.cfg.Events.EventsForAccount(r.Context(), accountID)
	if err != nil {
		return nil, err
	}
	genesis, err := findGenesis(stored)
	if err != nil {
		return nil, err
	}
	identityKey, err := eventBodyBytes(genesis.Body, 0)
	if err != nil {
		return nil, err
	}

	index, deleted, err := buildAccountIndex(stored)
	if err != nil {
		return nil, err
	}
	profileIsPublic := hasProfileVisibility(stored)

	if !profileIsPublic {
		auth := requestAuth(r)
		if auth == nil || len(auth.Account) == 0 {
			return nil, ErrEventNotFound
		}
	}

	response := map[uint64]any{
		0: accountID,
		1: identityKey,
		2: accountHandle(stored),
		3: s.cfg.Document.InstanceID,
		4: deviceSummaries(index),
		5: boolUint(deleted),
		6: profileIsPublic,
	}
	if roles := s.accountRoles(accountID); len(roles) != 0 {
		response[9] = roles
	}
	return response, nil
}

// accountRoles returns the local staff roles of an account (13.10).
func (s *Server) accountRoles(accountID []byte) []any {
	roles := make([]any, 0, 2)
	if bytes.Equal(accountID, s.cfg.Document.Administrator) {
		roles = append(roles, "administrator")
	}
	for _, moderator := range s.cfg.Moderators {
		if bytes.Equal(accountID, moderator) {
			roles = append(roles, "moderator")
		}
	}
	return roles
}

// findGenesis returns the ACCOUNT_CREATED event of an account.
func findGenesis(stored []StoredEvent) (eventWithBody, error) {
	for _, item := range stored {
		if item.Event.EventType == 0 {
			return eventWithBody{Body: item.Event.Body}, nil
		}
	}
	return eventWithBody{}, ErrEventNotFound
}

type eventWithBody struct{ Body map[uint64]any }

// accountHandle derives the canonical handle of an account from its latest
// USERNAME_CHANGED event and its genesis username.
func accountHandle(stored []StoredEvent) string {
	var handle string
	for _, item := range stored {
		switch item.Event.EventType {
		case 0:
			if value, ok := item.Event.Body[1]; ok {
				if text, ok := value.(string); ok {
					handle = text
				}
			}
		case 4:
			if value, ok := item.Event.Body[0]; ok {
				if text, ok := value.(string); ok {
					handle = text
				}
			}
		}
	}
	return handle
}

// hasProfileVisibility reports whether an account has elected a public
// profile (PROFILE_VISIBILITY_SET, 51.5).
func hasProfileVisibility(stored []StoredEvent) bool {
	for _, item := range stored {
		if item.Event.EventType == 25 {
			return true
		}
	}
	return false
}

func boolUint(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

// handleMemberLookup serves the membership state of an account in this
// instance. The requester must be a member (account-authenticated).
func (s *Server) handleMemberLookup(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "membership", func() {
		requestID := requestContextID(r)
		auth := requestAuth(r)
		if auth == nil || len(auth.Account) == 0 {
			writeError(w, asInvalidRequest(errors.New("member authentication required")), requestID)
			return
		}
		accountID, err := s.parsePathID(identifiers.AccountID, r.PathValue("account_id"))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		stored, err := s.cfg.Events.EventsForAccount(r.Context(), accountID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		if len(stored) == 0 {
			writeError(w, ErrEventNotFound, requestID)
			return
		}
		_, _, err = buildAccountIndex(stored)
		if err != nil {
			writeError(w, mapStoreNotFound(err, requestID), requestID)
			return
		}
		_ = s.writeCBOR(w, http.StatusOK, map[uint64]any{0: accountID, 1: uint64(1)})
	})
}

func mapStoreNotFound(err error, requestID []byte) error {
	if errors.Is(err, storepkg.ErrEventNotFound) {
		return ErrEventNotFound
	}
	return err
}
