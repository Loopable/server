// Package eventstore provides an immutable event acceptance store.
//
// It is an in-memory reference implementation of the identity and collision
// rules that persistent repositories must preserve.
package eventstore

import (
	"bytes"
	"errors"
	"sync"

	"loopable.party/server/internal/protocol/events"
)

var ErrEventIDCollision = errors.New("event ID collision")

type Store struct {
	mu     sync.RWMutex
	events map[string][]byte
}

func New() *Store { return &Store{events: make(map[string][]byte)} }

// Put accepts an event once. Re-submitting identical bytes is idempotent.
func (s *Store) Put(event events.Event) error {
	encoded, err := event.CanonicalBytes()
	if err != nil {
		return err
	}
	key := string(event.EventID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.events[key]; ok {
		if bytes.Equal(existing, encoded) {
			return nil
		}
		return ErrEventIDCollision
	}
	s.events[key] = append([]byte(nil), encoded...)
	return nil
}

func (s *Store) Get(eventID []byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	encoded, ok := s.events[string(eventID)]
	return append([]byte(nil), encoded...), ok
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}
