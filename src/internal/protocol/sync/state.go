// Package sync implements resumable per-peer synchronization state.
package sync

import (
	"bytes"
	"errors"
	"sync"
	"time"
)

var (
	ErrUnknownPeer = errors.New("peer has no synchronization state")
	ErrStaleCursor = errors.New("cursor does not match the last successful cursor")
	ErrEmptyCursor = errors.New("cursor must not be empty")
)

// PeerState is the persistent synchronization state for one federation
// relationship, per 62.8.
type PeerState struct {
	PeerInstanceID     []byte
	Cursor             []byte
	ProtocolVersion    string
	Capabilities       []string
	LastSuccessfulSync time.Time
}

// StateStore tracks per-peer cursors and known IDs. The cursor is opaque; the
// resume token enforces ordering and resumption per 62.4.
type StateStore struct {
	mu           sync.RWMutex
	peers        map[string]PeerState
	knownEvents  map[string]map[string]struct{}
	knownObjects map[string]map[string]struct{}
}

func NewStateStore() *StateStore {
	return &StateStore{
		peers:        make(map[string]PeerState),
		knownEvents:  make(map[string]map[string]struct{}),
		knownObjects: make(map[string]map[string]struct{}),
	}
}

func (s *StateStore) Initialize(peerID []byte, protocolVersion string, capabilities []string) error {
	if len(peerID) == 0 {
		return errors.New("peer ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.peers[string(peerID)]; exists {
		return nil
	}
	s.peers[string(peerID)] = PeerState{PeerInstanceID: append([]byte(nil), peerID...), ProtocolVersion: protocolVersion, Capabilities: append([]string(nil), capabilities...)}
	s.knownEvents[string(peerID)] = make(map[string]struct{})
	s.knownObjects[string(peerID)] = make(map[string]struct{})
	return nil
}

func (s *StateStore) Get(peerID []byte) (PeerState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.peers[string(peerID)]
	if !ok {
		return PeerState{}, ErrUnknownPeer
	}
	return clone(state), nil
}

// KnownEvent reports whether the event was already seen from the peer.
func (s *StateStore) KnownEvent(peerID, eventID []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if known, ok := s.knownEvents[string(peerID)]; ok {
		_, seen := known[string(eventID)]
		return seen
	}
	return false
}

// RecordKnownEvent marks an event as received from the peer. It returns false
// when the event was already known, for duplicate detection per 62.6.
func (s *StateStore) RecordKnownEvent(peerID, eventID []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	known, ok := s.knownEvents[string(peerID)]
	if !ok {
		return false
	}
	if _, seen := known[string(eventID)]; seen {
		return false
	}
	known[string(eventID)] = struct{}{}
	return true
}

// KnownObject reports whether the object was already seen from the peer.
func (s *StateStore) KnownObject(peerID, objectID []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if known, ok := s.knownObjects[string(peerID)]; ok {
		_, seen := known[string(objectID)]
		return seen
	}
	return false
}

// RecordKnownObject marks an object as received from the peer.
func (s *StateStore) RecordKnownObject(peerID, objectID []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	known, ok := s.knownObjects[string(peerID)]
	if !ok {
		return false
	}
	if _, seen := known[string(objectID)]; seen {
		return false
	}
	known[string(objectID)] = struct{}{}
	return true
}

// Advance accepts a page only if it resumes from the last stored cursor.
// The server-issued cursor remains opaque; ordering is enforced by the resume token.
func (s *StateStore) Advance(peerID, previousCursor, nextCursor []byte) error {
	if len(nextCursor) == 0 {
		return ErrEmptyCursor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.peers[string(peerID)]
	if !ok {
		return ErrUnknownPeer
	}
	if !bytes.Equal(state.Cursor, previousCursor) {
		return ErrStaleCursor
	}
	state.Cursor = append([]byte(nil), nextCursor...)
	if s.knownEvents[string(peerID)] == nil {
		s.knownEvents[string(peerID)] = make(map[string]struct{})
	}
	if s.knownObjects[string(peerID)] == nil {
		s.knownObjects[string(peerID)] = make(map[string]struct{})
	}
	s.peers[string(peerID)] = state
	return nil
}

// RecordSuccess sets the timestamp of the last fully applied sync for the
// peer, per 62.8.
func (s *StateStore) RecordSuccess(peerID []byte, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.peers[string(peerID)]
	if !ok {
		return ErrUnknownPeer
	}
	state.LastSuccessfulSync = at
	s.peers[string(peerID)] = state
	return nil
}

func clone(state PeerState) PeerState {
	state.PeerInstanceID = append([]byte(nil), state.PeerInstanceID...)
	state.Cursor = append([]byte(nil), state.Cursor...)
	state.Capabilities = append([]string(nil), state.Capabilities...)
	return state
}
