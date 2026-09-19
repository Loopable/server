// Package sync implements resumable per-peer synchronization state.
package sync

import (
	"bytes"
	"errors"
	"sync"
)

var (
	ErrUnknownPeer = errors.New("peer has no synchronization state")
	ErrStaleCursor = errors.New("cursor does not match the last successful cursor")
	ErrEmptyCursor = errors.New("cursor must not be empty")
)

type PeerState struct {
	PeerInstanceID  []byte
	Cursor          []byte
	ProtocolVersion string
	Capabilities    []string
}

type StateStore struct {
	mu    sync.RWMutex
	peers map[string]PeerState
}

func NewStateStore() *StateStore { return &StateStore{peers: make(map[string]PeerState)} }

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
	s.peers[string(peerID)] = state
	return nil
}

func clone(state PeerState) PeerState {
	state.PeerInstanceID = append([]byte(nil), state.PeerInstanceID...)
	state.Cursor = append([]byte(nil), state.Cursor...)
	state.Capabilities = append([]string(nil), state.Capabilities...)
	return state
}
