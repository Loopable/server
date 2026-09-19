package sync

import (
	"bytes"
	"errors"
	"sync"

	"loopable.party/server/internal/protocol/events"
)

// Event states per 100-conformance and 63.4.
const (
	EventPending    = "pending"
	EventValidated  = "validated"
	EventAuthorized = "authorized"
	EventApplied    = "applied"
)

// ErrEventCollision is reported when the same event ID arrives with different
// bytes, per 63.5.
var ErrEventCollision = errors.New("event ID collision")

// PendingStore tracks dependent events that are waiting for missing
// predecessors, per 63.3.
type PendingStore struct {
	mu         sync.RWMutex
	index      map[string][]byte
	byID       map[string][]string
	state      map[string]string
	unresolved map[string]int
}

// NewPendingStore creates a dependency registry.
func NewPendingStore() *PendingStore {
	return &PendingStore{
		index:      make(map[string][]byte),
		byID:       make(map[string][]string),
		state:      make(map[string]string),
		unresolved: make(map[string]int),
	}
}

// RecordPending stores a received event as pending, noting its missing
// dependencies. It rejects a re-submission whose bytes differ, per 63.5.
func (p *PendingStore) RecordPending(event events.Event, missing [][]byte) error {
	encoded, err := event.CanonicalBytes()
	if err != nil {
		return err
	}
	id := string(event.EventID)
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.index[id]; ok {
		if !bytes.Equal(existing, encoded) {
			return ErrEventCollision
		}
		return nil
	}
	p.index[id] = encoded
	p.unresolved[id] = len(missing)
	if len(missing) == 0 {
		p.state[id] = EventValidated
	} else {
		p.state[id] = EventPending
		for _, dependency := range missing {
			p.byID[string(dependency)] = append(p.byID[string(dependency)], id)
		}
	}
	return nil
}

// State reports the current event state, or an empty string when unknown.
func (p *PendingStore) State(eventID []byte) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state[string(eventID)]
}

// MissingEvents returns the distinct missing dependency IDs that still block
// pending events, for batching a fetch per 63.3 step 2.
func (p *PendingStore) MissingEvents() [][]byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	missing := make([][]byte, 0, len(p.byID))
	for dependency := range p.byID {
		missing = append(missing, []byte(dependency))
	}
	return missing
}

// Resolve marks a dependency as received; it returns the IDs of dependent
// events that became fully validated, per 63.2 step 2 and 63.3 steps 3-5.
func (p *PendingStore) Resolve(dependencyID []byte) [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	dependents := p.byID[string(dependencyID)]
	delete(p.byID, string(dependencyID))
	nowValid := make([][]byte, 0, len(dependents))
	for _, id := range dependents {
		p.unresolved[id]--
		if p.unresolved[id] == 0 && p.state[id] == EventPending {
			p.state[id] = EventValidated
			nowValid = append(nowValid, []byte(id))
		}
	}
	return nowValid
}
