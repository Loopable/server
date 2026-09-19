// Package dag validates Loopable event dependency graphs.
//
// The rules correspond to protospec/spec/63-event-dependencies.md.
package dag

import (
	"bytes"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/events"
)

var (
	ErrCycle    = errors.New("event dependency cycle")
	ErrUnrooted = errors.New("event dependency graph is unrooted")
	ErrMissing  = errors.New("event dependency is missing")
	ErrAccount  = errors.New("event dependency belongs to another account")
)

// Validate checks whether event can be accepted against already known events.
// The known map is keyed by the raw 16-byte event ID converted to string.
func Validate(event events.Event, known map[string]events.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if event.EventType == 0 && len(event.Predecessors) != 0 {
		return fmt.Errorf("genesis event has predecessors: %w", ErrUnrooted)
	}
	if event.EventType != 0 && len(event.Predecessors) == 0 {
		return ErrUnrooted
	}
	for _, predecessorID := range event.Predecessors {
		predecessor, ok := known[string(predecessorID)]
		if !ok {
			return fmt.Errorf("%x: %w", predecessorID, ErrMissing)
		}
		if !bytes.Equal(predecessor.AccountID, event.AccountID) {
			return ErrAccount
		}
		if reaches(predecessor, event.EventID, known, map[string]bool{}) {
			return ErrCycle
		}
		if !rooted(predecessor, known, map[string]bool{}) {
			return ErrUnrooted
		}
	}
	return nil
}

func reaches(event events.Event, target []byte, known map[string]events.Event, visited map[string]bool) bool {
	id := string(event.EventID)
	if visited[id] {
		return false
	}
	visited[id] = true
	for _, predecessorID := range event.Predecessors {
		if bytes.Equal(predecessorID, target) {
			return true
		}
		if predecessor, ok := known[string(predecessorID)]; ok && reaches(predecessor, target, known, visited) {
			return true
		}
	}
	return false
}

func rooted(event events.Event, known map[string]events.Event, visited map[string]bool) bool {
	id := string(event.EventID)
	if visited[id] {
		return false
	}
	visited[id] = true
	if event.EventType == 0 {
		return len(event.Predecessors) == 0
	}
	for _, predecessorID := range event.Predecessors {
		predecessor, ok := known[string(predecessorID)]
		if ok && rooted(predecessor, known, visited) {
			return true
		}
	}
	return false
}
