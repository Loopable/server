// Package conflict implements deterministic presentation ordering and version
// selection for concurrent events, per protospec/spec/64-event-conflict-resolution.md.
package conflict

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/events"
)

var (
	ErrCycle   = errors.New("event cycle")
	ErrEmpty   = errors.New("no events supplied")
	ErrCollide = errors.New("event id collision")
)

// Order returns the given events in deterministic presentation order per 64.2:
// causal predecessors first, then created_at ascending, with ties broken by
// event_id ascending (byte order). Only dependencies among the supplied events
// constrain the order; references to events outside the set are ignored.
// Duplicate event IDs collapse to one position; if two distinct events share an
// ID, ordering is ambiguous and ErrCollide is returned. A dependency cycle
// within the set yields ErrCycle.
func Order(set []events.Event) ([]events.Event, error) {
	if len(set) == 0 {
		return nil, ErrEmpty
	}
	nodes := make(map[string]*node, len(set))
	for _, event := range set {
		id := string(event.EventID)
		if existing, ok := nodes[id]; ok {
			if !sameEvent(existing.event, event) {
				return nil, fmt.Errorf("%x: %w", event.EventID, ErrCollide)
			}
			continue
		}
		nodes[id] = &node{
			event:      event,
			successors: make([]string, 0, 4),
		}
	}
	for id, current := range nodes {
		for _, predecessorID := range current.event.Predecessors {
			predecessor, ok := nodes[string(predecessorID)]
			if !ok {
				continue
			}
			current.indegree++
			predecessor.successors = append(predecessor.successors, id)
		}
	}
	queue := make(pending, 0, len(nodes))
	for _, current := range nodes {
		if current.indegree == 0 {
			queue.Push(current)
		}
	}
	heap.Init(&queue)

	order := make([]events.Event, 0, len(nodes))
	for queue.Len() > 0 {
		current := heap.Pop(&queue).(*node)
		order = append(order, current.event)
		for _, successorID := range current.successors {
			successor := nodes[successorID]
			successor.indegree--
			if successor.indegree == 0 {
				heap.Push(&queue, successor)
			}
		}
	}
	if len(order) != len(nodes) {
		return nil, ErrCycle
	}
	return order, nil
}

// SelectVersion returns the "current" version among concurrent versions per
// 64.4: newest created_at, then highest event_id (byte order). It always
// returns a candidate, or ErrEmpty when the slice is empty.
func SelectVersion(versions []events.Event) (events.Event, error) {
	if len(versions) == 0 {
		return events.Event{}, ErrEmpty
	}
	best := versions[0]
	for _, candidate := range versions[1:] {
		if candidate.CreatedAt > best.CreatedAt ||
			(candidate.CreatedAt == best.CreatedAt && bytes.Compare(candidate.EventID, best.EventID) > 0) {
			best = candidate
		}
	}
	return best, nil
}

type node struct {
	event      events.Event
	indegree   int
	successors []string
}

type pending []*node

func (p pending) Len() int      { return len(p) }
func (p pending) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func (p pending) Less(i, j int) bool {
	if p[i].event.CreatedAt != p[j].event.CreatedAt {
		return p[i].event.CreatedAt < p[j].event.CreatedAt
	}
	return bytes.Compare(p[i].event.EventID, p[j].event.EventID) < 0
}

func (p *pending) Push(x any) { *p = append(*p, x.(*node)) }
func (p *pending) Pop() any {
	old := *p
	last := old[len(old)-1]
	*p = old[:len(old)-1]
	return last
}

func sameEvent(a, b events.Event) bool {
	encodedA, err := encoding.Encode(a.Wire())
	if err != nil {
		return false
	}
	encodedB, err := encoding.Encode(b.Wire())
	if err != nil {
		return false
	}
	return bytes.Equal(encodedA, encodedB)
}
