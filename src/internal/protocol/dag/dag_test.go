package dag

import (
	"bytes"
	"errors"
	"testing"

	"loopable.party/server/internal/protocol/events"
)

func makeEvent(id, account byte, eventType uint64, predecessors ...byte) events.Event {
	ids := make([][]byte, len(predecessors))
	for i, predecessor := range predecessors {
		ids[i] = bytes.Repeat([]byte{predecessor}, 16)
	}
	return events.Event{EventID: bytes.Repeat([]byte{id}, 16), EventType: eventType, AccountID: bytes.Repeat([]byte{account}, 32), DeviceID: bytes.Repeat([]byte{9}, 16), Body: map[uint64]any{}, Predecessors: ids}
}

func TestValidateRootedGraph(t *testing.T) {
	root := makeEvent(1, 7, 0)
	known := map[string]events.Event{string(root.EventID): root}
	child := makeEvent(2, 7, 13, 1)
	if err := Validate(child, known); err != nil {
		t.Fatal(err)
	}
}

func TestValidateMissingAccountAndCycle(t *testing.T) {
	root := makeEvent(1, 7, 0)
	known := map[string]events.Event{string(root.EventID): root}
	if err := Validate(makeEvent(2, 7, 13, 8), known); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing error = %v", err)
	}
	other := makeEvent(3, 8, 13, 1)
	if err := Validate(other, known); !errors.Is(err, ErrAccount) {
		t.Fatalf("account error = %v", err)
	}
	known[string(bytes.Repeat([]byte{2}, 16))] = makeEvent(2, 7, 13, 1)
	known[string(bytes.Repeat([]byte{2}, 16))] = makeEvent(2, 7, 13, 4)
	if err := Validate(makeEvent(4, 7, 13, 2), known); !errors.Is(err, ErrCycle) {
		t.Fatalf("cycle error = %v", err)
	}
}
