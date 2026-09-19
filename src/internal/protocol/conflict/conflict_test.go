package conflict

import (
	"bytes"
	"errors"
	"testing"

	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
)

func TestOrderBasic(t *testing.T) {
	genesis := event(t, []byte{0x01}, 0, 0, nil)
	a := event(t, []byte{0x02}, 2, 1, genesis.EventID)
	b := event(t, []byte{0x03}, 1, 1, genesis.EventID)
	d := event(t, []byte{0x04}, 3, 1, a.EventID, b.EventID)
	ordered, err := Order([]events.Event{d, b, a, genesis})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{genesis.EventID, b.EventID, a.EventID, d.EventID}
	for i, event := range ordered {
		if !bytes.Equal(event.EventID, want[i]) {
			t.Fatalf("position %d: got %x, want %x", i, event.EventID, want[i])
		}
	}
}

func TestOrderSameCreatedAtTiesByEventID(t *testing.T) {
	a := event(t, []byte{0x02}, 1, 1, nil)
	b := event(t, []byte{0x03}, 1, 1, nil)
	ordered, err := Order([]events.Event{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ordered[0].EventID, a.EventID) {
		t.Fatalf("expected %x before %x", a.EventID, b.EventID)
	}
}

func TestOrderIgnoresForeignPredecessors(t *testing.T) {
	foreign := event(t, []byte{0xff}, 0, 0, nil)
	a := event(t, []byte{0x02}, 1, 1, foreign.EventID)
	ordered, err := Order([]events.Event{a})
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 1 {
		t.Fatalf("got %d events, want 1", len(ordered))
	}
}

func TestOrderCycle(t *testing.T) {
	a := event(t, []byte{0x02}, 1, 1, nil)
	b := event(t, []byte{0x03}, 1, 1, nil)
	a.Predecessors = [][]byte{b.EventID}
	b.Predecessors = [][]byte{a.EventID}
	if _, err := Order([]events.Event{a, b}); !errors.Is(err, ErrCycle) {
		t.Fatalf("got %v, want ErrCycle", err)
	}
}

func TestOrderCollision(t *testing.T) {
	a := event(t, []byte{0x02}, 1, 1, nil)
	b := event(t, []byte{0x02}, 2, 1, nil)
	if _, err := Order([]events.Event{a, b}); !errors.Is(err, ErrCollide) {
		t.Fatalf("got %v, want ErrCollide", err)
	}
	dup := event(t, []byte{0x03}, 1, 1, nil)
	ordered, err := Order([]events.Event{dup, dup})
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 1 {
		t.Fatalf("duplicate collapsed, got %d events", len(ordered))
	}
}

func TestOrderEmpty(t *testing.T) {
	if _, err := Order(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("got %v, want ErrEmpty", err)
	}
}

func TestSelectVersionNewestCreatedAt(t *testing.T) {
	older := event(t, []byte{0x02}, 1, 1, nil)
	newer := event(t, []byte{0x03}, 5, 1, nil)
	chosen, err := SelectVersion([]events.Event{newer, older})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chosen.EventID, newer.EventID) {
		t.Fatalf("got %x, want %x", chosen.EventID, newer.EventID)
	}
}

func TestSelectVersionTieByHighestEventID(t *testing.T) {
	low := event(t, []byte{0x02}, 1, 1, nil)
	high := event(t, []byte{0x05}, 1, 1, nil)
	chosen, err := SelectVersion([]events.Event{low, high})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chosen.EventID, high.EventID) {
		t.Fatalf("got %x, want %x", chosen.EventID, high.EventID)
	}
}

func TestSelectVersionEmpty(t *testing.T) {
	if _, err := SelectVersion(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("got %v, want ErrEmpty", err)
	}
}

func event(t *testing.T, id []byte, createdAt uint64, seed uint8, predecessorIDs ...[]byte) events.Event {
	t.Helper()
	event := events.Event{
		EventID:   bytes.Repeat(id, identifiers.ShortLength/len(id)),
		EventType: 4,
		AccountID: bytes.Repeat([]byte{0xaa}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{0xbb}, identifiers.ShortLength),
		CreatedAt: createdAt,
		Body:      map[uint64]any{0: bytes.Repeat([]byte{seed}, identifiers.LongLength)},
	}
	if len(predecessorIDs) > 0 {
		event.Predecessors = predecessorIDs
	}
	return event
}
