package eventstore

import (
	"bytes"
	"errors"
	"testing"

	"loopable.party/server/internal/protocol/events"
)

func TestPutIsIdempotentAndDetectsCollisions(t *testing.T) {
	store := New()
	event := events.Event{EventID: bytes.Repeat([]byte{1}, 16), EventType: 0, AccountID: bytes.Repeat([]byte{2}, 32), DeviceID: bytes.Repeat([]byte{3}, 16), Body: map[uint64]any{}}
	if err := store.Put(event); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(event); err != nil {
		t.Fatal(err)
	}
	if store.Len() != 1 {
		t.Fatalf("store length = %d, want 1", store.Len())
	}
	event.Body[0] = "changed"
	if err := store.Put(event); !errors.Is(err, ErrEventIDCollision) {
		t.Fatalf("collision error = %v", err)
	}
	if got, ok := store.Get(event.EventID); !ok || len(got) == 0 {
		t.Fatal("stored event was not retained")
	}
}
