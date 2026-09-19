package sync

import (
	"bytes"
	"errors"
	"testing"
)

func TestCursorResumptionIsMonotonic(t *testing.T) {
	store := NewStateStore()
	peer := bytes.Repeat([]byte{1}, 32)
	if err := store.Initialize(peer, "0.1", []string{"events"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(peer, nil, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(peer, []byte("one"), []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(peer, []byte("one"), []byte("stale")); !errors.Is(err, ErrStaleCursor) {
		t.Fatalf("stale cursor error = %v", err)
	}
	state, err := store.Get(peer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.Cursor, []byte("two")) {
		t.Fatalf("cursor = %q", state.Cursor)
	}
}

func TestStateIsCopied(t *testing.T) {
	store := NewStateStore()
	peer := []byte("peer")
	if err := store.Initialize(peer, "0.1", nil); err != nil {
		t.Fatal(err)
	}
	state, err := store.Get(peer)
	if err != nil {
		t.Fatal(err)
	}
	state.PeerInstanceID[0] = 'x'
	again, err := store.Get(peer)
	if err != nil {
		t.Fatal(err)
	}
	if again.PeerInstanceID[0] != 'p' {
		t.Fatal("state exposed internal storage")
	}
}
