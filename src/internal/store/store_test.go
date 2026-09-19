package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/sync"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("LOOPABLE_TEST_PG")
	if dsn == "" {
		t.Skip("set LOOPABLE_TEST_PG to a PostgreSQL DSN to run store integration tests")
	}
	ctx := t.Context()
	store, err := Open(ctx, Config{DSN: dsn})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(store.Close)
	testReset(ctx, t, store)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return store
}

func testReset(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()
	for _, table := range []string{"peer_cursors", "peers", "events", "schema_migrations"} {
		if _, err := store.pool.Exec(ctx, `DROP TABLE IF EXISTS `+table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
}

func signedEvent(t *testing.T, seed byte) events.Event {
	t.Helper()
	return signedEventType(t, seed, 0)
}

func signedEventType(t *testing.T, seed byte, eventType uint64) events.Event {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		EventID:   bytes.Repeat([]byte{seed}, identifiers.ShortLength),
		EventType: eventType,
		AccountID: bytes.Repeat([]byte{2}, identifiers.LongLength),
		CreatedAt: 1,
		Body:      map[uint64]any{1: "sample"},
	}
	if err := event.Sign(private); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestMigrateProducesLatestSchema(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	version, err := store.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version != latestVersion() {
		t.Fatalf("version %d, want %d", version, latestVersion())
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := store.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestPutEventIdempotentAndCollision(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	event := signedEvent(t, 0xa0)

	first, err := store.PutEvent(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.PutEvent(ctx, event)
	if err != nil {
		t.Fatalf("idempotent re-put: %v", err)
	}
	if again.Seq != first.Seq {
		t.Fatalf("re-put seq %d, want %d", again.Seq, first.Seq)
	}

	wire, err := event.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	clashing := append([]byte(nil), wire...)
	slices.Reverse(clashing)
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO events (event_id, event_type, account_id, wire)
		VALUES ($1, $2, $3, $4)
	`, event.EventID, uint32(event.EventType), event.AccountID, clashing); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutEvent(ctx, event); !errors.Is(err, ErrEventIDCollision) {
		t.Fatalf("colliding event: got %v, want ErrEventIDCollision", err)
	}
}

func TestGetEventRoundTrip(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	event := signedEvent(t, 0xa1)
	if _, err := store.PutEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetEvent(ctx, event.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.EventID, event.EventID) || got.CreatedAt != event.CreatedAt {
		t.Fatal("round trip mismatch")
	}
	has, err := store.HasEvent(ctx, event.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("HasEvent false for stored event")
	}
	if _, err := store.GetEvent(ctx, bytes.Repeat([]byte{0xee}, identifiers.ShortLength)); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("missing event: got %v, want ErrEventNotFound", err)
	}
}

func TestEventsAfterPaginationAndFilter(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	a := signedEvent(t, 0xb1)
	b := signedEvent(t, 0xb2)
	c := signedEventType(t, 0xb3, 13)
	if _, err := store.PutEvent(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutEvent(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutEvent(ctx, c); err != nil {
		t.Fatal(err)
	}

	page, more, err := store.EventsAfter(ctx, 0, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !more {
		t.Fatal("expected more pages")
	}
	if len(page) != 2 || !bytes.Equal(page[0].Event.EventID, a.EventID) {
		t.Fatalf("first page wrong: %d events, first %x", len(page), page[0].Event.EventID)
	}
	resume, more, err := store.EventsAfter(ctx, page[1].Seq, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if more || len(resume) != 1 || !bytes.Equal(resume[0].Event.EventID, c.EventID) {
		t.Fatalf("resume wrong: %d events, more %v", len(resume), more)
	}

	filtered, _, err := store.EventsAfter(ctx, 0, []uint64{13}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || !bytes.Equal(filtered[0].Event.EventID, c.EventID) {
		t.Fatalf("type filter wrong: %d events", len(filtered))
	}
	excluded, _, err := store.EventsAfter(ctx, 0, []uint64{4}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(excluded) != 0 {
		t.Fatalf("excluded filter got %d events", len(excluded))
	}

	full, _, err := store.EventsAfter(ctx, 0, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 3 {
		t.Fatalf("got %d events, want 3", len(full))
	}
}

func TestPeerStateRoundTrip(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	peerID := bytes.Repeat([]byte{9}, identifiers.LongLength)
	state := sync.PeerState{
		PeerInstanceID:     peerID,
		ProtocolVersion:    "0.1",
		Capabilities:       []string{"sync"},
		Cursor:             EncodeCursor(42),
		LastSuccessfulSync: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.UpsertPeer(ctx, state); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetPeer(ctx, peerID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProtocolVersion != "0.1" || len(got.Capabilities) != 1 || got.Capabilities[0] != "sync" {
		t.Fatalf("got %#v", got)
	}
	if !bytes.Equal(got.Cursor, state.Cursor) {
		t.Fatal("cursor mismatch")
	}
	if !got.LastSuccessfulSync.Equal(state.LastSuccessfulSync) {
		t.Fatalf("last sync %v, want %v", got.LastSuccessfulSync, state.LastSuccessfulSync)
	}
	if _, err := store.GetPeer(ctx, bytes.Repeat([]byte{8}, identifiers.LongLength)); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("unknown peer: got %v, want ErrUnknownPeer", err)
	}
}

func TestCursorsPerInterestFilter(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	peerID := bytes.Repeat([]byte{9}, identifiers.LongLength)
	filterA := sync.Interest{EventTypes: []uint64{0}}
	encodedA, err := encoding.Encode(filterA.Wire())
	if err != nil {
		t.Fatal(err)
	}
	filterB := sync.Interest{EventTypes: []uint64{13}}
	encodedB, err := encoding.Encode(filterB.Wire())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.CursorFor(ctx, peerID, encodedA); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("before save: got %v, want ErrUnknownPeer", err)
	}
	if err := store.SaveCursor(ctx, peerID, encodedA, 7); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCursor(ctx, peerID, encodedB, 9); err != nil {
		t.Fatal(err)
	}
	seq, err := store.CursorFor(ctx, peerID, encodedA)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 7 {
		t.Fatalf("seq %d, want 7", seq)
	}
	anchors, err := store.CursorsFor(ctx, peerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2", len(anchors))
	}

	if err := store.ForgetPeer(ctx, peerID); err != nil {
		t.Fatal(err)
	}
	remaining, err := store.CursorsFor(ctx, peerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("%d anchors survive peer deletion", len(remaining))
	}
	if _, err := store.GetPeer(ctx, peerID); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("after forget: got %v, want ErrUnknownPeer", err)
	}
}

func TestCursorEncoding(t *testing.T) {
	seq, err := DecodeCursor(EncodeCursor(0x0102030405060708))
	if err != nil {
		t.Fatal(err)
	}
	if seq != 0x0102030405060708 {
		t.Fatalf("got %d", seq)
	}
	if _, err := DecodeCursor(nil); !errors.Is(err, ErrEmptyCursor) {
		t.Fatalf("empty: got %v, want ErrEmptyCursor", err)
	}
	if _, err := DecodeCursor([]byte{1, 2}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("short: got %v, want ErrInvalidCursor", err)
	}
}
