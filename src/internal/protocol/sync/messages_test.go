package sync

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/objects"
)

func TestSyncRequestRoundTrip(t *testing.T) {
	interest := Interest{EventTypes: []uint64{0, 1, 4}, ObjectTypes: []uint64{3}}
	request := Request{Cursor: []byte("cursor"), Interest: &interest}
	encoded, err := request.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Cursor, []byte("cursor")) {
		t.Fatal("cursor did not round-trip")
	}
	if parsed.Interest == nil {
		t.Fatal("interest lost on round-trip")
	}
	if len(parsed.Interest.EventTypes) != 3 || len(parsed.Interest.ObjectTypes) != 1 {
		t.Fatal("interest filters did not round-trip")
	}
}

func TestSyncRequestOmissions(t *testing.T) {
	request := Request{}
	encoded, err := request.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Cursor) != 0 || parsed.Interest != nil {
		t.Fatal("absent fields must decode as absent")
	}
	withInterest := Request{Interest: &Interest{ObjectTypes: []uint64{0}}}
	encoded, err = withInterest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Interest == nil || parsed.Interest.EventTypes != nil || len(parsed.Interest.ObjectTypes) != 1 {
		t.Fatal("partial interest did not round-trip")
	}
}

func TestSyncRequestRejectsUnregisteredInterestType(t *testing.T) {
	request := Request{Interest: &Interest{EventTypes: []uint64{99}}}
	encoded, err := request.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(encoded); err == nil {
		t.Fatal("unregistered event type accepted in interest filter")
	}
}

func TestSyncPageRoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		EventID:   bytes.Repeat([]byte{1}, 16),
		EventType: 0,
		AccountID: bytes.Repeat([]byte{2}, 32),
		CreatedAt: 1,
		Body:      map[uint64]any{1: "sample"},
	}
	if err := event.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := event.Verify(publicKey); err != nil {
		t.Fatal(err)
	}
	object := objects.Object{
		ObjectID:        bytes.Repeat([]byte{3}, 32),
		ObjectType:      objects.ObjectTypePost,
		EncryptionSuite: objects.EncryptionSuiteAESGCM,
		VersionID:       bytes.Repeat([]byte{4}, 32),
		Nonce:           bytes.Repeat([]byte{5}, 12),
		Ciphertext:      bytes.Repeat([]byte{6}, 32),
		Recipients: []objects.RecipientRecord{{
			Kind:            objects.RecipientKindDevice,
			AccountID:       bytes.Repeat([]byte{2}, 32),
			DeviceID:        bytes.Repeat([]byte{7}, 16),
			RecipientKeyID:  bytes.Repeat([]byte{8}, 16),
			EncapsulatedKey: bytes.Repeat([]byte{9}, 32),
			WrappedKey:      bytes.Repeat([]byte{10}, 48),
		}},
	}
	if err := object.Validate(); err != nil {
		t.Fatal(err)
	}

	page := Page{Cursor: []byte("c1"), Events: []events.Event{event}, Objects: []objects.Object{object}, More: true}
	encoded, err := page.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Cursor, []byte("c1")) || !parsed.More {
		t.Fatal("page cursor or more flag did not round-trip")
	}
	if len(parsed.Events) != 1 || !bytes.Equal(parsed.Events[0].EventID, event.EventID) || !bytes.Equal(parsed.Events[0].Signature, event.Signature) {
		t.Fatal("page events did not round-trip")
	}
	if len(parsed.Objects) != 1 || !bytes.Equal(parsed.Objects[0].ObjectID, object.ObjectID) {
		t.Fatal("page objects did not round-trip")
	}

	terminal, err := Page{Cursor: []byte("c2")}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedTerminal, err := ParsePage(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if decodedTerminal.More || len(decodedTerminal.Events) != 0 {
		t.Fatal("terminal page decoded incorrectly")
	}
}

func TestSyncPageRequiresCursor(t *testing.T) {
	page := Page{}
	encoded, err := page.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePage(encoded); err == nil {
		t.Fatal("page without cursor accepted")
	}
}

func TestPendingStoreDependencies(t *testing.T) {
	store := NewPendingStore()
	dependent := events.Event{
		EventID:   bytes.Repeat([]byte{1}, 16),
		EventType: 0,
		AccountID: bytes.Repeat([]byte{2}, 32),
		CreatedAt: 1,
		Body:      map[uint64]any{1: "sample"},
	}
	missing := [][]byte{bytes.Repeat([]byte{0xaa}, 16), bytes.Repeat([]byte{0xbb}, 16)}
	if err := store.RecordPending(dependent, missing); err != nil {
		t.Fatal(err)
	}
	if got := store.State(dependent.EventID); got != EventPending {
		t.Fatalf("state after record = %q", got)
	}
	if len(store.MissingEvents()) != 2 {
		t.Fatal("missing dependencies not reported")
	}
	resolved := store.Resolve(bytes.Repeat([]byte{0xaa}, 16))
	if len(resolved) != 0 {
		t.Fatal("event resolved while still missing a dependency")
	}
	resolved = store.Resolve(bytes.Repeat([]byte{0xbb}, 16))
	if len(resolved) != 1 || !bytes.Equal(resolved[0], dependent.EventID) {
		t.Fatal("event did not resolve once complete")
	}
	if got := store.State(dependent.EventID); got != EventValidated {
		t.Fatalf("state after resolve = %q", got)
	}
	if len(store.MissingEvents()) != 0 {
		t.Fatal("dependency tracking not cleared")
	}
}

func TestPendingStoreCollision(t *testing.T) {
	store := NewPendingStore()
	first := events.Event{
		EventID:   bytes.Repeat([]byte{1}, 16),
		EventType: 0,
		AccountID: bytes.Repeat([]byte{2}, 32),
		CreatedAt: 1,
		Body:      map[uint64]any{1: "first"},
	}
	second := first
	second.Body = map[uint64]any{1: "second"}
	if err := store.RecordPending(first, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordPending(first, nil); err != nil {
		t.Fatalf("re-submission rejected: %v", err)
	}
	if err := store.RecordPending(second, nil); !errors.Is(err, ErrEventCollision) {
		t.Fatalf("colliding event error = %v", err)
	}
}

func TestPerPeerKnownIDsAndSuccess(t *testing.T) {
	store := NewStateStore()
	peer := bytes.Repeat([]byte{1}, 32)
	if err := store.Initialize(peer, "0.1", []string{"events"}); err != nil {
		t.Fatal(err)
	}
	eventID := bytes.Repeat([]byte{3}, 16)
	objectID := bytes.Repeat([]byte{4}, 32)
	if !store.RecordKnownEvent(peer, eventID) {
		t.Fatal("first event sighting must be new")
	}
	if store.RecordKnownEvent(peer, eventID) {
		t.Fatal("duplicate event sighting must not be new")
	}
	if !store.KnownEvent(peer, eventID) {
		t.Fatal("known event not reported")
	}
	if !store.RecordKnownObject(peer, objectID) || !store.KnownObject(peer, objectID) {
		t.Fatal("object tracking failed")
	}
	before := time.Now()
	if err := store.RecordSuccess(peer, before.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	state, err := store.Get(peer)
	if err != nil {
		t.Fatal(err)
	}
	if !state.LastSuccessfulSync.Equal(before.Add(time.Minute)) {
		t.Fatal("last successful sync not recorded")
	}
}
