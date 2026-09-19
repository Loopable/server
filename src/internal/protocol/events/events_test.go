package events

import (
	"bytes"
	"testing"

	"loopable.party/server/internal/protocol/signatures"
)

func TestEventSignAndVerify(t *testing.T) {
	publicKey, privateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	eventID := bytes.Repeat([]byte{1}, 16)
	event := Event{EventID: eventID, EventType: 13, AccountID: bytes.Repeat([]byte{2}, 32), DeviceID: bytes.Repeat([]byte{3}, 16), CreatedAt: 10, Predecessors: [][]byte{bytes.Repeat([]byte{4}, 16)}, Body: map[uint64]any{0: "object"}}
	if err := event.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := event.Verify(publicKey); err != nil {
		t.Fatal(err)
	}
	event.Body[0] = "changed"
	if err := event.Verify(publicKey); err == nil {
		t.Fatal("accepted modified event")
	}
}

func TestEventRejectsInvalidPredecessors(t *testing.T) {
	event := Event{EventID: bytes.Repeat([]byte{1}, 16), AccountID: bytes.Repeat([]byte{2}, 32), DeviceID: bytes.Repeat([]byte{3}, 16), Body: map[uint64]any{}}
	event.Predecessors = [][]byte{bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{1}, 16)}
	if err := event.Validate(); err == nil {
		t.Fatal("accepted unsorted predecessors")
	}
	event.Predecessors = [][]byte{event.EventID}
	if err := event.Validate(); err == nil {
		t.Fatal("accepted self-reference")
	}
}
