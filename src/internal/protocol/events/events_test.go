package events

import (
	"bytes"
	"testing"

	"loopable.party/server/internal/protocol/encoding"
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

func TestEventRoundTripHasNoNull(t *testing.T) {
	_, privateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	base := Event{EventID: bytes.Repeat([]byte{1}, 16), EventType: 0, AccountID: bytes.Repeat([]byte{2}, 32), CreatedAt: 1, Body: map[uint64]any{1: "sample"}}
	if err := base.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	encoded, err := base.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := encoding.Decode(encoded, &decoded); err != nil {
		t.Fatalf("genesis wire rejected by strict decoder: %v", err)
	}
	parsed, err := Parse(decoded)
	if err != nil {
		t.Fatalf("genesis wire round-trip rejected: %v", err)
	}
	if len(parsed.DeviceID) != 0 || len(parsed.Predecessors) != 0 || len(parsed.ObjectReferences) != 0 {
		t.Fatal("empty arrays or device id did not survive round-trip")
	}
	if !bytes.Equal(parsed.EventID, base.EventID) || parsed.EventType != 0 {
		t.Fatal("round-trip altered event")
	}
}

func TestEventParsesDecodedValue(t *testing.T) {
	base := Event{EventID: bytes.Repeat([]byte{1}, 16), EventType: 13, AccountID: bytes.Repeat([]byte{2}, 32), DeviceID: bytes.Repeat([]byte{3}, 16), CreatedAt: 10, Predecessors: [][]byte{bytes.Repeat([]byte{4}, 16)}, Body: map[uint64]any{0: "object"}}
	wire := base.Wire()
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Predecessors[0], base.Predecessors[0]) || len(parsed.ObjectReferences) != 0 {
		t.Fatal("parsed event differs")
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

func TestGenesisDeviceIDRule(t *testing.T) {
	base := Event{EventID: bytes.Repeat([]byte{1}, 16), EventType: 0, AccountID: bytes.Repeat([]byte{2}, 32), Body: map[uint64]any{}}
	genesis := base
	if err := genesis.Validate(); err != nil {
		t.Fatalf("genesis with empty device id rejected: %v", err)
	}
	genesis.DeviceID = bytes.Repeat([]byte{3}, 16)
	if err := genesis.Validate(); err == nil {
		t.Fatal("accepted genesis event with non-empty device id")
	}
	content := base
	content.EventType = 13
	content.DeviceID = bytes.Repeat([]byte{3}, 16)
	if err := content.Validate(); err != nil {
		t.Fatalf("content event with device id rejected: %v", err)
	}
	content.DeviceID = nil
	if err := content.Validate(); err == nil {
		t.Fatal("accepted content event without device id")
	}
}
