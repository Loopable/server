package objects

import (
	"bytes"
	"testing"
)

func TestRandomIDs(t *testing.T) {
	objectID, err := NewObjectID()
	if err != nil {
		t.Fatal(err)
	}
	versionID, err := NewVersionID()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateID(objectID); err != nil {
		t.Fatal(err)
	}
	if err := ValidateID(versionID); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(objectID, versionID) {
		t.Fatal("independent random identifiers unexpectedly matched")
	}
}

func TestEnvelopeIDIsCanonicalAndContentBound(t *testing.T) {
	envelope := map[uint64]any{0: "0.1", 1: bytes.Repeat([]byte{1}, 32), 2: uint64(0)}
	first, err := EnvelopeID(envelope)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnvelopeID(map[uint64]any{2: uint64(0), 1: bytes.Repeat([]byte{1}, 32), 0: "0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("map order changed envelope ID")
	}
	envelope[2] = uint64(1)
	third, err := EnvelopeID(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, third) {
		t.Fatal("envelope ID ignored envelope changes")
	}
}
