package accounts

import (
	"bytes"
	"testing"
)

func TestAuthorizationIndexTransitions(t *testing.T) {
	index := NewAuthorizationIndex()
	first := DeviceState{ID: bytes.Repeat([]byte{1}, 16), SigningKey: bytes.Repeat([]byte{2}, 32), EncryptionKey: bytes.Repeat([]byte{3}, 32)}
	second := DeviceState{ID: bytes.Repeat([]byte{4}, 16), SigningKey: bytes.Repeat([]byte{5}, 32), EncryptionKey: bytes.Repeat([]byte{6}, 32)}
	if err := index.SeedFirstDevice(first); err != nil {
		t.Fatal(err)
	}
	if !index.CanSign(first.ID) {
		t.Fatal("first device cannot sign")
	}
	if err := index.Authorize(second); err != nil {
		t.Fatal(err)
	}
	if err := index.TransferTrust(second.ID); err != nil {
		t.Fatal(err)
	}
	if index.CanSign(first.ID) {
		t.Fatal("superseded device can sign")
	}
	if !index.CanSign(second.ID) {
		t.Fatal("new trusted device cannot sign")
	}
	if err := index.Revoke(second.ID); err == nil {
		t.Fatal("revoked trusted device without transfer")
	}
	if err := index.Revoke(first.ID); err == nil {
		t.Fatal("revoked superseded device")
	}
}
