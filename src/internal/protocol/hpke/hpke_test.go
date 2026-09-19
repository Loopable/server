package hpke

import (
	"bytes"
	"testing"
)

func TestRecipientKeyIDAndInfo(t *testing.T) {
	recipient := DeviceRecipient{AccountID: bytes.Repeat([]byte{1}, 32), DeviceID: bytes.Repeat([]byte{2}, 16), PublicKey: bytes.Repeat([]byte{3}, 32)}
	keyID, err := RecipientKeyID(recipient)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyID) != 16 {
		t.Fatalf("key ID length = %d, want 16", len(keyID))
	}
	repeated, err := RecipientKeyID(recipient)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyID, repeated) {
		t.Fatal("recipient key ID is not stable")
	}
	info, err := Info(bytes.Repeat([]byte{4}, 32), keyID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(info, []byte(ObjectKeyInfoDomain)) {
		t.Fatal("info is missing its domain")
	}
}

func TestRecipientKeyIDBindsDescriptor(t *testing.T) {
	recipient := DeviceRecipient{AccountID: bytes.Repeat([]byte{1}, 32), DeviceID: bytes.Repeat([]byte{2}, 16), PublicKey: bytes.Repeat([]byte{3}, 32)}
	first, err := RecipientKeyID(recipient)
	if err != nil {
		t.Fatal(err)
	}
	recipient.DeviceID[0]++
	second, err := RecipientKeyID(recipient)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("recipient key ID ignored descriptor changes")
	}
}
