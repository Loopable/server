package hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestWrapAndUnwrap(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient := DeviceRecipient{AccountID: bytes.Repeat([]byte{1}, 32), DeviceID: bytes.Repeat([]byte{2}, 16), PublicKey: privateKey.PublicKey().Bytes()}
	keyID, err := RecipientKeyID(recipient)
	if err != nil {
		t.Fatal(err)
	}
	objectID := bytes.Repeat([]byte{4}, 32)
	cek := bytes.Repeat([]byte{5}, 32)
	enc, wrapped, err := Wrap(recipient.PublicKey, objectID, keyID, cek)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Unwrap(privateKey.Bytes(), objectID, keyID, enc, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, cek) {
		t.Fatal("unwrapped key differs")
	}
	objectID[0]++
	if opened, err := Unwrap(privateKey.Bytes(), objectID, keyID, enc, wrapped); err == nil || opened != nil {
		t.Fatalf("modified info result = %x, error = %v", opened, err)
	}
}

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
