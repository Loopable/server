package x25519

import (
	"bytes"
	"errors"
	"testing"
)

func TestSharedSecret(t *testing.T) {
	alice, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	aliceSecret, err := alice.SharedSecret(bob.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	bobSecret, err := bob.SharedSecret(alice.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatal("shared secrets differ")
	}
	if len(aliceSecret) != 32 {
		t.Fatalf("shared secret length = %d, want 32", len(aliceSecret))
	}
}

func TestRejectsInvalidPublicKey(t *testing.T) {
	keyPair, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyPair.SharedSecret([]byte{1}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("error = %v, want ErrInvalidPublicKey", err)
	}
}

func TestPublicKeyIsCopied(t *testing.T) {
	keyPair, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := keyPair.PublicKey()
	publicKey[0] ^= 0xff
	if bytes.Equal(publicKey, keyPair.PublicKey()) {
		t.Fatal("PublicKey returned mutable internal storage")
	}
}
