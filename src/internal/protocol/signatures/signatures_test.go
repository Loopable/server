package signatures

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	publicKey, privateKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := map[uint64]any{1: uint64(7), 2: []byte("payload")}
	signature, err := Sign(privateKey, EventDomain, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(signature), ed25519.SignatureSize)
	}
	if err := Verify(publicKey, EventDomain, unsigned, signature); err != nil {
		t.Fatal(err)
	}

	unsigned[1] = uint64(8)
	if err := Verify(publicKey, EventDomain, unsigned, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify mutated structure error = %v, want ErrInvalidSignature", err)
	}
}

func TestSignaturesAreDomainSeparated(t *testing.T) {
	publicKey, privateKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := map[uint64]any{1: uint64(1)}
	signature, err := Sign(privateKey, EventDomain, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicKey, FirstDeviceAuthorizationDomain, unsigned, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("cross-domain verification error = %v, want ErrInvalidSignature", err)
	}
}

func TestRejectsInvalidInputs(t *testing.T) {
	publicKey, privateKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := map[uint64]any{1: uint64(1)}
	if _, err := Sign(privateKey[:ed25519.PrivateKeySize-1], EventDomain, unsigned); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("short private key error = %v", err)
	}
	if err := Verify(publicKey[:ed25519.PublicKeySize-1], EventDomain, unsigned, make([]byte, ed25519.SignatureSize)); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("short public key error = %v", err)
	}
	if err := Verify(publicKey, EventDomain, unsigned, bytes.Repeat([]byte{0}, ed25519.SignatureSize-1)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("short signature error = %v", err)
	}
}
