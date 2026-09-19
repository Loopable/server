// Package signatures implements Loopable's Ed25519 signature construction.
//
// The rules in this package correspond to protospec/spec/22-signatures.md.
package signatures

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
)

const (
	EventDomain                    = "loopable-event-v1\x00"
	FirstDeviceAuthorizationDomain = "loopable-first-device-authorization-v1\x00"
)

var (
	ErrInvalidPrivateKey = errors.New("invalid Ed25519 private key")
	ErrInvalidPublicKey  = errors.New("invalid Ed25519 public key")
	ErrInvalidSignature  = errors.New("invalid Ed25519 signature")
)

// Generate creates an Ed25519 key pair using the system cryptographic random source.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return publicKey, privateKey, nil
}

// Sign signs the canonical encoding of unsigned with domain as its prefix.
// The caller must omit the structure's signature field before calling Sign.
func Sign(privateKey ed25519.PrivateKey, domain string, unsigned any) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	input, err := signatureInput(domain, unsigned)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privateKey, input), nil
}

// Verify checks a signature over the canonical encoding of unsigned with domain
// as its prefix. The caller must omit the structure's signature field.
func Verify(publicKey ed25519.PublicKey, domain string, unsigned any, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}
	if len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	input, err := signatureInput(domain, unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, input, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func signatureInput(domain string, unsigned any) ([]byte, error) {
	encoded, err := encoding.Encode(unsigned)
	if err != nil {
		return nil, fmt.Errorf("encode unsigned structure: %w", err)
	}
	input := make([]byte, 0, len(domain)+len(encoded))
	input = append(input, domain...)
	input = append(input, encoded...)
	return input, nil
}
