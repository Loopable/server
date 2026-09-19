// Package x25519 implements Loopable's X25519 key-agreement boundary.
//
// X25519 keys are separate from Ed25519 signing keys, as required by
// protospec/spec/20-cryptographic-primitives.md.
package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
)

var ErrInvalidPublicKey = errors.New("invalid X25519 public key")

const keySize = 32

// KeyPair contains an X25519 private key and its public key.
type KeyPair struct {
	privateKey *ecdh.PrivateKey
	publicKey  []byte
}

// Generate creates an independent X25519 key pair from the system random source.
func Generate() (KeyPair, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate X25519 key: %w", err)
	}
	return KeyPair{privateKey: privateKey, publicKey: append([]byte(nil), privateKey.PublicKey().Bytes()...)}, nil
}

// PublicKey returns the 32-byte X25519 public key.
func (k KeyPair) PublicKey() []byte {
	return append([]byte(nil), k.publicKey...)
}

// SharedSecret derives the X25519 shared secret with peerPublicKey.
func (k KeyPair) SharedSecret(peerPublicKey []byte) ([]byte, error) {
	if k.privateKey == nil || len(k.publicKey) != keySize {
		return nil, errors.New("invalid X25519 private key")
	}
	if len(peerPublicKey) != keySize {
		return nil, ErrInvalidPublicKey
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse X25519 public key: %w", err)
	}
	secret, err := k.privateKey.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("derive X25519 shared secret: %w", err)
	}
	return secret, nil
}
