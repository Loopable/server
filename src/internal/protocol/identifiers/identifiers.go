// Package identifiers implements Loopable identifier encoding and derivation.
//
// The rules in this package correspond to protospec/spec/10-identifiers.md.
package identifiers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

const (
	ShortLength = 16
	LongLength  = 32
)

var (
	shortEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	longEncoding  = shortEncoding
)

// Type identifies the protocol identifier length and text form.
type Type uint8

const (
	EventID Type = iota
	ObjectID
	AccountID
	InstanceID
	DeviceID
	RequestID
	KeyID
	RecipientKeyID
	VersionID
	GroupID
)

func (t Type) length() int {
	switch t {
	case EventID, DeviceID, RequestID, KeyID, RecipientKeyID, GroupID:
		return ShortLength
	case ObjectID, AccountID, InstanceID, VersionID:
		return LongLength
	default:
		return 0
	}
}

func (t Type) valid() bool {
	return t.length() != 0 || t == EventID
}

// Parse decodes a canonical text-form identifier. Input is case-insensitive;
// output is always the exact wire length required by kind.
func Parse(kind Type, text string) ([]byte, error) {
	length := kind.length()
	if !kind.valid() {
		return nil, errors.New("unknown identifier type")
	}

	text = strings.ToUpper(text)
	encoding := shortEncoding
	if length == LongLength {
		encoding = longEncoding
	}
	if len(text) != encoding.EncodedLen(length) {
		return nil, fmt.Errorf("identifier has length %d, want %d", len(text), encoding.EncodedLen(length))
	}

	decoded, err := encoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("decode identifier: %w", err)
	}
	if len(decoded) != length {
		return nil, fmt.Errorf("identifier decodes to %d bytes, want %d", len(decoded), length)
	}
	return decoded, nil
}

// String returns the canonical lowercase, unpadded base32 representation.
func String(kind Type, wire []byte) (string, error) {
	length := kind.length()
	if !kind.valid() {
		return "", errors.New("unknown identifier type")
	}
	if len(wire) != length {
		return "", fmt.Errorf("identifier has %d bytes, want %d", len(wire), length)
	}

	encoding := shortEncoding
	if length == LongLength {
		encoding = longEncoding
	}
	return strings.ToLower(encoding.EncodeToString(wire)), nil
}

// Random returns a cryptographically random identifier of kind. The bytes
// are used directly, as required by the protocol.
func Random(kind Type) ([]byte, error) {
	length := kind.length()
	if !kind.valid() {
		return nil, errors.New("unknown identifier type")
	}

	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("generate identifier: %w", err)
	}
	return value, nil
}

// DeriveAccountID derives an account ID from a 32-byte Ed25519 public key.
func DeriveAccountID(publicKey []byte) ([]byte, error) {
	return derive("loopable-account-id", publicKey)
}

// DeriveInstanceID derives an instance ID from a 32-byte Ed25519 public key.
func DeriveInstanceID(publicKey []byte) ([]byte, error) {
	return derive("loopable-instance-id", publicKey)
}

func derive(domain string, publicKey []byte) ([]byte, error) {
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("public key has %d bytes, want 32", len(publicKey))
	}

	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(publicKey)
	return hash.Sum(nil), nil
}
