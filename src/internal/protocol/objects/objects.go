// Package objects implements object-envelope identity helpers.
//
// The rules correspond to protospec/spec/10-identifiers.md and
// protospec/spec/33-object-envelope.md.
package objects

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
)

const EnvelopeDomain = "loopable-object-envelope-v1\x00"

// NewObjectID returns a fresh random object identifier.
func NewObjectID() ([]byte, error) { return identifiers.Random(identifiers.ObjectID) }

// NewVersionID returns a fresh random version identifier.
func NewVersionID() ([]byte, error) { return identifiers.Random(identifiers.VersionID) }

// ValidateID checks an object or version identifier's exact wire length.
func ValidateID(id []byte) error {
	if len(id) != identifiers.LongLength {
		return fmt.Errorf("identifier has %d bytes, want %d", len(id), identifiers.LongLength)
	}
	return nil
}

// EnvelopeID derives the identifier of a complete object envelope.
func EnvelopeID(envelope map[uint64]any) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("object envelope is nil")
	}
	encoded, err := encoding.Encode(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode object envelope: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(EnvelopeDomain))
	_, _ = hash.Write(encoded)
	return hash.Sum(nil), nil
}
