// Package hpke implements the Loopable HPKE input construction.
//
// HPKE parameters and input rules correspond to protospec/spec/24-hpke.md.
package hpke

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
)

const (
	RecipientKeyIDDomain = "loopable-recipient-key-id-v1\x00"
	ObjectKeyInfoDomain  = "loopable-hpke-object-key-v1\x00"
	ProtocolVersion      = "0.1"
)

// DeviceRecipient describes an X25519 device key before HPKE encryption.
type DeviceRecipient struct {
	AccountID []byte
	DeviceID  []byte
	PublicKey []byte
}

func (r DeviceRecipient) descriptor() map[uint64]any {
	return map[uint64]any{0: uint64(0), 1: r.AccountID, 2: r.DeviceID, 3: r.PublicKey}
}

func (r DeviceRecipient) validate() error {
	if len(r.AccountID) != 32 || len(r.DeviceID) != 16 || len(r.PublicKey) != 32 {
		return errors.New("device recipient fields have invalid lengths")
	}
	return nil
}

// RecipientKeyID returns the stable 16-byte identifier for a device recipient.
func RecipientKeyID(recipient DeviceRecipient) ([]byte, error) {
	if err := recipient.validate(); err != nil {
		return nil, err
	}
	descriptor, err := encoding.Encode(recipient.descriptor())
	if err != nil {
		return nil, fmt.Errorf("encode recipient descriptor: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(RecipientKeyIDDomain))
	_, _ = hash.Write(descriptor)
	digest := hash.Sum(nil)
	return append([]byte(nil), digest[:16]...), nil
}

// Info constructs the HPKE info bytes for a device recipient.
func Info(objectID, recipientKeyID []byte) ([]byte, error) {
	if len(objectID) != 32 {
		return nil, errors.New("object ID must be 32 bytes")
	}
	if len(recipientKeyID) != 16 {
		return nil, errors.New("recipient key ID must be 16 bytes")
	}
	info := make([]byte, 0, len(ObjectKeyInfoDomain)+32+16+len(ProtocolVersion))
	info = append(info, ObjectKeyInfoDomain...)
	info = append(info, objectID...)
	info = append(info, recipientKeyID...)
	info = append(info, ProtocolVersion...)
	return info, nil
}
