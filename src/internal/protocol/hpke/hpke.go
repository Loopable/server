// Package hpke implements the Loopable HPKE input construction.
//
// HPKE parameters and input rules correspond to protospec/spec/24-hpke.md.
package hpke

import (
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"fmt"

	rfc9180 "filippo.io/hpke"
	"loopable.party/server/internal/protocol/encoding"
)

const x25519KeySize = 32

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

// Wrap seals a content-encryption key for a device recipient using HPKE base mode.
func Wrap(recipientPublicKey, objectID, recipientKeyID, cek []byte) (encapsulatedKey, wrappedKey []byte, err error) {
	if len(recipientPublicKey) != x25519KeySize {
		return nil, nil, errors.New("recipient public key must be 32 bytes")
	}
	if len(cek) != 32 {
		return nil, nil, errors.New("content-encryption key must be 32 bytes")
	}
	info, err := Info(objectID, recipientKeyID)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := ecdh.X25519().NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse recipient public key: %w", err)
	}
	hpkePublicKey, err := rfc9180.NewDHKEMPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create HPKE recipient key: %w", err)
	}
	encapsulatedKey, sender, err := rfc9180.NewSender(hpkePublicKey, rfc9180.HKDFSHA256(), rfc9180.AES256GCM(), info)
	if err != nil {
		return nil, nil, fmt.Errorf("create HPKE sender: %w", err)
	}
	wrappedKey, err = sender.Seal(nil, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap content-encryption key: %w", err)
	}
	return encapsulatedKey, wrappedKey, nil
}

// Unwrap opens a content-encryption key with the recipient's X25519 private key.
func Unwrap(recipientPrivateKey, objectID, recipientKeyID, encapsulatedKey, wrappedKey []byte) ([]byte, error) {
	if len(recipientPrivateKey) != x25519KeySize {
		return nil, errors.New("recipient private key must be 32 bytes")
	}
	if len(encapsulatedKey) != x25519KeySize {
		return nil, errors.New("encapsulated key must be 32 bytes")
	}
	info, err := Info(objectID, recipientKeyID)
	if err != nil {
		return nil, err
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse recipient private key: %w", err)
	}
	hpkePrivateKey, err := rfc9180.NewDHKEMPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create HPKE recipient key: %w", err)
	}
	recipient, err := rfc9180.NewRecipient(encapsulatedKey, hpkePrivateKey, rfc9180.HKDFSHA256(), rfc9180.AES256GCM(), info)
	if err != nil {
		return nil, fmt.Errorf("create HPKE recipient: %w", err)
	}
	cek, err := recipient.Open(nil, wrappedKey)
	if err != nil {
		return nil, errors.New("HPKE key unwrap failed")
	}
	return cek, nil
}
