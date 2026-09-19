// Package mls defines the Loopable MLS integration boundary.
//
// The rules correspond to protospec/spec/25-mls.md. The server never performs
// MLS key management itself; it defines the Loopable-specific pieces that bind
// an MLS participant to a Loopable identity and carries MLS control messages as
// opaque encrypted objects (spec 33).
package mls

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
)

// MLSSuite is the mandatory MLS cipher suite per 20.9 and 25.2.
const MLSSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"

// CredentialDomain is the domain-separation label registered in 20.12 for the
// MLS credential binding. It MUST lead the credential identity when a credential
// type is presented outside HTTPS negotiation, per 25.3.
const CredentialDomain = "loopable-mls-credential-v1\x00"

// CredentialTypeDevice identifies a Loopable device credential, per 25.3.
const CredentialTypeDevice uint64 = 0

// Credential is the Loopable MLS credential of 25.3: a custom MLS credential
// whose credential_data is this canonical CBOR map.
type Credential struct {
	AccountID                []byte
	DeviceID                 []byte
	DeviceSigningPublicKey   ed25519.PublicKey
	AccountIdentityPublicKey ed25519.PublicKey
}

// Wire returns the canonical CBOR credential_data map, per 25.3.
func (c Credential) Wire() map[uint64]any {
	return map[uint64]any{
		0: CredentialTypeDevice,
		1: c.AccountID,
		2: c.DeviceID,
		3: c.DeviceSigningPublicKey,
		4: c.AccountIdentityPublicKey,
	}
}

// CredentialData returns the canonical CBOR encoding of the credential_data map.
func (c Credential) CredentialData() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return encoding.Encode(c.Wire())
}

// Validate checks the credential's lengths and its identity binding: the
// credential MUST claim the account whose identity key is present, and the
// account_id MUST be the derivation of account_identity_public_key per 10.5,
// per 25.3.
func (c Credential) Validate() error {
	if len(c.AccountID) != identifiers.LongLength {
		return errors.New("credential account ID must be 32 bytes")
	}
	if len(c.DeviceID) != identifiers.ShortLength {
		return errors.New("credential device ID must be 16 bytes")
	}
	if len(c.DeviceSigningPublicKey) != ed25519.PublicKeySize {
		return errors.New("credential device signing key must be 32 bytes")
	}
	if len(c.AccountIdentityPublicKey) != ed25519.PublicKeySize {
		return errors.New("credential account identity key must be 32 bytes")
	}
	derived, err := identifiers.DeriveAccountID(c.AccountIdentityPublicKey)
	if err != nil {
		return fmt.Errorf("derive credential account ID: %w", err)
	}
	if string(derived) != string(c.AccountID) {
		return errors.New("credential account ID does not match its account identity key")
	}
	return nil
}

// Parse validates a decoded credential_data map into a typed Credential.
func Parse(value any) (Credential, error) {
	fields, ok := value.(map[uint64]any)
	if !ok {
		return Credential{}, errors.New("MLS credential data is not a map")
	}
	credentialType, err := fieldUint(fields, 0)
	if err != nil {
		return Credential{}, err
	}
	if credentialType != CredentialTypeDevice {
		return Credential{}, fmt.Errorf("unknown MLS credential type %d", credentialType)
	}
	accountID, err := fieldBytes(fields, 1)
	if err != nil {
		return Credential{}, err
	}
	deviceID, err := fieldBytes(fields, 2)
	if err != nil {
		return Credential{}, err
	}
	deviceSigningKey, err := fieldBytes(fields, 3)
	if err != nil {
		return Credential{}, err
	}
	accountIdentityKey, err := fieldBytes(fields, 4)
	if err != nil {
		return Credential{}, err
	}
	credential := Credential{
		AccountID:                accountID,
		DeviceID:                 deviceID,
		DeviceSigningPublicKey:   ed25519.PublicKey(deviceSigningKey),
		AccountIdentityPublicKey: ed25519.PublicKey(accountIdentityKey),
	}
	if err := credential.Validate(); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

func fieldBytes(fields map[uint64]any, key uint64) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("MLS credential field %d is missing", key)
	}
	switch buffer := value.(type) {
	case []byte:
		return buffer, nil
	case ed25519.PublicKey:
		return []byte(buffer), nil
	default:
		return nil, fmt.Errorf("MLS credential field %d is not bytes", key)
	}
}

func fieldUint(fields map[uint64]any, key uint64) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("MLS credential field %d is missing", key)
	}
	number, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("MLS credential field %d is not an unsigned integer", key)
	}
	return number, nil
}
