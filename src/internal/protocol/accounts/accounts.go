// Package accounts implements account identity and first-device authorization.
//
// The rules correspond to protospec/spec/11-accounts.md and section 34.3.
package accounts

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
)

const ProtocolVersion = "0.1"

type FirstDeviceAuthorization struct {
	AccountID                 []byte
	DeviceID                  []byte
	DeviceSigningPublicKey    ed25519.PublicKey
	DeviceEncryptionPublicKey []byte
	DeviceKind                uint64
	IdentitySignature         []byte
}

func (a FirstDeviceAuthorization) unsigned() map[uint64]any {
	return map[uint64]any{0: ProtocolVersion, 1: a.AccountID, 2: a.DeviceID, 3: a.DeviceSigningPublicKey, 4: a.DeviceEncryptionPublicKey, 5: a.DeviceKind}
}

func (a FirstDeviceAuthorization) Validate(identityPublicKey ed25519.PublicKey) error {
	if len(identityPublicKey) != ed25519.PublicKeySize || len(a.AccountID) != identifiers.LongLength || len(a.DeviceID) != identifiers.ShortLength || len(a.DeviceSigningPublicKey) != ed25519.PublicKeySize || len(a.DeviceEncryptionPublicKey) != 32 || len(a.IdentitySignature) != ed25519.SignatureSize {
		return errors.New("invalid first-device authorization lengths")
	}
	derived, err := identifiers.DeriveAccountID(identityPublicKey)
	if err != nil || string(derived) != string(a.AccountID) {
		return errors.New("first-device account ID does not match identity key")
	}
	if a.DeviceKind == 1 {
		return errors.New("backup device cannot be the first device")
	}
	return signatures.Verify(identityPublicKey, signatures.FirstDeviceAuthorizationDomain, a.unsigned(), a.IdentitySignature)
}

func (a *FirstDeviceAuthorization) Sign(identityPrivateKey ed25519.PrivateKey) error {
	if len(identityPrivateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid account identity private key")
	}
	publicKey := identityPrivateKey.Public().(ed25519.PublicKey)
	if len(a.AccountID) == 0 {
		derived, err := identifiers.DeriveAccountID(publicKey)
		if err != nil {
			return err
		}
		a.AccountID = derived
	}
	if len(a.AccountID) != identifiers.LongLength || len(a.DeviceID) != identifiers.ShortLength || len(a.DeviceSigningPublicKey) != ed25519.PublicKeySize || len(a.DeviceEncryptionPublicKey) != 32 || a.DeviceKind == 1 {
		return errors.New("invalid first-device authorization")
	}
	signature, err := signatures.Sign(identityPrivateKey, signatures.FirstDeviceAuthorizationDomain, a.unsigned())
	if err != nil {
		return err
	}
	a.IdentitySignature = signature
	return nil
}

func (a FirstDeviceAuthorization) Wire() map[uint64]any {
	value := a.unsigned()
	value[6] = a.IdentitySignature
	return value
}

// ParseFirstDeviceAuthorization decodes a FirstDeviceAuthorization record from
// its wire map form, as carried in an ACCOUNT_CREATED body field 3.
func ParseFirstDeviceAuthorization(value any) (FirstDeviceAuthorization, error) {
	fields, ok := value.(map[uint64]any)
	if !ok {
		return FirstDeviceAuthorization{}, errors.New("first-device authorization is not a map")
	}
	accountID, err := recordBytes(fields, 1)
	if err != nil {
		return FirstDeviceAuthorization{}, err
	}
	deviceID, err := recordBytes(fields, 2)
	if err != nil {
		return FirstDeviceAuthorization{}, err
	}
	signingKey, err := recordBytes(fields, 3)
	if err != nil {
		return FirstDeviceAuthorization{}, err
	}
	encryptionKey, err := recordBytes(fields, 4)
	if err != nil {
		return FirstDeviceAuthorization{}, err
	}
	deviceKind, err := recordUint(fields, 5)
	if err != nil {
		return FirstDeviceAuthorization{}, err
	}
	signature, err := recordBytes(fields, 6)
	if err != nil {
		return FirstDeviceAuthorization{}, err
	}
	return FirstDeviceAuthorization{
		AccountID:                 accountID,
		DeviceID:                  deviceID,
		DeviceSigningPublicKey:    ed25519.PublicKey(signingKey),
		DeviceEncryptionPublicKey: encryptionKey,
		DeviceKind:                deviceKind,
		IdentitySignature:         signature,
	}, nil
}

func recordBytes(fields map[uint64]any, key uint64) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("missing first-device authorization field %d", key)
	}
	switch buffer := value.(type) {
	case []byte:
		return buffer, nil
	case ed25519.PublicKey:
		return []byte(buffer), nil
	default:
		return nil, fmt.Errorf("first-device authorization field %d is not bytes", key)
	}
}

func recordUint(fields map[uint64]any, key uint64) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("missing first-device authorization field %d", key)
	}
	number, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("first-device authorization field %d is not an unsigned integer", key)
	}
	return number, nil
}

func (a FirstDeviceAuthorization) CanonicalBytes() ([]byte, error) {
	if len(a.IdentitySignature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid identity signature")
	}
	return encoding.Encode(a.Wire())
}
