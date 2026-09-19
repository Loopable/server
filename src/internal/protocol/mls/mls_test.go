package mls

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
)

func validCredential(t *testing.T) (Credential, ed25519.PublicKey) {
	t.Helper()
	accountPub, _, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := identifiers.DeriveAccountID(accountPub)
	if err != nil {
		t.Fatal(err)
	}
	devicePub, _, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return Credential{
		AccountID:                accountID,
		DeviceID:                 bytes.Repeat([]byte{0x02}, identifiers.ShortLength),
		DeviceSigningPublicKey:   devicePub,
		AccountIdentityPublicKey: accountPub,
	}, accountPub
}

func TestValidCredential(t *testing.T) {
	credential, _ := validCredential(t)
	if err := credential.Validate(); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}
	for key, field := range credential.Wire() {
		switch field := field.(type) {
		case uint64:
			if field != 0 {
				t.Fatalf("credential field %d type is not the device type", key)
			}
		case []byte, ed25519.PublicKey:
		default:
			t.Fatalf("credential field %d has unexpected type %T", key, field)
		}
	}
}

func TestCredentialDomainLabel(t *testing.T) {
	if len(CredentialDomain) > 32 {
		t.Fatalf("credential domain exceeds the 32-byte identity prefix: %d bytes", len(CredentialDomain))
	}
}

func TestCredentialDataRoundtrip(t *testing.T) {
	credential, _ := validCredential(t)
	data, err := credential.CredentialData()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[uint64]any
	if err := encoding.Decode(data, &decoded); err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(decoded)
	if err != nil {
		t.Fatalf("decoded credential rejected: %v", err)
	}
	if !bytes.Equal(parsed.AccountID, credential.AccountID) || !bytes.Equal(parsed.DeviceID, credential.DeviceID) {
		t.Fatal("credential roundtrip changed identity fields")
	}
}

func TestCredentialRejectsMismatchedAccount(t *testing.T) {
	credential, _ := validCredential(t)
	credential.AccountID = bytes.Repeat([]byte{0x00}, identifiers.LongLength)
	if err := credential.Validate(); err == nil {
		t.Fatal("credential with mismatched account ID accepted")
	}
}

func TestCredentialRejectsWrongLengths(t *testing.T) {
	credential, _ := validCredential(t)
	credential.DeviceID = bytes.Repeat([]byte{0x02}, identifiers.ShortLength-1)
	if err := credential.Validate(); err == nil {
		t.Fatal("short credential device ID accepted")
	}
	credential, _ = validCredential(t)
	credential.DeviceSigningPublicKey = bytes.Repeat([]byte{0x03}, ed25519.PublicKeySize-1)
	if err := credential.Validate(); err == nil {
		t.Fatal("short credential device signing key accepted")
	}
	credential, _ = validCredential(t)
	credential.AccountIdentityPublicKey = bytes.Repeat([]byte{0x04}, ed25519.PublicKeySize+1)
	if err := credential.Validate(); err == nil {
		t.Fatal("long credential account identity key accepted")
	}
}

func TestParseRejectsUnknownTypeAndFields(t *testing.T) {
	credential, _ := validCredential(t)
	wire := credential.Wire()
	wire[0] = uint64(9)
	if _, err := Parse(wire); err == nil {
		t.Fatal("unknown credential type accepted")
	}
	wire = credential.Wire()
	delete(wire, 1)
	if _, err := Parse(wire); err == nil {
		t.Fatal("credential missing account ID accepted")
	}
	wire = credential.Wire()
	wire[3] = "not bytes"
	if _, err := Parse(wire); err == nil {
		t.Fatal("credential with non-bytes signing key accepted")
	}
}
