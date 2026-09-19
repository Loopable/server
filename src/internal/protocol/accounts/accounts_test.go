package accounts

import (
	"bytes"
	"testing"

	"loopable.party/server/internal/protocol/signatures"
)

func TestFirstDeviceAuthorization(t *testing.T) {
	identityPublicKey, identityPrivateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	authorization := FirstDeviceAuthorization{DeviceID: bytes.Repeat([]byte{1}, 16), DeviceSigningPublicKey: bytes.Repeat([]byte{2}, 32), DeviceEncryptionPublicKey: bytes.Repeat([]byte{3}, 32), DeviceKind: 0}
	if err := authorization.Sign(identityPrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := authorization.Validate(identityPublicKey); err != nil {
		t.Fatal(err)
	}
	authorization.DeviceID[0]++
	if err := authorization.Validate(identityPublicKey); err == nil {
		t.Fatal("accepted modified authorization")
	}
}

func TestRejectsBackupFirstDevice(t *testing.T) {
	_, identityPrivateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	authorization := FirstDeviceAuthorization{DeviceID: bytes.Repeat([]byte{1}, 16), DeviceSigningPublicKey: bytes.Repeat([]byte{2}, 32), DeviceEncryptionPublicKey: bytes.Repeat([]byte{3}, 32), DeviceKind: 1}
	if err := authorization.Sign(identityPrivateKey); err == nil {
		t.Fatal("accepted backup first device")
	}
}
