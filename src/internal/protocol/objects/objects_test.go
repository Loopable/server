package objects

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/encryption"
	"loopable.party/server/internal/protocol/hpke"
	"loopable.party/server/internal/protocol/identifiers"
)

func TestObjectTypeRegistry(t *testing.T) {
	for objectType, name := range map[uint64]string{
		ObjectTypePost: "post", ObjectTypeReply: "reply", ObjectTypeProfile: "profile",
		ObjectTypeMedia: "media", ObjectTypeDirectMessage: "direct_message", ObjectTypeRelationship: "relationship",
		ObjectTypeMembership: "membership", ObjectTypeGroupMetadata: "group_metadata",
		ObjectTypeNotification: "notification", ObjectTypeMLSMessage: "mls_message",
	} {
		resolved, err := LookupType(objectType)
		if err != nil {
			t.Fatalf("object type %d rejected: %v", objectType, err)
		}
		if resolved != name {
			t.Fatalf("object type %d resolved to %q, want %q", objectType, resolved, name)
		}
	}
	if _, err := LookupType(50); err == nil {
		t.Fatal("unknown object type accepted")
	}
}

func TestValidDeviceEnvelope(t *testing.T) {
	object := testEnvelope()
	if err := object.Validate(); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

func TestEnvelopeRejectsWrongSuiteForType(t *testing.T) {
	mediaWithAES := testEnvelope()
	mediaWithAES.ObjectType = ObjectTypeMedia
	mediaWithAES.EncryptionSuite = EncryptionSuiteAESGCM
	if err := mediaWithAES.Validate(); err == nil {
		t.Fatal("media object with AES-GCM suite accepted")
	}
	postWithStreaming := testEnvelope()
	postWithStreaming.EncryptionSuite = EncryptionSuiteStreamingMedia
	postWithStreaming.Nonce = nil
	if err := postWithStreaming.Validate(); err == nil {
		t.Fatal("post object with streaming media suite accepted")
	}
	unknownSuite := testEnvelope()
	unknownSuite.EncryptionSuite = 7
	if err := unknownSuite.Validate(); err == nil {
		t.Fatal("unknown encryption suite accepted")
	}
}

func TestEnvelopeRejectsInvalidLengths(t *testing.T) {
	object := testEnvelope()
	object.ObjectID = bytes.Repeat([]byte{0x11}, 31)
	if err := object.Validate(); err == nil {
		t.Fatal("short object ID accepted")
	}
	object = testEnvelope()
	object.VersionID = bytes.Repeat([]byte{0x22}, 33)
	if err := object.Validate(); err == nil {
		t.Fatal("long version ID accepted")
	}
	object = testEnvelope()
	object.Nonce = bytes.Repeat([]byte{0x88}, encryption.NonceSize-1)
	if err := object.Validate(); err == nil {
		t.Fatal("short AES-GCM nonce accepted")
	}
	object = testEnvelope()
	object.Ciphertext = bytes.Repeat([]byte{0x99}, encryption.TagSize-1)
	if err := object.Validate(); err == nil {
		t.Fatal("ciphertext without a full tag accepted")
	}
	object = testEnvelope()
	object.Nonce = nil
	if err := object.Validate(); err == nil {
		t.Fatal("missing AES-GCM nonce accepted")
	}
}

func TestEnvelopeRequiresRecipients(t *testing.T) {
	object := testEnvelope()
	object.Recipients = nil
	if err := object.Validate(); err == nil {
		t.Fatal("envelope without recipients accepted")
	}
	object.Recipients = []RecipientRecord{}
	if err := object.Validate(); err == nil {
		t.Fatal("envelope with empty recipient list accepted")
	}
}

func TestDeviceRecipientRules(t *testing.T) {
	record := validDeviceRecord()
	record.AccountID = bytes.Repeat([]byte{0x33}, 31)
	if err := record.validate(); err == nil {
		t.Fatal("short device recipient account ID accepted")
	}
	record = validDeviceRecord()
	record.AccountID = nil
	if err := record.validate(); err == nil {
		t.Fatal("empty device recipient account ID accepted")
	}
	record = validDeviceRecord()
	record.DeviceID = bytes.Repeat([]byte{0x44}, 15)
	if err := record.validate(); err == nil {
		t.Fatal("short device recipient device ID accepted")
	}
	record = validDeviceRecord()
	record.RecipientKeyID = bytes.Repeat([]byte{0x55}, 15)
	if err := record.validate(); err == nil {
		t.Fatal("short device recipient key ID accepted")
	}
	record = validDeviceRecord()
	record.EncapsulatedKey = bytes.Repeat([]byte{0x66}, 31)
	if err := record.validate(); err == nil {
		t.Fatal("short encapsulated key accepted")
	}
	record = validDeviceRecord()
	record.WrappedKey = bytes.Repeat([]byte{0x77}, 47)
	if err := record.validate(); err == nil {
		t.Fatal("short wrapped key accepted")
	}
}

func TestMLSRecipientRules(t *testing.T) {
	record := RecipientRecord{
		Kind:           RecipientKindMLSGroup,
		RecipientKeyID: bytes.Repeat([]byte{0x55}, identifiers.ShortLength),
	}
	if err := record.validate(); err != nil {
		t.Fatalf("valid MLS group recipient rejected: %v", err)
	}
	record.AccountID = bytes.Repeat([]byte{0x33}, identifiers.LongLength)
	if err := record.validate(); err == nil {
		t.Fatal("MLS group recipient with account ID accepted")
	}
	record = RecipientRecord{Kind: RecipientKindMLSGroup, RecipientKeyID: bytes.Repeat([]byte{0x55}, identifiers.ShortLength)}
	record.WrappedKey = bytes.Repeat([]byte{0x77}, 48)
	if err := record.validate(); err == nil {
		t.Fatal("MLS group recipient with wrapped key accepted")
	}
}

func TestMetadataMustNotCarryAuthenticatedFields(t *testing.T) {
	for _, key := range []uint64{0, 1, 2, 3, 4} {
		object := testEnvelope()
		object.Metadata = map[uint64]any{key: "hint"}
		if err := object.Validate(); err == nil {
			t.Fatalf("metadata carrying authenticated field %d accepted", key)
		}
	}
	object := testEnvelope()
	object.Metadata = map[uint64]any{8: "hint", 9: []byte("ok")}
	if err := object.Validate(); err != nil {
		t.Fatalf("lossless metadata rejected: %v", err)
	}
}

func TestEnvelopeIDIsCanonicalAndContentBound(t *testing.T) {
	first, err := testEnvelope().EnvelopeID()
	if err != nil {
		t.Fatal(err)
	}

	hashed := map[uint64]any{
		0: ProtocolVersion,
		1: bytes.Repeat([]byte{0x11}, identifiers.LongLength),
		2: ObjectTypePost,
		3: EncryptionSuiteAESGCM,
		4: bytes.Repeat([]byte{0x22}, identifiers.LongLength),
		5: bytes.Repeat([]byte{0x88}, encryption.NonceSize),
		6: bytes.Repeat([]byte{0x99}, 32+encryption.TagSize),
		7: recipientRecords([]RecipientRecord{validDeviceRecord()}),
	}
	reshuffled, err := envelopeID(map[uint64]any{
		4: hashed[4], 0: hashed[0], 5: hashed[5], 2: hashed[2], 1: hashed[1], 7: hashed[7], 6: hashed[6], 3: hashed[3],
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reshuffled) {
		t.Fatal("map order changed envelope ID")
	}

	parsed, err := Parse(testEnvelope().Wire())
	if err != nil {
		t.Fatal(err)
	}
	fromParsed, err := parsed.EnvelopeID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, fromParsed) {
		t.Fatal("envelope ID changed across parse roundtrip")
	}

	object := testEnvelope()
	object.Ciphertext = append(append([]byte(nil), object.Ciphertext...), 0x00)
	mutated, err := object.EnvelopeID()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, mutated) {
		t.Fatal("envelope ID ignored a ciphertext change")
	}
}

func TestAADMatchesEncryptionPackage(t *testing.T) {
	object := testEnvelope()
	aad, err := object.AAD()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := encryption.SecurityMetadata{
		ObjectID:        object.ObjectID,
		ObjectType:      object.ObjectType,
		EncryptionSuite: object.EncryptionSuite,
		VersionID:       object.VersionID,
	}.AAD()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aad, expected) {
		t.Fatal("associated data diverges from the authoritative construction")
	}
}

func TestEnvelopeRoundtrip(t *testing.T) {
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accountID := bytes.Repeat([]byte{0x33}, identifiers.LongLength)
	deviceID := bytes.Repeat([]byte{0x44}, identifiers.ShortLength)
	publicKey := recipientKey.PublicKey().Bytes()
	recipient := hpke.DeviceRecipient{AccountID: accountID, DeviceID: deviceID, PublicKey: publicKey}
	recipientKeyID, err := hpke.RecipientKeyID(recipient)
	if err != nil {
		t.Fatal(err)
	}

	objectID := bytes.Repeat([]byte{0x11}, identifiers.LongLength)
	versionID := bytes.Repeat([]byte{0x22}, identifiers.LongLength)
	cek, err := encryption.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, wrapped, err := hpke.Wrap(publicKey, objectID, recipientKeyID, cek)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := encoding.Encode(map[uint64]any{0: "hello loopable"})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := encryption.Encrypt(cek, plaintext, encryption.SecurityMetadata{
		ObjectID: objectID, ObjectType: ObjectTypePost, EncryptionSuite: EncryptionSuiteAESGCM, VersionID: versionID,
	})
	if err != nil {
		t.Fatal(err)
	}

	object := Object{
		ObjectID:        objectID,
		ObjectType:      ObjectTypePost,
		EncryptionSuite: EncryptionSuiteAESGCM,
		VersionID:       versionID,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
		Recipients: []RecipientRecord{{
			Kind: RecipientKindDevice, AccountID: accountID, DeviceID: deviceID,
			RecipientKeyID: recipientKeyID, EncapsulatedKey: enc, WrappedKey: wrapped,
		}},
	}
	if err := object.Validate(); err != nil {
		t.Fatalf("constructed envelope rejected: %v", err)
	}
	wire, err := encoding.Encode(object.Wire())
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[uint64]any
	if err := encoding.Decode(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(decoded)
	if err != nil {
		t.Fatalf("decoded envelope rejected: %v", err)
	}

	recoveredCEK, err := hpke.Unwrap(recipientKey.Bytes(), parsed.ObjectID, parsed.Recipients[0].RecipientKeyID, parsed.Recipients[0].EncapsulatedKey, parsed.Recipients[0].WrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := encryption.Decrypt(recoveredCEK, parsed.Nonce, parsed.Ciphertext, encryption.SecurityMetadata{
		ObjectID: parsed.ObjectID, ObjectType: parsed.ObjectType, EncryptionSuite: parsed.EncryptionSuite, VersionID: parsed.VersionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatal("decrypted plaintext does not match the original")
	}
}

func testEnvelope() Object {
	return Object{
		ObjectID:        bytes.Repeat([]byte{0x11}, identifiers.LongLength),
		ObjectType:      ObjectTypePost,
		EncryptionSuite: EncryptionSuiteAESGCM,
		VersionID:       bytes.Repeat([]byte{0x22}, identifiers.LongLength),
		Nonce:           bytes.Repeat([]byte{0x88}, encryption.NonceSize),
		Ciphertext:      bytes.Repeat([]byte{0x99}, 32+encryption.TagSize),
		Recipients:      []RecipientRecord{validDeviceRecord()},
	}
}

func validDeviceRecord() RecipientRecord {
	return RecipientRecord{
		Kind:            RecipientKindDevice,
		AccountID:       bytes.Repeat([]byte{0x33}, identifiers.LongLength),
		DeviceID:        bytes.Repeat([]byte{0x44}, identifiers.ShortLength),
		RecipientKeyID:  bytes.Repeat([]byte{0x55}, identifiers.ShortLength),
		EncapsulatedKey: bytes.Repeat([]byte{0x66}, 32),
		WrappedKey:      bytes.Repeat([]byte{0x77}, 48),
	}
}
