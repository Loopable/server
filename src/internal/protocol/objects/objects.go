// Package objects implements Loopable's encrypted object envelope.
//
// The envelope rules correspond to protospec/spec/33-object-envelope.md, the
// recipient records to protospec/spec/24-hpke.md section 24.6 and
// protospec/spec/25-mls.md section 25.6, and the associated data to
// protospec/spec/23-encryption.md section 23.4.
package objects

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/encryption"
	"loopable.party/server/internal/protocol/identifiers"
)

const (
	ProtocolVersion = "0.1"
	EnvelopeDomain  = "loopable-object-envelope-v1\x00"
)

// Object types per protospec/spec/33-object-envelope.md section 33.7.
const (
	ObjectTypePost          uint64 = 0
	ObjectTypeReply         uint64 = 1
	ObjectTypeProfile       uint64 = 2
	ObjectTypeMedia         uint64 = 3
	ObjectTypeDirectMessage uint64 = 4
	ObjectTypeRelationship  uint64 = 5
	ObjectTypeMembership    uint64 = 6
	ObjectTypeGroupMetadata uint64 = 7
	ObjectTypeNotification  uint64 = 8
	ObjectTypeMLSMessage    uint64 = 9
)

// Encryption suites per protospec/spec/33-object-envelope.md section 33.3.
const (
	EncryptionSuiteAESGCM         uint64 = 0
	EncryptionSuiteStreamingMedia uint64 = 1
)

// Recipient kinds per protospec/spec/24-hpke.md section 24.6.
const (
	RecipientKindDevice   uint64 = 0
	RecipientKindMLSGroup uint64 = 1
)

// LookupType returns the name of an object type code. Unknown codes are rejected.
func LookupType(objectType uint64) (string, error) {
	switch objectType {
	case ObjectTypePost:
		return "post", nil
	case ObjectTypeReply:
		return "reply", nil
	case ObjectTypeProfile:
		return "profile", nil
	case ObjectTypeMedia:
		return "media", nil
	case ObjectTypeDirectMessage:
		return "direct_message", nil
	case ObjectTypeRelationship:
		return "relationship", nil
	case ObjectTypeMembership:
		return "membership", nil
	case ObjectTypeGroupMetadata:
		return "group_metadata", nil
	case ObjectTypeNotification:
		return "notification", nil
	case ObjectTypeMLSMessage:
		return "mls_message", nil
	default:
		return "", fmt.Errorf("unknown object type %d", objectType)
	}
}

// RecipientRecord is one independently protected key record, per 24.6. For a
// device recipient it carries the wrapped content-encryption key; for an MLS
// group recipient (`RecipientKindMLSGroup`) the key material is empty.
type RecipientRecord struct {
	Kind            uint64
	AccountID       []byte
	DeviceID        []byte
	RecipientKeyID  []byte
	EncapsulatedKey []byte
	WrappedKey      []byte
}

// Object is the complete object envelope, per 33.2. The plaintext content is
// never stored unprotected; the envelope authenticates the object-level fields
// through the associated data of 33.4.
type Object struct {
	ObjectID        []byte
	ObjectType      uint64
	EncryptionSuite uint64
	VersionID       []byte
	Nonce           []byte
	Ciphertext      []byte
	Recipients      []RecipientRecord
	Metadata        map[uint64]any
}

// NewObjectID returns a fresh random object identifier.
func NewObjectID() ([]byte, error) { return identifiers.Random(identifiers.ObjectID) }

// NewVersionID returns a fresh random version identifier.
func NewVersionID() ([]byte, error) { return identifiers.Random(identifiers.VersionID) }

func (o Object) Validate() error {
	if len(o.ObjectID) != identifiers.LongLength {
		return errors.New("object ID must be 32 bytes")
	}
	if _, err := LookupType(o.ObjectType); err != nil {
		return err
	}
	switch o.EncryptionSuite {
	case EncryptionSuiteAESGCM:
		if o.ObjectType == ObjectTypeMedia {
			return errors.New("media objects must use the streaming media encryption suite")
		}
		if len(o.Nonce) != encryption.NonceSize {
			return errors.New("AES-GCM nonce must be 12 bytes")
		}
		if len(o.Ciphertext) < encryption.TagSize {
			return errors.New("AES-GCM ciphertext must carry a 16-byte tag")
		}
	case EncryptionSuiteStreamingMedia:
		if o.ObjectType != ObjectTypeMedia {
			return errors.New("the streaming media encryption suite applies only to media objects")
		}
		if len(o.Nonce) != 0 {
			return errors.New("streaming media nonce must be empty")
		}
		if len(o.Ciphertext) == 0 {
			return errors.New("streaming media ciphertext must not be empty")
		}
	default:
		return fmt.Errorf("unknown encryption suite %d", o.EncryptionSuite)
	}
	if len(o.VersionID) != identifiers.LongLength {
		return errors.New("version ID must be 32 bytes")
	}
	if len(o.Recipients) == 0 {
		return errors.New("object envelope must carry at least one recipient record")
	}
	for i, record := range o.Recipients {
		if err := record.validate(); err != nil {
			return fmt.Errorf("recipient record %d: %w", i, err)
		}
	}
	for key := range o.Metadata {
		if key <= 4 {
			return fmt.Errorf("metadata must not carry authenticated field %d", key)
		}
	}
	return nil
}

func (r RecipientRecord) validate() error {
	switch r.Kind {
	case RecipientKindDevice:
		if len(r.AccountID) != identifiers.LongLength {
			return errors.New("device recipient account ID must be 32 bytes")
		}
		if len(r.DeviceID) != identifiers.ShortLength {
			return errors.New("device recipient device ID must be 16 bytes")
		}
		if len(r.RecipientKeyID) != identifiers.ShortLength {
			return errors.New("recipient key ID must be 16 bytes")
		}
		if len(r.EncapsulatedKey) != 32 {
			return errors.New("device recipient encapsulated key must be 32 bytes")
		}
		if len(r.WrappedKey) != 48 {
			return errors.New("device recipient wrapped key must carry the sealed 32-byte key and tag")
		}
		return nil
	case RecipientKindMLSGroup:
		if len(r.AccountID) != 0 || len(r.DeviceID) != 0 {
			return errors.New("MLS group recipient must have empty account and device IDs")
		}
		if len(r.RecipientKeyID) != identifiers.ShortLength {
			return errors.New("MLS group recipient key ID must be 16 bytes")
		}
		if len(r.EncapsulatedKey) != 0 || len(r.WrappedKey) != 0 {
			return errors.New("MLS group recipient must not carry encapsulated or wrapped keys")
		}
		return nil
	default:
		return fmt.Errorf("unknown recipient kind %d", r.Kind)
	}
}

// AAD returns the authoritative AES-GCM associated data of 23.4.
func (o Object) AAD() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	metadata := encryption.SecurityMetadata{
		ObjectID:        o.ObjectID,
		ObjectType:      o.ObjectType,
		EncryptionSuite: o.EncryptionSuite,
		VersionID:       o.VersionID,
	}
	return metadata.AAD()
}

// Wire returns the complete object map, including recipients and metadata.
func (o Object) Wire() map[uint64]any {
	value := map[uint64]any{
		0: ProtocolVersion,
		1: o.ObjectID,
		2: o.ObjectType,
		3: o.EncryptionSuite,
		4: o.VersionID,
		5: o.Nonce,
		6: o.Ciphertext,
		7: recipientRecords(o.Recipients),
	}
	if o.Metadata != nil {
		value[8] = o.Metadata
	}
	return value
}

// CanonicalBytes returns the deterministic CBOR of the complete envelope.
func (o Object) CanonicalBytes() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return encoding.Encode(o.Wire())
}

// EnvelopeID derives the identifier of the complete envelope, per 33.3.
func (o Object) EnvelopeID() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return envelopeID(o.Wire())
}

// envelopeID derives the identifier of a complete wire envelope, per 33.3.
func envelopeID(envelope map[uint64]any) ([]byte, error) {
	encoded, err := encoding.Encode(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode object envelope: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(EnvelopeDomain))
	_, _ = hash.Write(encoded)
	return hash.Sum(nil), nil
}

// Parse validates a decoded wire envelope and returns its typed form.
func Parse(value any) (Object, error) {
	fields, err := asFieldMap(value)
	if err != nil {
		return Object{}, err
	}
	version, ok := fields[0].(string)
	if !ok || version != ProtocolVersion {
		return Object{}, errors.New("object envelope protocol version is invalid")
	}
	objectID, err := fieldBytes(fields, 1)
	if err != nil {
		return Object{}, err
	}
	objectType, err := fieldUint(fields, 2)
	if err != nil {
		return Object{}, err
	}
	encryptionSuite, err := fieldUint(fields, 3)
	if err != nil {
		return Object{}, err
	}
	versionID, err := fieldBytes(fields, 4)
	if err != nil {
		return Object{}, err
	}
	nonce, err := fieldBytes(fields, 5)
	if err != nil {
		return Object{}, err
	}
	ciphertext, err := fieldBytes(fields, 6)
	if err != nil {
		return Object{}, err
	}
	recipientsValue, ok := fields[7].([]any)
	if !ok {
		return Object{}, errors.New("object envelope recipients must be an array")
	}
	recipients := make([]RecipientRecord, len(recipientsValue))
	for i, item := range recipientsValue {
		record, err := parseRecipient(item)
		if err != nil {
			return Object{}, fmt.Errorf("recipient record %d: %w", i, err)
		}
		recipients[i] = record
	}
	var metadata map[uint64]any
	if metadataValue, ok := fields[8]; ok {
		metadata, err = asFieldMap(metadataValue)
		if err != nil {
			return Object{}, errors.New("object envelope metadata must be a map")
		}
	}
	object := Object{
		ObjectID:        objectID,
		ObjectType:      objectType,
		EncryptionSuite: encryptionSuite,
		VersionID:       versionID,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
		Recipients:      recipients,
		Metadata:        metadata,
	}
	if err := object.Validate(); err != nil {
		return Object{}, err
	}
	return object, nil
}

func parseRecipient(value any) (RecipientRecord, error) {
	fields, err := asFieldMap(value)
	if err != nil {
		return RecipientRecord{}, errors.New("recipient record is not a map")
	}
	kind, err := fieldUint(fields, 0)
	if err != nil {
		return RecipientRecord{}, err
	}
	accountID, err := fieldBytes(fields, 1)
	if err != nil {
		return RecipientRecord{}, err
	}
	deviceID, err := fieldBytes(fields, 2)
	if err != nil {
		return RecipientRecord{}, err
	}
	recipientKeyID, err := fieldBytes(fields, 3)
	if err != nil {
		return RecipientRecord{}, err
	}
	encapsulatedKey, err := fieldBytes(fields, 4)
	if err != nil {
		return RecipientRecord{}, err
	}
	wrappedKey, err := fieldBytes(fields, 5)
	if err != nil {
		return RecipientRecord{}, err
	}
	return RecipientRecord{
		Kind:            kind,
		AccountID:       accountID,
		DeviceID:        deviceID,
		RecipientKeyID:  recipientKeyID,
		EncapsulatedKey: encapsulatedKey,
		WrappedKey:      wrappedKey,
	}, nil
}

func recipientRecords(records []RecipientRecord) []any {
	value := make([]any, len(records))
	for i, record := range records {
		value[i] = map[uint64]any{
			0: record.Kind,
			1: record.AccountID,
			2: record.DeviceID,
			3: record.RecipientKeyID,
			4: record.EncapsulatedKey,
			5: record.WrappedKey,
		}
	}
	return value
}

func fieldBytes(fields map[uint64]any, key uint64) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("object envelope field %d is missing", key)
	}
	buffer, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("object envelope field %d is not bytes", key)
	}
	return buffer, nil
}

// asFieldMap accepts either a typed map[uint64]any or the map[any]any form a
// strict CBOR decoder produces for nested maps, and normalizes it to the typed
// form used by Parse.
func asFieldMap(value any) (map[uint64]any, error) {
	switch fields := value.(type) {
	case map[uint64]any:
		return fields, nil
	case map[any]any:
		normalized := make(map[uint64]any, len(fields))
		for key, item := range fields {
			number, ok := key.(uint64)
			if !ok {
				return nil, errors.New("map key is not an unsigned integer")
			}
			normalized[number] = item
		}
		return normalized, nil
	default:
		return nil, errors.New("value is not a map")
	}
}

func fieldUint(fields map[uint64]any, key uint64) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("object envelope field %d is missing", key)
	}
	number, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("object envelope field %d is not an unsigned integer", key)
	}
	return number, nil
}
