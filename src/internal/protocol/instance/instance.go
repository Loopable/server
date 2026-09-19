// Package instance implements instance identity and instance documents.
//
// The wire fields and signature rules correspond to protospec/spec/13-instances.md.
package instance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
)

const (
	ProtocolVersion = "0.1"
	DocumentDomain  = "loopable-instance-document-v1\x00"
)

// OperationalKey is a currently authorized instance federation key.
type OperationalKey struct {
	KeyID     []byte
	PublicKey ed25519.PublicKey
	NotBefore uint64
	NotAfter  uint64
}

// Document is the signed public instance identity document.
type Document struct {
	ProtocolVersion string
	InstanceID      []byte
	RootPublicKey   ed25519.PublicKey
	OperationalKeys []OperationalKey
	Domain          string
	Administrator   []byte
	Description     string
	Rules           []string
	Signature       []byte
}

// NewOperationalKey validates a public key and derives its protocol key ID.
func NewOperationalKey(publicKey ed25519.PublicKey, notBefore, notAfter uint64) (OperationalKey, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return OperationalKey{}, errors.New("invalid operational public key")
	}
	if notBefore > notAfter {
		return OperationalKey{}, errors.New("operational key interval is invalid")
	}
	digest := sha256.Sum256(publicKey)
	return OperationalKey{KeyID: digest[:16], PublicKey: append(ed25519.PublicKey(nil), publicKey...), NotBefore: notBefore, NotAfter: notAfter}, nil
}

// NewDocument constructs an unsigned instance document and derives its instance ID.
func NewDocument(rootPublicKey ed25519.PublicKey, operationalKeys []OperationalKey, domain string, administrator []byte) (Document, error) {
	if len(rootPublicKey) != ed25519.PublicKeySize {
		return Document{}, errors.New("invalid root public key")
	}
	if len(operationalKeys) == 0 {
		return Document{}, errors.New("instance document requires an operational key")
	}
	if len(administrator) != identifiers.LongLength {
		return Document{}, fmt.Errorf("administrator has %d bytes, want %d", len(administrator), identifiers.LongLength)
	}
	canonicalDomain, err := CanonicalHostname(domain)
	if err != nil {
		return Document{}, err
	}
	domain = canonicalDomain
	instanceID, err := identifiers.DeriveInstanceID(rootPublicKey)
	if err != nil {
		return Document{}, err
	}
	return Document{
		ProtocolVersion: ProtocolVersion,
		InstanceID:      instanceID,
		RootPublicKey:   append(ed25519.PublicKey(nil), rootPublicKey...),
		OperationalKeys: append([]OperationalKey(nil), operationalKeys...),
		Domain:          domain,
		Administrator:   append([]byte(nil), administrator...),
	}, nil
}

// CanonicalHostname converts a hostname to its protocol A-label form.
func CanonicalHostname(hostname string) (string, error) {
	if hostname == "" || strings.ContainsAny(hostname, "/\\:@?#") || strings.Contains(hostname, "://") {
		return "", errors.New("hostname must be a name without scheme, port, or path")
	}
	hostname = strings.ToLower(hostname)
	if strings.HasSuffix(hostname, ".") {
		hostname = strings.TrimSuffix(hostname, ".")
	}
	if hostname == "" {
		return "", errors.New("hostname is empty")
	}
	canonical, err := idna.ToASCII(hostname)
	if err != nil {
		return "", fmt.Errorf("canonicalize hostname: %w", err)
	}
	return canonical, nil
}

// Sign signs the document with the instance root key.
func (d *Document) Sign(rootPrivateKey ed25519.PrivateKey) error {
	if err := d.Validate(); err != nil {
		return err
	}
	signature, err := signatures.Sign(rootPrivateKey, DocumentDomain, d.unsigned())
	if err != nil {
		return err
	}
	d.Signature = signature
	return nil
}

// Verify checks the document signature and that its instance ID matches the root key.
func (d Document) Verify() error {
	if err := d.Validate(); err != nil {
		return err
	}
	if len(d.Signature) != ed25519.SignatureSize {
		return signatures.ErrInvalidSignature
	}
	return signatures.Verify(d.RootPublicKey, DocumentDomain, d.unsigned(), d.Signature)
}

// Validate checks document structure without checking its signature.
func (d Document) Validate() error {
	if d.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %q", d.ProtocolVersion)
	}
	if len(d.RootPublicKey) != ed25519.PublicKeySize || len(d.InstanceID) != identifiers.LongLength {
		return errors.New("invalid instance identity fields")
	}
	derived, err := identifiers.DeriveInstanceID(d.RootPublicKey)
	if err != nil || string(derived) != string(d.InstanceID) {
		return errors.New("instance ID does not match root public key")
	}
	if len(d.OperationalKeys) == 0 || len(d.Administrator) != identifiers.LongLength {
		return errors.New("invalid instance document fields")
	}
	canonicalDomain, err := CanonicalHostname(d.Domain)
	if err != nil || canonicalDomain != d.Domain {
		return errors.New("instance domain is not canonical")
	}
	for _, key := range d.OperationalKeys {
		if len(key.KeyID) != identifiers.ShortLength || len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore > key.NotAfter {
			return errors.New("invalid operational key")
		}
		derivedKey := sha256.Sum256(key.PublicKey)
		if string(key.KeyID) != string(derivedKey[:16]) {
			return errors.New("operational key ID does not match public key")
		}
	}
	return nil
}

// OperationalKey returns the listed operational key with the given key ID.
func (d Document) OperationalKey(keyID []byte) (OperationalKey, bool) {
	for _, key := range d.OperationalKeys {
		if string(key.KeyID) == string(keyID) {
			return key, true
		}
	}
	return OperationalKey{}, false
}

func (d Document) unsigned() map[uint64]any {
	value := map[uint64]any{0: d.ProtocolVersion, 1: d.InstanceID, 2: d.RootPublicKey, 3: operationalKeys(d.OperationalKeys), 4: d.Domain, 5: d.Administrator}
	if d.Description != "" {
		value[6] = d.Description
	}
	if d.Rules != nil {
		value[7] = d.Rules
	}
	return value
}

// Wire returns the complete signed document map, including its signature.
func (d Document) Wire() map[uint64]any {
	value := d.unsigned()
	value[8] = d.Signature
	return value
}

// Encode returns the deterministic CBOR of the complete document.
func (d Document) Encode() ([]byte, error) {
	if err := d.Verify(); err != nil {
		return nil, err
	}
	return encoding.Encode(d.Wire())
}

// Parse decodes and validates a wire document.
func Parse(value any) (Document, error) {
	fields, err := asFieldMap(value)
	if err != nil {
		return Document{}, errors.New("instance document must be a map")
	}
	protocolVersion, ok := fields[0].(string)
	if !ok {
		return Document{}, errors.New("instance document field 0 must be text")
	}
	instanceID, err := fieldBytes(fields, 1)
	if err != nil {
		return Document{}, err
	}
	rootPublicKey, err := fieldBytes(fields, 2)
	if err != nil {
		return Document{}, err
	}
	keysValue, ok := fields[3].([]any)
	if !ok {
		return Document{}, errors.New("instance document field 3 must be an array")
	}
	keys := make([]OperationalKey, len(keysValue))
	for i, item := range keysValue {
		key, err := parseOperationalKey(item)
		if err != nil {
			return Document{}, fmt.Errorf("operational key %d: %w", i, err)
		}
		keys[i] = key
	}
	domain, ok := fields[4].(string)
	if !ok {
		return Document{}, errors.New("instance document field 4 must be text")
	}
	administrator, err := fieldBytes(fields, 5)
	if err != nil {
		return Document{}, err
	}
	document := Document{
		ProtocolVersion: protocolVersion,
		InstanceID:      instanceID,
		RootPublicKey:   ed25519.PublicKey(rootPublicKey),
		OperationalKeys: keys,
		Domain:          domain,
		Administrator:   administrator,
	}
	if description, ok := fields[6]; ok {
		text, ok := description.(string)
		if !ok {
			return Document{}, errors.New("instance document field 6 must be text")
		}
		document.Description = text
	}
	if rulesValue, ok := fields[7]; ok {
		rules, ok := rulesValue.([]any)
		if !ok {
			return Document{}, errors.New("instance document field 7 must be an array")
		}
		document.Rules = make([]string, len(rules))
		for i, rule := range rules {
			text, ok := rule.(string)
			if !ok {
				return Document{}, errors.New("instance document field 7 must contain text")
			}
			document.Rules[i] = text
		}
	}
	signature, err := fieldBytes(fields, 8)
	if err != nil {
		return Document{}, err
	}
	document.Signature = signature
	if err := document.Verify(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func parseOperationalKey(value any) (OperationalKey, error) {
	fields, err := asFieldMap(value)
	if err != nil {
		return OperationalKey{}, errors.New("operational key must be a map")
	}
	keyID, err := fieldBytes(fields, 0)
	if err != nil {
		return OperationalKey{}, err
	}
	publicKey, err := fieldBytes(fields, 1)
	if err != nil {
		return OperationalKey{}, err
	}
	notBefore, err := fieldUint(fields, 2)
	if err != nil {
		return OperationalKey{}, err
	}
	notAfter, err := fieldUint(fields, 3)
	if err != nil {
		return OperationalKey{}, err
	}
	key := OperationalKey{KeyID: keyID, PublicKey: ed25519.PublicKey(publicKey), NotBefore: notBefore, NotAfter: notAfter}
	if len(key.KeyID) != identifiers.ShortLength || len(key.PublicKey) != ed25519.PublicKeySize {
		return OperationalKey{}, errors.New("operational key has invalid lengths")
	}
	return key, nil
}

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

func fieldBytes(fields map[uint64]any, key uint64) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("instance document field %d is missing", key)
	}
	switch buffer := value.(type) {
	case []byte:
		return buffer, nil
	case ed25519.PublicKey:
		return []byte(buffer), nil
	default:
		return nil, fmt.Errorf("instance document field %d is not bytes", key)
	}
}

func fieldUint(fields map[uint64]any, key uint64) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("instance document field %d is missing", key)
	}
	number, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("instance document field %d is not an unsigned integer", key)
	}
	return number, nil
}

func operationalKeys(keys []OperationalKey) []any {
	value := make([]any, len(keys))
	for i, key := range keys {
		value[i] = map[uint64]any{0: key.KeyID, 1: key.PublicKey, 2: key.NotBefore, 3: key.NotAfter}
	}
	return value
}
