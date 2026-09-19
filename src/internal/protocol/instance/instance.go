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

func operationalKeys(keys []OperationalKey) []any {
	value := make([]any, len(keys))
	for i, key := range keys {
		value[i] = map[uint64]any{0: key.KeyID, 1: key.PublicKey, 2: key.NotBefore, 3: key.NotAfter}
	}
	return value
}
