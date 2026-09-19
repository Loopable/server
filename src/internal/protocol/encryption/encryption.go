// Package encryption implements Loopable's AES-256-GCM object encryption.
//
// The construction corresponds to protospec/spec/23-encryption.md.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"loopable.party/server/internal/protocol/encoding"
)

const (
	ObjectDomain    = "loopable-object-v1\x00"
	ProtocolVersion = "0.1"
	KeySize         = 32
	NonceSize       = 12
	TagSize         = 16
)

// SecurityMetadata is the unencrypted object metadata authenticated by GCM.
type SecurityMetadata struct {
	ObjectID        []byte
	ObjectType      uint64
	EncryptionSuite uint64
	VersionID       []byte
}

func (m SecurityMetadata) unsigned() map[uint64]any {
	return map[uint64]any{0: ProtocolVersion, 1: m.ObjectID, 2: m.ObjectType, 3: m.EncryptionSuite, 4: m.VersionID}
}

func (m SecurityMetadata) AAD() ([]byte, error) {
	if len(m.ObjectID) != 32 || len(m.VersionID) != 32 {
		return nil, errors.New("object and version IDs must be 32 bytes")
	}
	encoded, err := encoding.Encode(m.unsigned())
	if err != nil {
		return nil, fmt.Errorf("encode object security metadata: %w", err)
	}
	aad := make([]byte, 0, len(ObjectDomain)+len(encoded))
	aad = append(aad, ObjectDomain...)
	aad = append(aad, encoded...)
	return aad, nil
}

// GenerateKey returns a fresh 256-bit content-encryption key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate AES-256 key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts canonical-CBOR plaintext with a fresh random nonce.
func Encrypt(key, plaintext []byte, metadata SecurityMetadata) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, errors.New("AES-256 key must be 32 bytes")
	}
	aad, err := metadata.AAD()
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate GCM nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt authenticates and decrypts ciphertext. It returns no plaintext on failure.
func Decrypt(key, nonce, ciphertext []byte, metadata SecurityMetadata) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("AES-256 key must be 32 bytes")
	}
	if len(nonce) != NonceSize || len(ciphertext) < TagSize {
		return nil, errors.New("invalid AES-GCM nonce or ciphertext")
	}
	aad, err := metadata.AAD()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("AES-GCM authentication failed")
	}
	return plaintext, nil
}
