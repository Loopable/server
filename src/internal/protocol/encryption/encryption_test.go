package encryption

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	metadata := SecurityMetadata{ObjectID: bytes.Repeat([]byte{1}, 32), ObjectType: 1, VersionID: bytes.Repeat([]byte{2}, 32)}
	nonce, ciphertext, err := Encrypt(key, []byte("canonical payload"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != NonceSize || len(ciphertext) != len("canonical payload")+TagSize {
		t.Fatalf("unexpected encrypted sizes: nonce=%d ciphertext=%d", len(nonce), len(ciphertext))
	}
	plaintext, err := Decrypt(key, nonce, ciphertext, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "canonical payload" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestRejectsTamperedCiphertextAndMetadata(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	metadata := SecurityMetadata{ObjectID: bytes.Repeat([]byte{3}, 32), ObjectType: 1, VersionID: bytes.Repeat([]byte{4}, 32)}
	nonce, ciphertext, err := Encrypt(key, []byte("secret"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	if plaintext, err := Decrypt(key, nonce, ciphertext, metadata); err == nil || plaintext != nil {
		t.Fatalf("tampered ciphertext result = %q, error = %v", plaintext, err)
	}
	nonce, ciphertext, err = Encrypt(key, []byte("secret"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.ObjectType = 2
	if plaintext, err := Decrypt(key, nonce, ciphertext, metadata); err == nil || plaintext != nil {
		t.Fatalf("tampered metadata result = %q, error = %v", plaintext, err)
	}
}
