package instance

import (
	"bytes"
	"testing"

	"loopable.party/server/internal/protocol/signatures"
)

func TestDocumentSignAndVerify(t *testing.T) {
	rootPublicKey, rootPrivateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	opPublicKey, _, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	opKey, err := NewOperationalKey(opPublicKey, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	document, err := NewDocument(rootPublicKey, []OperationalKey{opKey}, "example.test", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Sign(rootPrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := document.Verify(); err != nil {
		t.Fatal(err)
	}
	document.Domain = "other.test"
	if err := document.Verify(); err == nil {
		t.Fatal("Verify accepted a modified document")
	}
}

func TestCanonicalHostname(t *testing.T) {
	canonical, err := CanonicalHostname("Bücher.Example.")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "xn--bcher-kva.example" {
		t.Fatalf("canonical hostname = %q", canonical)
	}
	for _, hostname := range []string{"https://example.test", "example.test:443", "example.test/path", ""} {
		if _, err := CanonicalHostname(hostname); err == nil {
			t.Errorf("accepted invalid hostname %q", hostname)
		}
	}
}
