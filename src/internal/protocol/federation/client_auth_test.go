package federation

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"loopable.party/server/internal/protocol/signatures"
)

func TestClientAuthorizationHeaderRoundTrip(t *testing.T) {
	authorization := Authorization{
		InstanceID: bytes.Repeat([]byte{1}, 32),
		KeyID:      bytes.Repeat([]byte{2}, 16),
		RequestID:  bytes.Repeat([]byte{3}, 16),
		Timestamp:  1000,
		AccountID:  bytes.Repeat([]byte{9}, 32),
		Signature:  bytes.Repeat([]byte{4}, 64),
	}
	header, err := authorization.HeaderValue()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthorization(header)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Timestamp != authorization.Timestamp || !bytes.Equal(parsed.AccountID, authorization.AccountID) {
		t.Fatal("client authorization header did not round-trip")
	}
	if _, err := ParseAuthorization(header + ";" + "acc=" + "AAAA"); err == nil {
		t.Fatal("accepted duplicate acc parameter")
	}
}

func TestClientAuthorizationWithoutAccount(t *testing.T) {
	header, err := Authorization{
		InstanceID: bytes.Repeat([]byte{1}, 32),
		KeyID:      bytes.Repeat([]byte{2}, 16),
		RequestID:  bytes.Repeat([]byte{3}, 16),
		Timestamp:  1000,
		Signature:  bytes.Repeat([]byte{4}, 64),
	}.HeaderValue()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthorization(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.AccountID) != 0 {
		t.Fatal("instance-level request unexpectedly carried an account ID")
	}
}

func TestClientRequestSigningBindsAccount(t *testing.T) {
	publicKey, privateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000, 0)
	request := RequestAuthentication{
		Method: "POST", Host: "home.example", Path: "/v1/events",
		RequestID: bytes.Repeat([]byte{3}, 16), Timestamp: uint64(now.Unix()),
		BodyHash: HashBody(nil), AccountID: bytes.Repeat([]byte{9}, 32),
	}
	signature, err := SignRequest(privateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(publicKey, request, signature, now); err != nil {
		t.Fatal(err)
	}
	request.AccountID = bytes.Repeat([]byte{8}, 32)
	if err := VerifyRequest(publicKey, request, signature, now); !errors.Is(err, signatures.ErrInvalidSignature) {
		t.Fatalf("account swap error = %v", err)
	}
}
