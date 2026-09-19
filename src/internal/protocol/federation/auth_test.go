package federation

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"loopable.party/server/internal/protocol/signatures"
)

func TestRequestAuthentication(t *testing.T) {
	publicKey, privateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000, 0)
	request := RequestAuthentication{Method: "POST", Host: "peer.example", Path: "/v1/events", RequestID: bytes.Repeat([]byte{1}, 16), Timestamp: uint64(now.Unix()), BodyHash: HashBody([]byte("body"))}
	signature, err := SignRequest(privateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(publicKey, request, signature, now); err != nil {
		t.Fatal(err)
	}
	request.BodyHash = HashBody([]byte("changed"))
	if err := VerifyRequest(publicKey, request, signature, now); !errors.Is(err, signatures.ErrInvalidSignature) {
		t.Fatalf("changed body error = %v", err)
	}
}

func TestRequestFreshness(t *testing.T) {
	publicKey, privateKey, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	request := RequestAuthentication{Method: "GET", Host: "peer.example", Path: "/v1/events", RequestID: bytes.Repeat([]byte{2}, 16), Timestamp: 1_000, BodyHash: HashBody(nil)}
	signature, err := SignRequest(privateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(publicKey, request, signature, time.Unix(1_301, 0)); err == nil {
		t.Fatal("accepted stale request")
	}
}

func TestAuthorizationHeaderRoundTrip(t *testing.T) {
	authorization := Authorization{InstanceID: bytes.Repeat([]byte{1}, 32), KeyID: bytes.Repeat([]byte{2}, 16), RequestID: bytes.Repeat([]byte{3}, 16), Timestamp: 1000, Signature: bytes.Repeat([]byte{4}, 64)}
	header, err := authorization.HeaderValue()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthorization(header)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Timestamp != authorization.Timestamp || !bytes.Equal(parsed.InstanceID, authorization.InstanceID) || !bytes.Equal(parsed.Signature, authorization.Signature) {
		t.Fatal("authorization header did not round-trip")
	}
	if _, err := ParseAuthorization(header + ";key=" + "x"); err == nil {
		t.Fatal("accepted duplicate parameter")
	}
}
