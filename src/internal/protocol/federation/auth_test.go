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
