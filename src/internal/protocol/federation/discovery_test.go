package federation

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"loopable.party/server/internal/protocol/instance"
	"loopable.party/server/internal/protocol/signatures"
)

func TestVerifyInstanceRequest(t *testing.T) {
	rootPublic, rootPrivate, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalPublic, operationalPrivate, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalKey, err := instance.NewOperationalKey(operationalPublic, 0, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	document, err := instance.NewDocument(rootPublic, []instance.OperationalKey{operationalKey}, "peer.example", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_000, 0)
	request := RequestAuthentication{
		Method: "POST", Host: "peer.example", Path: "/v1/events",
		RequestID: bytes.Repeat([]byte{2}, 16), Timestamp: uint64(now.Unix()), BodyHash: HashBody([]byte("body")),
	}
	signature, err := SignRequest(operationalPrivate, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstanceRequest(document, operationalKey.KeyID, request, signature, now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	if err := VerifyInstanceRequest(document, bytes.Repeat([]byte{0xee}, 16), request, signature, now); err == nil {
		t.Fatal("unknown operational key accepted")
	}
	if err := VerifyInstanceRequest(document, operationalKey.KeyID, request, signature[:63], now); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestVerifyInstanceRequestRejectsExpiredKey(t *testing.T) {
	rootPublic, rootPrivate, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalPublic, operationalPrivate, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	expired, err := instance.NewOperationalKey(operationalPublic, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	document, err := instance.NewDocument(rootPublic, []instance.OperationalKey{expired}, "peer.example", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}
	request := RequestAuthentication{
		Method: "GET", Host: "peer.example", Path: "/v1/events",
		RequestID: bytes.Repeat([]byte{2}, 16), Timestamp: 200, BodyHash: HashBody(nil),
	}
	signature, err := SignRequest(operationalPrivate, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstanceRequest(document, expired.KeyID, request, signature, time.Unix(200, 0)); err == nil {
		t.Fatal("request signed after key expiry accepted")
	}
}

func TestDocumentCacheFetching(t *testing.T) {
	rootPublic, rootPrivate, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalPublic, _, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalKey, err := instance.NewOperationalKey(operationalPublic, 0, uint64(time.Now().Unix()+3_600))
	if err != nil {
		t.Fatal(err)
	}
	document, err := instance.NewDocument(rootPublic, []instance.OperationalKey{operationalKey}, "peer.example", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}

	fetches := 0
	cache := NewDocumentCache(func(_ []byte) (instance.Document, error) {
		fetches++
		return document, nil
	}, 24*time.Hour)

	instanceID := document.InstanceID
	first, err := cache.Document(instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 {
		t.Fatalf("first lookup performed %d fetches", fetches)
	}
	second, err := cache.Document(instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 {
		t.Fatalf("cached lookup performed %d fetches", fetches)
	}
	if !bytes.Equal(first.InstanceID, second.InstanceID) {
		t.Fatal("cached document changed")
	}
}

func TestDocumentCacheVerifiesAndRejectsWrongInstance(t *testing.T) {
	rootPublic, rootPrivate, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalPublic, _, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalKey, err := instance.NewOperationalKey(operationalPublic, 0, uint64(time.Now().Unix()+3_600))
	if err != nil {
		t.Fatal(err)
	}
	document, err := instance.NewDocument(rootPublic, []instance.OperationalKey{operationalKey}, "peer.example", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}
	instanceID := document.InstanceID

	wrongInstance := document
	wrongInstance.InstanceID = bytes.Repeat([]byte{0xaa}, 32)
	cache := NewDocumentCache(func(_ []byte) (instance.Document, error) { return wrongInstance, nil }, 24*time.Hour)
	if _, err := cache.Document(instanceID); err == nil {
		t.Fatal("document identifying a different instance accepted")
	}

	tampered := document
	tampered.Signature = bytes.Repeat([]byte{0xaa}, 64)
	cache = NewDocumentCache(func(_ []byte) (instance.Document, error) { return tampered, nil }, 24*time.Hour)
	if _, err := cache.Document(instanceID); err == nil {
		t.Fatal("document with invalid signature accepted")
	}

	failing := NewDocumentCache(func(_ []byte) (instance.Document, error) {
		return instance.Document{}, errors.New("peer unreachable")
	}, 24*time.Hour)
	if _, err := failing.Document(instanceID); err == nil {
		t.Fatal("fetch error swallowed")
	}
}

func TestDocumentCacheRefetchesAfterForget(t *testing.T) {
	rootPublic, rootPrivate, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalPublic, _, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	operationalKey, err := instance.NewOperationalKey(operationalPublic, 0, uint64(time.Now().Unix()+3_600))
	if err != nil {
		t.Fatal(err)
	}
	document, err := instance.NewDocument(rootPublic, []instance.OperationalKey{operationalKey}, "peer.example", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}
	instanceID := document.InstanceID

	fetches := 0
	cache := NewDocumentCache(func(_ []byte) (instance.Document, error) {
		fetches++
		return document, nil
	}, 24*time.Hour)
	if _, err := cache.Document(instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Document(instanceID); err != nil {
		t.Fatal(err)
	}
	if fetches != 1 {
		t.Fatalf("expected one fetch before forget, got %d", fetches)
	}
	cache.Forget(instanceID)
	if _, err := cache.Document(instanceID); err != nil {
		t.Fatal(err)
	}
	if fetches != 2 {
		t.Fatalf("expected refetch after forget, got %d", fetches)
	}
}
