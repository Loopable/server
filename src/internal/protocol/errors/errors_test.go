package errors

import (
	"errors"
	"testing"
)

func TestRegistryAndSafeWire(t *testing.T) {
	definition, ok := Lookup("E_SIGNATURE_INVALID")
	if !ok || definition.Status != 401 || definition.Retryable {
		t.Fatalf("unexpected definition: %+v", definition)
	}
	cause := errors.New("database password must not escape")
	requestID := make([]byte, 16)
	protocolError, err := New("E_INTERNAL", requestID, map[uint64]any{0: "safe"}, cause)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := protocolError.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || protocolError.Error() != "E_INTERNAL" {
		t.Fatal("error did not encode safely")
	}
	if !errors.Is(protocolError, cause) {
		t.Fatal("internal cause was not retained")
	}
}

func TestRejectsUnknownCodesAndBadRequestIDs(t *testing.T) {
	if _, err := New("E_UNKNOWN", nil, nil, nil); err == nil {
		t.Fatal("accepted unknown error code")
	}
	if _, err := New("E_BAD_REQUEST", []byte{1}, nil, nil); err == nil {
		t.Fatal("accepted malformed request ID")
	}
}
