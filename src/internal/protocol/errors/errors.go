// Package errors implements Loopable's registered protocol error objects.
//
// The registry and wire shape correspond to protospec/spec/80-errors.md.
package errors

import (
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
)

type Definition struct {
	Code      string
	Status    int
	Retryable bool
	Message   string
}

var registry = map[string]Definition{
	"E_MALFORMED_ENCODING":     {"E_MALFORMED_ENCODING", 400, false, "The request encoding is invalid."},
	"E_BAD_REQUEST":            {"E_BAD_REQUEST", 400, false, "The request is invalid."},
	"E_EVENT_ID_COLLISION":     {"E_EVENT_ID_COLLISION", 400, false, "The event ID is already associated with different bytes."},
	"E_DECRYPTION_FAILED":      {"E_DECRYPTION_FAILED", 400, false, "The encrypted data could not be authenticated."},
	"E_SIGNATURE_INVALID":      {"E_SIGNATURE_INVALID", 401, false, "The signature is invalid."},
	"E_AUTH_MALFORMED":         {"E_AUTH_MALFORMED", 401, false, "The authentication credentials are malformed."},
	"E_AUTH_INVALID":           {"E_AUTH_INVALID", 401, false, "The authentication identity is not established."},
	"E_REPLAY":                 {"E_REPLAY", 401, false, "The request has already been used."},
	"E_TIMESTAMP_OUT_OF_RANGE": {"E_TIMESTAMP_OUT_OF_RANGE", 401, false, "The request timestamp is outside the accepted window."},
	"E_UNAUTHORIZED_INSTANCE":  {"E_UNAUTHORIZED_INSTANCE", 403, false, "The instance is not authorized."},
	"E_UNAUTHORIZED_DEVICE":    {"E_UNAUTHORIZED_DEVICE", 403, false, "The device is not authorized."},
	"E_FIRST_DEVICE_INVALID":   {"E_FIRST_DEVICE_INVALID", 422, false, "The first-device authorization is invalid."},
	"E_MEMBER_REQUIRED":        {"E_MEMBER_REQUIRED", 403, false, "Membership is required."},
	"E_BANNED":                 {"E_BANNED", 403, false, "The account is banned."},
	"E_SUSPENDED":              {"E_SUSPENDED", 403, false, "The account is suspended."},
	"E_OBJECT_NOT_AUTHORIZED":  {"E_OBJECT_NOT_AUTHORIZED", 403, false, "The object is not available to this requester."},
	"E_NOT_FOUND":              {"E_NOT_FOUND", 404, false, "The requested resource was not found."},
	"E_USERNAME_UNAVAILABLE":   {"E_USERNAME_UNAVAILABLE", 409, false, "The username is unavailable."},
	"E_DAG_CYCLE":              {"E_DAG_CYCLE", 422, false, "The event dependency graph contains a cycle."},
	"E_DAG_UNROOTED":           {"E_DAG_UNROOTED", 422, false, "The event is not connected to its account root."},
	"E_MISSING_DEPENDENCY":     {"E_MISSING_DEPENDENCY", 422, false, "An event dependency is missing."},
	"E_TRUST_CONFLICT":         {"E_TRUST_CONFLICT", 422, false, "The trusted-device state is ambiguous."},
	"E_MANDATORY_UNKNOWN":      {"E_MANDATORY_UNKNOWN", 422, false, "A mandatory protocol value is unknown."},
	"E_UNSUPPORTED_VERSION":    {"E_UNSUPPORTED_VERSION", 426, false, "The protocol version is unsupported."},
	"E_UNSUPPORTED_CAPABILITY": {"E_UNSUPPORTED_CAPABILITY", 426, false, "A mandatory capability is unsupported."},
	"E_RATE_LIMITED":           {"E_RATE_LIMITED", 429, false, "Too many requests."},
	"E_INTERNAL":               {"E_INTERNAL", 500, true, "An internal error occurred."},
}

// Error is a safe protocol error. Cause is never serialized or exposed on the wire.
type Error struct {
	Definition
	RequestID []byte
	Details   map[uint64]any
	Cause     error
}

func New(code string, requestID []byte, details map[uint64]any, cause error) (*Error, error) {
	definition, ok := registry[code]
	if !ok {
		return nil, fmt.Errorf("unknown protocol error code %q", code)
	}
	if requestID != nil && len(requestID) != identifiers.ShortLength {
		return nil, fmt.Errorf("request ID has %d bytes, want %d", len(requestID), identifiers.ShortLength)
	}
	return &Error{Definition: definition, RequestID: append([]byte(nil), requestID...), Details: details, Cause: cause}, nil
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code
}

func (e *Error) Unwrap() error { return e.Cause }

// Wire returns the safe CBOR map for an error response.
func (e *Error) Wire() map[uint64]any {
	value := map[uint64]any{0: e.Code, 1: e.Message, 3: e.Retryable}
	if e.RequestID != nil {
		value[2] = append([]byte(nil), e.RequestID...)
	}
	if e.Details != nil {
		value[4] = e.Details
	}
	return value
}

func (e *Error) Encode() ([]byte, error) {
	if e == nil {
		return nil, errors.New("nil protocol error")
	}
	return encoding.Encode(e.Wire())
}

func Lookup(code string) (Definition, bool) { definition, ok := registry[code]; return definition, ok }
