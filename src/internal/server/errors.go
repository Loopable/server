package server

import (
	"errors"
	"net/http"
	"strconv"

	"loopable.party/server/internal/objectstore"
	"loopable.party/server/internal/protocol/authorization"
	"loopable.party/server/internal/protocol/dag"
	protoerrors "loopable.party/server/internal/protocol/errors"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/federation"
	storepkg "loopable.party/server/internal/store"
)

// authInvalid marks a failed authentication/authorization bound to E_AUTH_INVALID.
type authInvalid struct{ err error }

func (a authInvalid) Error() string { return a.err.Error() }
func (a authInvalid) Unwrap() error { return a.err }

// Sentinel data-layer errors used by in-memory and persistent repositories.
var (
	ErrEventNotFound       = errors.New("event not found")
	ErrEventCollision      = errors.New("event ID already associated with identical bytes")
	ErrEventIDCollision    = errors.New("event ID already associated with different bytes")
	ErrObjectNotFound      = errors.New("object not found")
	ErrObjectCollision     = errors.New("object ID already associated with different bytes")
	ErrEmptyCursor         = errors.New("sync cursor is empty")
	ErrInvalidCursor       = errors.New("sync cursor is invalid")
	ErrUnknownPeerInstance = errors.New("peer instance is unknown")
	errObjectNotAuthorized = errors.New("object is not available to this requester")
)

// malformedEncoding marks a request CBOR decoding failure for E_MALFORMED_ENCODING.
type malformedEncoding struct{ err error }

func (m malformedEncoding) Error() string { return m.err.Error() }
func (m malformedEncoding) Unwrap() error { return m.err }

func formatUint(value uint64) string { return strconv.FormatUint(value, 10) }

func formatInt(value int) string { return strconv.Itoa(value) }

// invalidRequest marks a well-formed but invalid submission for E_BAD_REQUEST.
type invalidRequest struct{ err error }

func (i invalidRequest) Error() string { return i.err.Error() }
func (i invalidRequest) Unwrap() error { return i.err }

func asInvalidRequest(err error) error { return invalidRequest{err: err} }

// mapError converts an application error into its protocol error object.
func mapError(err error, requestID []byte) *protoerrors.Error {
	var protocolErr *protoerrors.Error
	if errors.As(err, &protocolErr) {
		return protocolErr
	}
	code, details := "E_INTERNAL", (map[uint64]any)(nil)
	switch {
	case errors.Is(err, ErrEventNotFound), errors.Is(err, ErrObjectNotFound),
		errors.Is(err, storepkg.ErrEventNotFound), errors.Is(err, storepkg.ErrObjectNotFound),
		errors.Is(err, objectstore.ErrObjectNotFound), errors.Is(err, objectstore.ErrUploadNotFound):
		code = "E_NOT_FOUND"
	case errors.Is(err, ErrEventCollision), errors.Is(err, ErrEventIDCollision), errors.Is(err, storepkg.ErrEventIDCollision):
		code = "E_EVENT_ID_COLLISION"
	case errors.Is(err, ErrObjectCollision):
		code = "E_BAD_REQUEST"
	case errors.Is(err, errObjectNotAuthorized):
		code = "E_OBJECT_NOT_AUTHORIZED"
	case errors.Is(err, dag.ErrCycle):
		code = "E_DAG_CYCLE"
	case errors.Is(err, dag.ErrUnrooted):
		code = "E_DAG_UNROOTED"
	case errors.Is(err, dag.ErrMissing):
		code = "E_MISSING_DEPENDENCY"
	case errors.Is(err, authorization.ErrTrustConflict):
		code = "E_TRUST_CONFLICT"
	case errors.Is(err, authorization.ErrSignatureInvalid):
		code = "E_SIGNATURE_INVALID"
	case errors.Is(err, authorization.ErrUnauthorizedDevice):
		code = "E_UNAUTHORIZED_DEVICE"
	case errors.Is(err, authorization.ErrFirstDeviceInvalid):
		code = "E_FIRST_DEVICE_INVALID"
	case errors.Is(err, authorization.ErrSchemaInvalid):
		code = "E_BAD_REQUEST"
	case errors.Is(err, authorization.ErrMemberRequired):
		code = "E_MEMBER_REQUIRED"
	case errors.Is(err, events.ErrUnknownType):
		code = "E_BAD_REQUEST"
	case errors.Is(err, ErrEmptyCursor), errors.Is(err, ErrInvalidCursor):
		code = "E_BAD_REQUEST"
	case errors.Is(err, federation.ErrReplay):
		code = "E_REPLAY"
	case errors.Is(err, objectstore.ErrUploadComplete):
		code = "E_BAD_REQUEST"
	case errors.Is(err, objectstore.ErrInvalidLength), errors.Is(err, objectstore.ErrIncompleteStream):
		code = "E_BAD_REQUEST"
	case errors.Is(err, objectstore.ErrUploadTooLarge):
		code = "E_RATE_LIMITED"
	}
	var malformed malformedEncoding
	if errors.As(err, &malformed) {
		code = "E_MALFORMED_ENCODING"
	}
	var invalid invalidRequest
	if errors.As(err, &invalid) {
		code = "E_BAD_REQUEST"
	}
	var invalidAuth authInvalid
	if errors.As(err, &invalidAuth) {
		code = "E_AUTH_INVALID"
	}
	protocolErr, newErr := protoerrors.New(code, requestID, details, err)
	if newErr != nil {
		protocolErr, _ = protoerrors.New("E_INTERNAL", requestID, nil, err)
	}
	return protocolErr
}

// fail writes a protocol error object for an explicit registry code.
func fail(w http.ResponseWriter, code string, requestID []byte, details map[uint64]any, cause error) {
	protocolErr, err := protoerrors.New(code, requestID, details, cause)
	if err != nil {
		protocolErr, _ = protoerrors.New("E_INTERNAL", requestID, nil, cause)
	}
	if protocolErr.Code == "E_RATE_LIMITED" {
		if retry, ok := protocolErr.Details[0].(uint64); ok {
			w.Header().Set("Retry-After", formatUint(retry))
		}
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(protocolErr.Status)
	body, err := protocolErr.Encode()
	if err == nil {
		_, _ = w.Write(body)
	}
}

// writeError maps an application error to its protocol error response.
func writeError(w http.ResponseWriter, err error, requestID []byte) {
	protocolErr := mapError(err, requestID)
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(protocolErr.Status)
	body, err := protocolErr.Encode()
	if err == nil {
		_, _ = w.Write(body)
	}
}

// objectValidateError marks an envelope that failed structural validation.
func objectValidateError(err error) error { return asInvalidRequest(err) }
