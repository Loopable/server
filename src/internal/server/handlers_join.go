package server

import (
	"bytes"
	"errors"
	"net/http"

	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
)

// handleDeviceJoinRequests accepts a new device's self-asserted public keys
// for a hosted account (60.10), storing the request as pending.
func (s *Server) handleDeviceJoinRequests(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "device-join", func() {
		requestID := requestContextID(r)

		// This endpoint is public (the device is not yet authorized), so the
		// body is not buffered by the authentication middleware.
		body, err := s.readBody(r)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		var request map[uint64]any
		if err := s.decodeRequest(body, &request); err != nil {
			writeError(w, err, requestID)
			return
		}
		if err := validateJoinRequest(request); err != nil {
			writeError(w, err, requestID)
			return
		}
		accountID := request[0].([]byte)

		// The endpoint is self-asserted (the device is not yet authorized), so
		// the receiving instance must verify it hosts the account (60.10).
		stored, err := s.cfg.Events.EventsForAccount(r.Context(), accountID)
		if err != nil {
			writeError(w, mapStoreNotFound(err, requestID), requestID)
			return
		}
		if len(stored) == 0 {
			writeError(w, asInvalidRequest(errors.New("account is not hosted here")), requestID)
			return
		}

		wire, err := encoding.Encode(request)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		requestIDBytes, err := identifiers.Random(identifiers.VersionID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		if _, err := s.cfg.Blobs.PutObject(r.Context(), accountID, requestIDBytes, bytes.NewReader(wire), int64(len(wire))); err != nil {
			writeError(w, err, requestID)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
}

// validateJoinRequest enforces the device_join_request structure of 60.10.
func validateJoinRequest(fields map[uint64]any) error {
	lengths := []struct {
		key      uint64
		expected int
	}{
		{0, identifiers.LongLength},
		{1, identifiers.ShortLength},
		{2, 32},
		{3, 32},
	}
	for _, spec := range lengths {
		value, ok := fields[spec.key].([]byte)
		if !ok || len(value) != spec.expected {
			return asInvalidRequest(errors.New("device join request has invalid identifier lengths"))
		}
	}
	kind, ok := fields[4].(uint64)
	if !ok || kind > accounts.DeviceKindService {
		return asInvalidRequest(errors.New("device kind is invalid"))
	}
	if displayName, ok := fields[5]; ok {
		text, ok := displayName.(string)
		if !ok || len(text) > 100 {
			return asInvalidRequest(errors.New("display name is invalid"))
		}
	}
	return nil
}
