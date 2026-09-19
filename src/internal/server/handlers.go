package server

import (
	"encoding/base32"
	"net/http"

	"loopable.party/server/internal/protocol/capabilities"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
)

const base32lower = "abcdefghijklmnopqrstuvwxyz234567"

var base32Encoding = base32.NewEncoding(base32lower).WithPadding(base32.NoPadding)

// writeCBOR encodes value as canonical CBOR and writes it with status.
func (s *Server) writeCBOR(w http.ResponseWriter, status int, value any) error {
	body, err := encoding.Encode(value)
	if err != nil {
		abort(w, err)
		return err
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Content-Length", formatInt(len(body)))
	w.WriteHeader(status)
	_, err = w.Write(body)
	return err
}

// writeBytesCBOR writes pre-encoded CBOR bytes.
func (s *Server) writeBytesCBOR(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Content-Length", formatInt(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// parsePathID parses a base32lower path segment into identifier bytes of the
// expected kind, per 10-identifiers.md.
func (s *Server) parsePathID(kind identifiers.Type, segment string) ([]byte, error) {
	id, err := identifiers.Parse(kind, segment)
	if err != nil {
		return nil, asInvalidRequest(err)
	}
	return id, nil
}

// handleInstance serves this instance's signed document (60.3, 13.3.1).
func (s *Server) handleInstance(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "lookup", func() {
		body, err := s.cfg.Document.Encode()
		if err != nil {
			writeError(w, err, nil)
			return
		}
		s.writeBytesCBOR(w, http.StatusOK, body)
	})
}

// handleRoles serves the instance staff roles (13.10.4).
func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "lookup", func() {
		moderators := make([]any, 0, len(s.cfg.Moderators))
		for _, moderator := range s.cfg.Moderators {
			moderators = append(moderators, moderator)
		}
		s.writeCBOR(w, http.StatusOK, map[uint64]any{0: s.cfg.Document.Administrator, 1: moderators})
	})
}

// handleCapabilities serves the capability list (81.4).
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "lookup", func() {
		list := make([]any, len(capabilities.Registered))
		for i, capability := range capabilities.Registered {
			list[i] = capability.Wire()
		}
		s.writeCBOR(w, http.StatusOK, list)
	})
}

// handleHealth serves a lightweight operator liveness check outside the
// protocol wire. It never reveals account or event data.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeCBOR(w, http.StatusOK, map[uint64]any{0: "ok", 1: s.cfg.Document.InstanceID})
}

// abort converts a response-building error into an error response.
func abort(w http.ResponseWriter, err error) {
	writeError(w, err, nil)
}
