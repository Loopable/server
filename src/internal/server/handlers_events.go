package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"loopable.party/server/internal/protocol/authorization"
	protoerrors "loopable.party/server/internal/protocol/errors"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
	storepkg "loopable.party/server/internal/store"
)

// membershipFunc returns the membership predicate bound to this server's
// repository. Membership is a property of the group's event DAG (42.1); the
// resolver is injected so tests can substitute their own derivation.
func (s *Server) membershipFunc(ctx context.Context) authorization.MemberFunc {
	return func(groupID, accountID []byte) (bool, error) {
		return s.cfg.Membership.MemberOf(ctx, groupID, accountID)
	}
}

// missingDependency carries the predecessor IDs absent from the repository,
// mapped to E_MISSING_DEPENDENCY with the missing IDs in its details.
type missingDependency struct{ ids [][]byte }

func (m missingDependency) Error() string { return "event dependencies are missing" }

// loadClosure loads every transitive predecessor of event into a known map
// for dag.Validate and authorization.Validate.
func (s *Server) loadClosure(ctx context.Context, event events.Event) (map[string]events.Event, error) {
	known := make(map[string]events.Event)
	var missing [][]byte
	var load func(id []byte)
	load = func(id []byte) {
		key := string(id)
		if _, ok := known[key]; ok {
			return
		}
		predecessor, err := s.cfg.Events.GetEvent(ctx, id)
		if err != nil {
			if errors.Is(err, ErrEventNotFound) || errors.Is(err, storepkg.ErrEventNotFound) {
				missing = append(missing, append([]byte(nil), id...))
				return
			}
			panic(err)
		}
		known[key] = predecessor
		for _, parentID := range predecessor.Predecessors {
			load(parentID)
		}
	}
	for _, predecessorID := range event.Predecessors {
		load(predecessorID)
	}
	if len(missing) != 0 {
		return nil, missingDependency{ids: missing}
	}
	return known, nil
}

// acceptEvent validates an event's DAG, authorization, and membership, then
// stores it immutably. Duplicate and collision classification happens in
// submitEvent before acceptance; acceptEvent is the happy path (60.4).
func (s *Server) acceptEvent(ctx context.Context, event events.Event) (uint64, error) {
	known, err := s.loadClosure(ctx, event)
	if err != nil {
		return 0, err
	}
	if err := authorization.Validate(event, known, s.membershipFunc(ctx)); err != nil {
		return 0, err
	}
	return s.cfg.Events.PutEvent(ctx, event)
}

// handlePostEvents submits a CBOR array of events, validating each
// independently (60.4). The response mirrors the request: one result record
// per submitted event.
func (s *Server) handlePostEvents(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "events", func() {
		requestID := requestContextID(r)

		body := requestBody(r)
		var raw []any
		if err := s.decodeRequest(body, &raw); err != nil {
			writeError(w, err, requestID)
			return
		}
		if len(raw) == 0 || len(raw) > maxEventsPerPost {
			writeError(w, asInvalidRequest(errors.New("batch has no events or exceeds the limit")), requestID)
			return
		}

		results := make([]any, 0, len(raw))
		for _, item := range raw {
			results = append(results, s.acceptEventBatch(r, item))
		}
		_ = s.writeCBOR(w, http.StatusOK, results)
	})
}

// acceptEventBatch resolves one submitted event into its result record.
func (s *Server) acceptEventBatch(r *http.Request, item any) map[uint64]any {
	requestID := requestContextID(r)
	eventID, err := firstFieldBytes(item)
	if err != nil {
		return submitResult(nil, 2, mapError(asInvalidRequest(err), requestID))
	}
	event, err := events.Parse(item)
	if err != nil {
		return submitResult(eventID, 2, mapError(asInvalidRequest(err), requestID))
	}
	_, err = s.submitEvent(r.Context(), event)
	switch {
	case err == nil:
		return submitResult(eventID, 0, nil)
	case errors.Is(err, ErrEventCollision):
		return submitResult(eventID, 1, nil)
	default:
		return submitResult(eventID, 2, mapError(err, requestID))
	}
}

// submitEvent classifies an event submission per 60.4. An already-committed
// event whose bytes match is a duplicate; the same event ID with different
// bytes is a collision (E_EVENT_ID_COLLISION); otherwise the event is accepted
// through acceptEvent.
func (s *Server) submitEvent(ctx context.Context, event events.Event) (uint64, error) {
	existing, err := s.cfg.Events.GetEvent(ctx, event.EventID)
	if err == nil {
		if sameEventBytes(existing, event) {
			return 0, ErrEventCollision
		}
		return 0, ErrEventIDCollision
	}
	if !errors.Is(err, ErrEventNotFound) {
		return 0, err
	}
	return s.acceptEvent(ctx, event)
}

// sameEventBytes reports whether two events encode to identical canonical
// bytes.
func sameEventBytes(left, right events.Event) bool {
	leftEncoded, err := left.CanonicalBytes()
	if err != nil {
		return false
	}
	rightEncoded, err := right.CanonicalBytes()
	if err != nil {
		return false
	}
	return bytes.Equal(leftEncoded, rightEncoded)
}

func submitResult(id []byte, status uint64, protocolErr *protoerrors.Error) map[uint64]any {
	result := map[uint64]any{0: id, 1: status}
	if protocolErr != nil {
		result[2] = protocolErr.Wire()
	}
	return result
}

// handleGetEvent serves one event's canonical bytes (60.6).
func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "events", func() {
		requestID := requestContextID(r)
		eventID, err := s.parsePathID(identifiers.EventID, r.PathValue("event_id"))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		event, err := s.cfg.Events.GetEvent(r.Context(), eventID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		wire, err := event.CanonicalBytes()
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		s.writeBytesCBOR(w, http.StatusOK, wire)
	})
}

// handleFetchEvents fetches a batch of events by ID, including their stored
// dependency closure (60.6, 63.2). Each requested event yields exactly one
// result record; additional dependency events may follow.
func (s *Server) handleFetchEvents(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "fetch", func() {
		requestID := requestContextID(r)
		body := requestBody(r)
		var rawRequest any
		if err := s.decodeRequest(body, &rawRequest); err != nil {
			writeError(w, err, requestID)
			return
		}
		request, err := asUintMap(rawRequest)
		if err != nil {
			writeError(w, asInvalidRequest(err), requestID)
			return
		}
		eventIDs, err := fieldUintKeyBytes(request, 0)
		if err != nil || len(eventIDs) == 0 || len(eventIDs) > maxEventFetch {
			writeError(w, asInvalidRequest(errors.New("invalid event_ids list")), requestID)
			return
		}

		records := make([]any, 0, len(eventIDs))
		seen := make(map[string]bool)
		var appendRecord func(id []byte)
		appendRecord = func(id []byte) {
			key := string(id)
			if seen[key] {
				return
			}
			seen[key] = true
			event, err := s.cfg.Events.GetEvent(r.Context(), id)
			if err != nil {
				if errors.Is(err, ErrEventNotFound) || errors.Is(err, storepkg.ErrEventNotFound) {
					records = append(records, map[uint64]any{0: id, 2: mapError(ErrEventNotFound, requestID).Wire()})
				} else {
					records = append(records, map[uint64]any{0: id, 2: mapError(err, requestID).Wire()})
				}
				return
			}
			wire, err := event.CanonicalBytes()
			if err != nil {
				records = append(records, map[uint64]any{0: id, 2: mapError(err, requestID).Wire()})
				return
			}
			records = append(records, map[uint64]any{0: id, 1: wire})
			for _, parentID := range event.Predecessors {
				appendRecord(parentID)
			}
		}
		for _, eventID := range eventIDs {
			appendRecord(eventID)
		}
		_ = s.writeCBOR(w, http.StatusOK, records)
	})
}
