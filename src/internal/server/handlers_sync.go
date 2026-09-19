package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"

	protoerrors "loopable.party/server/internal/protocol/errors"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/objects"
	"loopable.party/server/internal/protocol/sync"
)

// cursor wire format is the opaque 8-byte big-endian publish sequence of 62.2.
func encodeCursor(seq uint64) []byte {
	cursor := make([]byte, 8)
	binary.BigEndian.PutUint64(cursor, seq)
	return cursor
}

func decodeCursor(cursor []byte) (uint64, error) {
	if len(cursor) == 0 {
		return 0, ErrEmptyCursor
	}
	if len(cursor) != 8 {
		return 0, ErrInvalidCursor
	}
	return binary.BigEndian.Uint64(cursor), nil
}

// handleSync opens or resumes a synchronization stream (62.2).
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "events", func() {
		requestID := requestContextID(r)

		request, err := sync.ParseRequest(requestBody(r))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		afterSeq := uint64(0)
		if len(request.Cursor) != 0 {
			afterSeq, err = decodeCursor(request.Cursor)
			if err != nil {
				writeError(w, err, requestID)
				return
			}
		}

		var eventTypes []uint64
		if request.Interest != nil {
			eventTypes = request.Interest.EventTypes
			if err := s.validateInterest(request.Interest); err != nil {
				writeError(w, err, requestID)
				return
			}
		}

		page, err := s.collectSyncPage(r.Context(), afterSeq, eventTypes, request.Interest)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		body, err := page.Encode()
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		s.writeBytesCBOR(w, http.StatusOK, body)
	})
}

// validateInterest rejects unknown event type and object type filters, which
// produce E_MANDATORY_UNKNOWN per 60.3.
func (s *Server) validateInterest(interest *sync.Interest) error {
	for _, eventType := range interest.EventTypes {
		if _, err := events.LookupType(eventType); err != nil {
			return registryError("E_MANDATORY_UNKNOWN", fmt.Errorf("unknown event type %d in interest", eventType))
		}
	}
	for _, objectType := range interest.ObjectTypes {
		if _, err := objects.LookupType(objectType); err != nil {
			return registryError("E_MANDATORY_UNKNOWN", fmt.Errorf("unknown object type %d in interest", objectType))
		}
	}
	return nil
}

// collectSyncPage fetches a page of events and their permitted objects,
// honoring the page size and object budget of 62.5.
func (s *Server) collectSyncPage(ctx context.Context, afterSeq uint64, eventTypes []uint64, interest *sync.Interest) (sync.Page, error) {
	pageEvents, more, err := s.cfg.Events.EventsAfter(ctx, afterSeq, eventTypes, s.cfg.PageSize)
	if err != nil {
		return sync.Page{}, err
	}

	pageObjects := make([]ObjectRecord, 0)
	if len(pageEvents) != 0 {
		var budget int64 = s.cfg.ObjectBudget
		seen := make(map[string]bool)
		for _, item := range pageEvents {
			for _, reference := range item.Event.ObjectReferences {
				key := string(reference.ObjectID) + "\x00" + string(reference.VersionID)
				if seen[key] {
					continue
				}
				record, err := s.cfg.Objects.GetObject(ctx, reference.ObjectID, reference.VersionID)
				if err != nil {
					if errors.Is(err, ErrObjectNotFound) {
						continue
					}
					return sync.Page{}, err
				}
				if !interestAllowsObject(interest, record) || budget-record.CiphertextLength < 0 {
					continue
				}
				seen[key] = true
				budget -= record.CiphertextLength
				pageObjects = append(pageObjects, record)
			}
		}
	}

	nextSeq := afterSeq
	if len(pageEvents) != 0 {
		nextSeq = pageEvents[len(pageEvents)-1].Seq
	}

	page := sync.Page{
		Cursor: encodeCursor(nextSeq),
		More:   more,
	}
	for _, item := range pageEvents {
		page.Events = append(page.Events, item.Event)
	}
	for _, record := range pageObjects {
		envelope, err := s.recordEnvelope(ctx, record)
		if err != nil {
			return sync.Page{}, err
		}
		page.Objects = append(page.Objects, envelope)
	}
	return page, nil
}

// interestAllowsObject applies the object-type filter of 62.3.
func interestAllowsObject(interest *sync.Interest, record ObjectRecord) bool {
	if interest == nil || len(interest.ObjectTypes) == 0 {
		return true
	}
	for _, objectType := range interest.ObjectTypes {
		if objectType == record.ObjectType {
			return true
		}
	}
	return false
}

// registryError wraps a registry code into an error suitable for writeError.
func registryError(code string, cause error) error {
	protocolErr, err := protoerrors.New(code, nil, nil, cause)
	if err != nil {
		return cause
	}
	return protocolErr
}
