package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/events"
)

// StoredEvent is an event row paired with its monotonic sync sequence.
type StoredEvent struct {
	Seq   uint64
	Event events.Event
}

// EncodeCursor wraps a sequence number in the opaque 8-byte cursor of 62.2.
func EncodeCursor(seq uint64) []byte {
	cursor := make([]byte, 8)
	binary.BigEndian.PutUint64(cursor, seq)
	return cursor
}

// DecodeCursor unwraps an opaque cursor into its sequence number.
func DecodeCursor(cursor []byte) (uint64, error) {
	if len(cursor) == 0 {
		return 0, ErrEmptyCursor
	}
	if len(cursor) != 8 {
		return 0, ErrInvalidCursor
	}
	return binary.BigEndian.Uint64(cursor), nil
}

// PutEvent stores an event immutably. Re-submitting identical bytes is
// idempotent; distinct bytes under the same event ID yield ErrEventIDCollision.
// The returned sequence is the event's watermark in the publish stream. Events
// are valid and authorized before they are stored.
func (s *Store) PutEvent(ctx context.Context, event events.Event) (StoredEvent, error) {
	encoded, err := event.CanonicalBytes()
	if err != nil {
		return StoredEvent{}, err
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO events (event_id, event_type, account_id, wire)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (event_id) DO NOTHING
		RETURNING seq
	`, event.EventID, uint32(event.EventType), event.AccountID, encoded)

	var seq int64
	err = row.Scan(&seq)
	if err == nil {
		return StoredEvent{Seq: uint64(seq), Event: event}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return StoredEvent{}, err
	}
	existing, err := s.eventWire(ctx, event.EventID)
	if err != nil {
		return StoredEvent{}, err
	}
	if !bytes.Equal(existing, encoded) {
		return StoredEvent{}, ErrEventIDCollision
	}
	seq, err = s.eventSeq(ctx, event.EventID)
	if err != nil {
		return StoredEvent{}, err
	}
	return StoredEvent{Seq: uint64(seq), Event: event}, nil
}

// GetEvent returns the stored event by ID.
func (s *Store) GetEvent(ctx context.Context, eventID []byte) (events.Event, error) {
	wire, err := s.eventWire(ctx, eventID)
	if err != nil {
		return events.Event{}, err
	}
	var decoded any
	if err := encoding.Decode(wire, &decoded); err != nil {
		return events.Event{}, fmt.Errorf("decode stored event: %w", err)
	}
	event, err := events.Parse(decoded)
	if err != nil {
		return events.Event{}, fmt.Errorf("parse stored event: %w", err)
	}
	return event, nil
}

// HasEvent reports whether an event is already stored.
func (s *Store) HasEvent(ctx context.Context, eventID []byte) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT exists(SELECT 1 FROM events WHERE event_id = $1)`, eventID).Scan(&exists)
	return exists, err
}

// EventsAfter returns up to limit events with sequence greater than afterSeq,
// oldest first, optionally filtered to the given event types. The returned
// boolean reports whether more events remain beyond the page.
func (s *Store) EventsAfter(ctx context.Context, afterSeq uint64, eventTypes []uint64, limit int) ([]StoredEvent, bool, error) {
	restricted := len(eventTypes) > 0
	rows, err := s.pool.Query(ctx, `
		SELECT seq, event_id, wire
		FROM events
		WHERE seq > $1
		  AND ($2 = false OR event_type = ANY($3::integer[]))
		ORDER BY seq ASC
		LIMIT $4
	`, afterSeq, restricted, int32s(eventTypes), limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	page := make([]StoredEvent, 0, limit)
	for rows.Next() {
		var seq int64
		var eventID []byte
		var wire []byte
		if err := rows.Scan(&seq, &eventID, &wire); err != nil {
			return nil, false, err
		}
		event, err := parseStoredEvent(wire, eventID)
		if err != nil {
			return nil, false, err
		}
		page = append(page, StoredEvent{Seq: uint64(seq), Event: event})
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(page) > limit
	if more {
		page = page[:limit]
	}
	return page, more, nil
}

// LatestSeq returns the highest watermark currently published.
func (s *Store) LatestSeq(ctx context.Context) (uint64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM events`).Scan(&seq)
	return uint64(seq), err
}

func (s *Store) eventWire(ctx context.Context, eventID []byte) ([]byte, error) {
	var wire []byte
	err := s.pool.QueryRow(ctx,
		`SELECT wire FROM events WHERE event_id = $1`, eventID).Scan(&wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEventNotFound
	}
	if err != nil {
		return nil, err
	}
	return wire, nil
}

func (s *Store) eventSeq(ctx context.Context, eventID []byte) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx,
		`SELECT seq FROM events WHERE event_id = $1`, eventID).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrEventNotFound
	}
	return seq, err
}

func parseStoredEvent(wire, eventID []byte) (events.Event, error) {
	var decoded any
	if err := encoding.Decode(wire, &decoded); err != nil {
		return events.Event{}, fmt.Errorf("decode stored event %x: %w", eventID, err)
	}
	event, err := events.Parse(decoded)
	if err != nil {
		return events.Event{}, fmt.Errorf("parse stored event %x: %w", eventID, err)
	}
	return event, nil
}

func int32s(values []uint64) []int32 {
	converted := make([]int32, len(values))
	for i, value := range values {
		converted[i] = int32(value)
	}
	return converted
}
