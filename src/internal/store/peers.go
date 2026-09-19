package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"loopable.party/server/internal/protocol/sync"
)

// UpsertPeer records or updates the sync state for one federation relationship,
// per 62.8. A nil Cursor clears a previously stored cursor.
func (s *Store) UpsertPeer(ctx context.Context, state sync.PeerState) error {
	var cursor any
	if state.Cursor != nil {
		cursor = state.Cursor
	}
	var lastSync any
	if !state.LastSuccessfulSync.IsZero() {
		lastSync = state.LastSuccessfulSync
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO peers (peer_instance_id, protocol_version, capabilities, cursor, last_successful_sync)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (peer_instance_id) DO UPDATE SET
			protocol_version = EXCLUDED.protocol_version,
			capabilities = EXCLUDED.capabilities,
			cursor = EXCLUDED.cursor,
			last_successful_sync = EXCLUDED.last_successful_sync
	`, state.PeerInstanceID, state.ProtocolVersion, state.Capabilities, cursor, lastSync)
	return err
}

// GetPeer returns the sync state for one federation relationship.
func (s *Store) GetPeer(ctx context.Context, peerID []byte) (sync.PeerState, error) {
	state := sync.PeerState{PeerInstanceID: append([]byte(nil), peerID...)}
	var capabilities []string
	var cursor []byte
	var lastSync *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT protocol_version, capabilities, cursor, last_successful_sync
		FROM peers WHERE peer_instance_id = $1
	`, peerID).Scan(&state.ProtocolVersion, &capabilities, &cursor, &lastSync)
	if errors.Is(err, pgx.ErrNoRows) {
		return sync.PeerState{}, ErrUnknownPeer
	}
	if err != nil {
		return sync.PeerState{}, err
	}
	state.Capabilities = capabilities
	state.Cursor = cursor
	if lastSync != nil {
		state.LastSuccessfulSync = *lastSync
	}
	return state, nil
}

// SaveCursor stores the serving watermark for one peer and interest filter, per
// 62.2. The interest is its canonical encoding; equal filters share an anchor.
func (s *Store) SaveCursor(ctx context.Context, peerID, interest []byte, seq uint64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO peer_cursors (peer_instance_id, interest_hash, cursor_seq)
		VALUES ($1, $2, $3)
		ON CONFLICT (peer_instance_id, interest_hash) DO UPDATE SET
			cursor_seq = EXCLUDED.cursor_seq,
			updated_at = now()
	`, peerID, hashInterest(interest), seq)
	return err
}

// CursorFor returns the stored watermark for one peer and interest filter.
// Empty peers and unknown filters both report ErrUnknownPeer so that callers
// cannot distinguish new peers from filtered-out streams.
func (s *Store) CursorFor(ctx context.Context, peerID, interest []byte) (uint64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `
		SELECT cursor_seq FROM peer_cursors
		WHERE peer_instance_id = $1 AND interest_hash = $2
	`, peerID, hashInterest(interest)).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrUnknownPeer
	}
	if err != nil {
		return 0, err
	}
	return uint64(seq), nil
}

// InterestAnchor is a stored watermark for one peer and interest filter.
type InterestAnchor struct {
	Interest []byte
	Seq      uint64
}

// CursorsFor returns every stored watermark for a peer.
func (s *Store) CursorsFor(ctx context.Context, peerID []byte) (map[string]InterestAnchor, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT interest_hash, cursor_seq FROM peer_cursors
		WHERE peer_instance_id = $1
	`, peerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	anchors := make(map[string]InterestAnchor)
	for rows.Next() {
		var hash []byte
		var seq int64
		if err := rows.Scan(&hash, &seq); err != nil {
			return nil, err
		}
		anchors[string(hash)] = InterestAnchor{Interest: hash, Seq: uint64(seq)}
	}
	return anchors, rows.Err()
}

// ForgetPeer deletes all sync state for a peer, including its cursors.
func (s *Store) ForgetPeer(ctx context.Context, peerID []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM peers WHERE peer_instance_id = $1`, peerID)
	return err
}

func hashInterest(interest []byte) []byte {
	if len(interest) == 0 {
		interest = nil
	}
	sum := sha256.Sum256(interest)
	return sum[:]
}
