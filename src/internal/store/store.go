// Package store persists events, peers, and sync state in PostgreSQL.
//
// The protocol layer stays dependency-free; storage maps protocol state onto
// a relational backend. Event rows are immutable and keyed by event ID with an
// additional monotonic sequence for sync watermarking (62.4). Per-peer sync
// state follows 62.8.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrEventIDCollision = errors.New("event ID collision")
	ErrEventNotFound    = errors.New("event not found")
	ErrUnknownPeer      = errors.New("peer has no synchronization state")
	ErrInvalidCursor    = errors.New("invalid sync cursor")
	ErrEmptyCursor      = errors.New("sync cursor must not be empty")
)

// Store is a PostgreSQL-backed persistence facade.
type Store struct {
	pool *pgxpool.Pool
}

// Config controls the PostgreSQL connection pool.
type Config struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnIdleTime time.Duration
	MaxConnLifetime time.Duration
}

// Open builds a store without requiring a live connection. Use Ping or Migrate
// to validate connectivity.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 8
	}
	if cfg.MaxConnIdleTime == 0 {
		cfg.MaxConnIdleTime = 30 * time.Minute
	}
	if cfg.MaxConnLifetime == 0 {
		cfg.MaxConnLifetime = time.Hour
	}
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}
	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Ping verifies database connectivity, for startup validation and health checks.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}
