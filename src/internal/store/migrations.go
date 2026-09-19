package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const migrationLockKey int64 = 0x6C6F6F7061626C65 // "loopable"

// Version reports the highest applied schema migration.
func (s *Store) Version(ctx context.Context) (int, error) {
	var version int
	err := s.pool.QueryRow(ctx, `
		SELECT coalesce(max(version), 0) FROM schema_migrations
	`).Scan(&version)
	return version, err
}

// Migratable reports whether applying migrations would change the schema.
func (s *Store) Migratable(ctx context.Context) (bool, error) {
	applied, err := s.Version(ctx)
	if err != nil {
		return false, err
	}
	return applied < latestVersion(), nil
}

// Migrate applies every embedded migration newer than the recorded schema
// version, each inside its own transaction. Concurrent migrations serialize on
// a single advisory lock. A failed migration rolls back completely and leaves
// the recorded version unchanged.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return err
	}

	current, err := s.Version(ctx)
	if err != nil {
		return err
	}

	for _, migration := range sortedMigrations() {
		if migration.version <= current {
			continue
		}
		if err := applyMigration(ctx, conn, migration); err != nil {
			return fmt.Errorf("migration %s: %w", migration.name, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, conn *pgxpool.Conn, migration migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, migration.sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`, migration.version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type migration struct {
	version int
	name    string
	sql     string
}

func sortedMigrations() []migration {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil
	}
	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			continue
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			continue
		}
		migrations = append(migrations, migration{version: version, name: name, sql: string(body)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations
}

func latestVersion() int {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return 0
	}
	latest := 0
	for _, entry := range entries {
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			continue
		}
		if version, err := strconv.Atoi(prefix); err == nil && version > latest {
			latest = version
		}
	}
	return latest
}
