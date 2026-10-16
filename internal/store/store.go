// Package store keeps Sonda's own state in SQLite: the audit log and result handles.
// It holds no telemetry beyond the samples behind result handles, which expire.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/contember/sonda/internal/apierr"
)

const schema = `
CREATE TABLE IF NOT EXISTS results (
	id         TEXT PRIMARY KEY,
	identity   TEXT NOT NULL,
	kind       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	payload    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS results_expires_at ON results (expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
	id             INTEGER PRIMARY KEY,
	time           INTEGER NOT NULL,
	identity       TEXT NOT NULL,
	method         TEXT NOT NULL,
	path           TEXT NOT NULL,
	service        TEXT NOT NULL,
	environment    TEXT NOT NULL,
	queries        TEXT NOT NULL,
	status         INTEGER NOT NULL,
	error_code     TEXT NOT NULL,
	duration_ms    INTEGER NOT NULL,
	response_bytes INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_time ON audit_log (time);
`

type Store struct {
	db  *sql.DB
	now func() time.Time
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a single connection avoids lock errors.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database %s: %w", path, err)
	}
	return &Store{db: db, now: time.Now}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// SaveResult stores a payload readable only by the same identity until ttl passes.
func (s *Store) SaveResult(ctx context.Context, identity, kind string, payload []byte, ttl time.Duration) (string, error) {
	now := s.now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM results WHERE expires_at < ?`, now.Unix()); err != nil {
		return "", err
	}
	id := newResultID()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO results (id, identity, kind, created_at, expires_at, payload) VALUES (?, ?, ?, ?, ?, ?)`,
		id, identity, kind, now.Unix(), now.Add(ttl).Unix(), payload)
	return id, err
}

// LoadResult returns not_found for unknown, expired and other identities' results alike.
func (s *Store) LoadResult(ctx context.Context, identity, id string) (kind string, payload []byte, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT kind, payload FROM results WHERE id = ? AND identity = ? AND expires_at >= ?`,
		id, identity, s.now().Unix(),
	).Scan(&kind, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, apierr.NotFound("result %q not found or expired", id)
	}
	return kind, payload, err
}

type AuditEntry struct {
	Time          time.Time
	Identity      string
	Method        string
	Path          string
	Service       string
	Environment   string
	Queries       string
	Status        int
	ErrorCode     string
	Duration      time.Duration
	ResponseBytes int
}

func (s *Store) WriteAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (time, identity, method, path, service, environment, queries, status, error_code, duration_ms, response_bytes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Time.UnixMilli(), e.Identity, e.Method, e.Path, e.Service, e.Environment, e.Queries,
		e.Status, e.ErrorCode, e.Duration.Milliseconds(), e.ResponseBytes)
	return err
}

func newResultID() string {
	b := make([]byte, 15)
	_, _ = rand.Read(b)
	return "res_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
