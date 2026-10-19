// Package store keeps Sonda's own state in SQLite or Postgres: identities, the audit log and result
// handles. It holds no telemetry beyond the samples behind result handles, which expire.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/contember/sonda/internal/apierr"
)

type Store struct {
	db                *sql.DB
	now               func() time.Time
	isUniqueViolation func(error) bool
}

// Open connects to Postgres when database is a postgres:// or postgresql:// URL and
// otherwise opens database as a SQLite file.
func Open(database string) (*Store, error) {
	if strings.HasPrefix(database, "postgres://") || strings.HasPrefix(database, "postgresql://") {
		return openPostgres(database)
	}
	return openSQLite(database)
}

func newStore(db *sql.DB, schema string, isUniqueViolation func(error) bool) (*Store, error) {
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, now: time.Now, isUniqueViolation: isUniqueViolation}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// SaveResult stores a payload readable only by the same identity until ttl passes.
func (s *Store) SaveResult(ctx context.Context, identity, kind string, payload []byte, ttl time.Duration) (string, error) {
	now := s.now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM results WHERE expires_at < $1`, now.Unix()); err != nil {
		return "", err
	}
	id := newResultID()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO results (id, identity, kind, created_at, expires_at, payload) VALUES ($1, $2, $3, $4, $5, $6)`,
		id, identity, kind, now.Unix(), now.Add(ttl).Unix(), payload)
	return id, err
}

// LoadResult returns not_found for unknown, expired and other identities' results alike.
func (s *Store) LoadResult(ctx context.Context, identity, id string) (kind string, payload []byte, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT kind, payload FROM results WHERE id = $1 AND identity = $2 AND expires_at >= $3`,
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
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		e.Time.UnixMilli(), e.Identity, e.Method, e.Path, e.Service, e.Environment, e.Queries,
		e.Status, e.ErrorCode, e.Duration.Milliseconds(), e.ResponseBytes)
	return err
}

func newResultID() string {
	b := make([]byte, 15)
	_, _ = rand.Read(b)
	return "res_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

type AuditRecord struct {
	ID int64
	AuditEntry
}

type AuditFilter struct {
	// Identity limits the result to one identity when not empty.
	Identity string
	// BeforeID pages backwards: only records with a lower ID are returned when positive.
	BeforeID int64
	Limit    int
}

// ListAudit returns audit records, newest first.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	query := `SELECT id, time, identity, method, path, service, environment, queries, status, error_code, duration_ms, response_bytes
		FROM audit_log WHERE 1 = 1`
	var args []any
	if f.Identity != "" {
		args = append(args, f.Identity)
		query += fmt.Sprintf(` AND identity = $%d`, len(args))
	}
	if f.BeforeID > 0 {
		args = append(args, f.BeforeID)
		query += fmt.Sprintf(` AND id < $%d`, len(args))
	}
	args = append(args, f.Limit)
	query += fmt.Sprintf(` ORDER BY id DESC LIMIT $%d`, len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []AuditRecord
	for rows.Next() {
		var r AuditRecord
		var timeMillis, durationMillis int64
		if err := rows.Scan(&r.ID, &timeMillis, &r.Identity, &r.Method, &r.Path, &r.Service, &r.Environment,
			&r.Queries, &r.Status, &r.ErrorCode, &durationMillis, &r.ResponseBytes); err != nil {
			return nil, err
		}
		r.Time = time.UnixMilli(timeMillis)
		r.Duration = time.Duration(durationMillis) * time.Millisecond
		records = append(records, r)
	}
	return records, rows.Err()
}
