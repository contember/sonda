package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/identities"
)

var _ identities.Store = (*Store)(nil)

const identityColumns = `name, token_sha256, created_at, max_range_ms, max_log_lines, max_response_bytes,
	query_timeout_ms, concurrent_queries, requests_per_minute`

func (s *Store) FindByTokenHash(ctx context.Context, hash [sha256.Size]byte) (identities.Identity, error) {
	return s.getIdentity(ctx, `SELECT `+identityColumns+` FROM identities WHERE token_sha256 = ?`, hash[:])
}

func (s *Store) Get(ctx context.Context, name string) (identities.Identity, error) {
	return s.getIdentity(ctx, `SELECT `+identityColumns+` FROM identities WHERE name = ?`, name)
}

func (s *Store) getIdentity(ctx context.Context, query string, arg any) (identities.Identity, error) {
	identity, err := scanIdentity(s.db.QueryRowContext(ctx, query, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return identities.Identity{}, identities.ErrNotFound
	}
	if err != nil {
		return identities.Identity{}, err
	}
	grants, err := s.grants(ctx, `SELECT identity, service, environment, capability FROM identity_grants WHERE identity = ?`, identity.Name)
	identity.Grants = grants[identity.Name]
	return identity, err
}

// List returns all identities sorted by name.
func (s *Store) List(ctx context.Context) ([]identities.Identity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+identityColumns+` FROM identities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []identities.Identity
	for rows.Next() {
		identity, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	grants, err := s.grants(ctx, `SELECT identity, service, environment, capability FROM identity_grants`)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Grants = grants[list[i].Name]
	}
	return list, nil
}

func (s *Store) Create(ctx context.Context, identity identities.Identity) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o := identity.Limits
		_, err := tx.ExecContext(ctx,
			`INSERT INTO identities (`+identityColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			identity.Name, identity.TokenSHA256[:], identity.CreatedAt.UnixMilli(),
			millis(o.MaxRange), o.MaxLogLines, o.MaxResponseBytes, millis(o.QueryTimeout), o.ConcurrentQueries, o.RequestsPerMinute)
		if isUniqueViolation(err) {
			return identities.ErrExists
		}
		if err != nil {
			return err
		}
		return insertGrants(ctx, tx, identity.Name, identity.Grants)
	})
}

func (s *Store) Update(ctx context.Context, name string, grants []identities.Grant, limits identities.LimitOverrides) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx,
			`UPDATE identities SET max_range_ms = ?, max_log_lines = ?, max_response_bytes = ?,
				query_timeout_ms = ?, concurrent_queries = ?, requests_per_minute = ?
			 WHERE name = ?`,
			millis(limits.MaxRange), limits.MaxLogLines, limits.MaxResponseBytes,
			millis(limits.QueryTimeout), limits.ConcurrentQueries, limits.RequestsPerMinute, name)
		if err := requireOneRow(result, err); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM identity_grants WHERE identity = ?`, name); err != nil {
			return err
		}
		return insertGrants(ctx, tx, name, grants)
	})
}

func (s *Store) SetTokenHash(ctx context.Context, name string, hash [sha256.Size]byte) error {
	result, err := s.db.ExecContext(ctx, `UPDATE identities SET token_sha256 = ? WHERE name = ?`, hash[:], name)
	if isUniqueViolation(err) {
		return identities.ErrExists
	}
	return requireOneRow(result, err)
}

// Delete removes the identity and, through the foreign key, its grants.
func (s *Store) Delete(ctx context.Context, name string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM identities WHERE name = ?`, name)
	return requireOneRow(result, err)
}

func (s *Store) grants(ctx context.Context, query string, args ...any) (map[string][]identities.Grant, error) {
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY service, environment, capability`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byIdentity := map[string][]identities.Grant{}
	for rows.Next() {
		var identity, service, environment, capability string
		if err := rows.Scan(&identity, &service, &environment, &capability); err != nil {
			return nil, err
		}
		parsed, err := api.ParseCapability(capability)
		if err != nil {
			return nil, fmt.Errorf("stored grant of identity %q: %w", identity, err)
		}
		byIdentity[identity] = append(byIdentity[identity], identities.Grant{Service: service, Environment: environment, Capability: parsed})
	}
	return byIdentity, rows.Err()
}

func insertGrants(ctx context.Context, tx *sql.Tx, name string, grants []identities.Grant) error {
	for _, g := range grants {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO identity_grants (identity, service, environment, capability) VALUES (?, ?, ?, ?)`,
			name, g.Service, g.Environment, string(g.Capability)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanIdentity(row rowScanner) (identities.Identity, error) {
	var identity identities.Identity
	var hash []byte
	var createdAt int64
	var maxRange, queryTimeout sql.NullInt64
	var maxLogLines, maxResponseBytes, concurrentQueries, requestsPerMinute sql.Null[int]
	err := row.Scan(&identity.Name, &hash, &createdAt, &maxRange, &maxLogLines, &maxResponseBytes,
		&queryTimeout, &concurrentQueries, &requestsPerMinute)
	if err != nil {
		return identities.Identity{}, err
	}
	if len(hash) != sha256.Size {
		return identities.Identity{}, fmt.Errorf("stored identity %q: token hash has %d bytes", identity.Name, len(hash))
	}
	identity.TokenSHA256 = [sha256.Size]byte(hash)
	identity.CreatedAt = time.UnixMilli(createdAt)
	identity.Limits = identities.LimitOverrides{
		MaxRange:          duration(maxRange),
		MaxLogLines:       nullable(maxLogLines),
		MaxResponseBytes:  nullable(maxResponseBytes),
		QueryTimeout:      duration(queryTimeout),
		ConcurrentQueries: nullable(concurrentQueries),
		RequestsPerMinute: nullable(requestsPerMinute),
	}
	return identity, nil
}

func millis(d *time.Duration) *int64 {
	if d == nil {
		return nil
	}
	ms := d.Milliseconds()
	return &ms
}

func duration(ms sql.NullInt64) *time.Duration {
	if !ms.Valid {
		return nil
	}
	d := time.Duration(ms.Int64) * time.Millisecond
	return &d
}

func nullable[T any](v sql.Null[T]) *T {
	if !v.Valid {
		return nil
	}
	return &v.V
}

func requireOneRow(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return identities.ErrNotFound
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || e.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}
