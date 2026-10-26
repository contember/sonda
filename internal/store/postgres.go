package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresSchema = `
CREATE TABLE IF NOT EXISTS results (
	id         TEXT PRIMARY KEY,
	identity   TEXT NOT NULL,
	kind       TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	expires_at BIGINT NOT NULL,
	payload    BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS results_expires_at ON results (expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
	id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	time           BIGINT NOT NULL,
	identity       TEXT NOT NULL,
	method         TEXT NOT NULL,
	path           TEXT NOT NULL,
	service        TEXT NOT NULL,
	environment    TEXT NOT NULL,
	queries        TEXT NOT NULL,
	status         INTEGER NOT NULL,
	error_code     TEXT NOT NULL,
	duration_ms    BIGINT NOT NULL,
	response_bytes BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_time ON audit_log (time);
CREATE INDEX IF NOT EXISTS audit_log_identity ON audit_log (identity, id);

CREATE TABLE IF NOT EXISTS identities (
	name                TEXT PRIMARY KEY,
	token_sha256        BYTEA NOT NULL UNIQUE,
	created_at          BIGINT NOT NULL,
	max_range_ms        BIGINT,
	max_log_lines       BIGINT,
	max_response_bytes  BIGINT,
	query_timeout_ms    BIGINT,
	concurrent_queries  BIGINT,
	requests_per_minute BIGINT
);

CREATE TABLE IF NOT EXISTS identity_grants (
	identity    TEXT NOT NULL REFERENCES identities (name) ON DELETE CASCADE,
	project     TEXT NOT NULL,
	environment TEXT NOT NULL,
	capability  TEXT NOT NULL,
	PRIMARY KEY (identity, project, environment, capability)
);

CREATE TABLE IF NOT EXISTS signing_keys (
	id          TEXT PRIMARY KEY,
	private_key BYTEA NOT NULL,
	created_at  BIGINT NOT NULL
);
`

const postgresUniqueViolation = "23505"

func openPostgres(url string) (*Store, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	st, err := newStore(db, postgresSchema, isPostgresUniqueViolation)
	if err != nil {
		// The URL is left out of the error: it may contain the password.
		return nil, fmt.Errorf("initialize Postgres database: %w", err)
	}
	return st, nil
}

func isPostgresUniqueViolation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == postgresUniqueViolation
}
