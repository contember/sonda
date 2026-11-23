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

-- Grants of per-service capabilities (data). A separate table, so an older Sonda ignores them.
CREATE TABLE IF NOT EXISTS identity_service_grants (
	identity    TEXT NOT NULL REFERENCES identities (name) ON DELETE CASCADE,
	service     TEXT NOT NULL,
	environment TEXT NOT NULL,
	capability  TEXT NOT NULL,
	PRIMARY KEY (identity, service, environment, capability)
);

-- Project grants with a wildcard (*) in the project, environment or capability. A separate
-- table, so an older Sonda ignores them instead of failing on the * capability.
CREATE TABLE IF NOT EXISTS identity_wildcard_grants (
	identity    TEXT NOT NULL REFERENCES identities (name) ON DELETE CASCADE,
	project     TEXT NOT NULL,
	environment TEXT NOT NULL,
	capability  TEXT NOT NULL,
	PRIMARY KEY (identity, project, environment, capability)
);

-- People who sign in to the admin UI through admin.oauth, each as one identity. A person is
-- matched by the issuer and the subject of their access token, never by a name or an address.
CREATE TABLE IF NOT EXISTS identity_people (
	identity   TEXT PRIMARY KEY REFERENCES identities (name) ON DELETE CASCADE,
	issuer     TEXT NOT NULL,
	subject    TEXT NOT NULL,
	admin      BOOLEAN NOT NULL,
	created_at BIGINT NOT NULL,
	UNIQUE (issuer, subject)
);

-- Admin UI sessions, stored by the SHA-256 of the cookie value.
CREATE TABLE IF NOT EXISTS admin_sessions (
	id_sha256  BYTEA PRIMARY KEY,
	kind       TEXT NOT NULL,
	issuer     TEXT NOT NULL,
	subject    TEXT NOT NULL,
	label      TEXT NOT NULL,
	credential BYTEA NOT NULL,
	expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_sessions_expires_at ON admin_sessions (expires_at);

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
