package store

import (
	"database/sql"
	"errors"
	"fmt"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const sqliteSchema = `
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
CREATE INDEX IF NOT EXISTS audit_log_identity ON audit_log (identity, id);

CREATE TABLE IF NOT EXISTS identities (
	name                TEXT PRIMARY KEY,
	token_sha256        BLOB NOT NULL UNIQUE,
	created_at          INTEGER NOT NULL,
	max_range_ms        INTEGER,
	max_log_lines       INTEGER,
	max_response_bytes  INTEGER,
	query_timeout_ms    INTEGER,
	concurrent_queries  INTEGER,
	requests_per_minute INTEGER
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
	admin      INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	UNIQUE (issuer, subject)
);

-- Admin UI sessions, stored by the SHA-256 of the cookie value.
CREATE TABLE IF NOT EXISTS admin_sessions (
	id_sha256  BLOB PRIMARY KEY,
	kind       TEXT NOT NULL,
	issuer     TEXT NOT NULL,
	subject    TEXT NOT NULL,
	label      TEXT NOT NULL,
	credential BLOB NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_sessions_expires_at ON admin_sessions (expires_at);

CREATE TABLE IF NOT EXISTS signing_keys (
	id          TEXT PRIMARY KEY,
	private_key BLOB NOT NULL,
	created_at  INTEGER NOT NULL
);
`

func openSQLite(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a single connection avoids lock errors.
	db.SetMaxOpenConns(1)
	st, err := newStore(db, sqliteSchema, isSQLiteUniqueViolation)
	if err != nil {
		return nil, fmt.Errorf("initialize database %s: %w", path, err)
	}
	return st, nil
}

func isSQLiteUniqueViolation(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || e.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}
