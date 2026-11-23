package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrPersonNotFound = errors.New("person not found")
	// ErrSubjectTaken refuses to link a subject that is already linked to another identity.
	ErrSubjectTaken = errors.New("subject is linked to another identity")
	// ErrIdentityNotFound refuses to link a person to an identity that does not exist.
	ErrIdentityNotFound = errors.New("identity not found")
)

// Person links a person at an OAuth issuer to the identity whose grants they get. Admin lets
// them manage Sonda; it is set only by an administrator, never derived from the issuer.
type Person struct {
	Identity  string
	Issuer    string
	Subject   string
	Admin     bool
	CreatedAt time.Time
}

const personColumns = `identity, issuer, subject, admin, created_at`

func (s *Store) PersonBySubject(ctx context.Context, issuer, subject string) (Person, error) {
	return s.getPerson(ctx, `SELECT `+personColumns+` FROM identity_people WHERE issuer = $1 AND subject = $2`, issuer, subject)
}

func (s *Store) PersonByIdentity(ctx context.Context, identity string) (Person, error) {
	return s.getPerson(ctx, `SELECT `+personColumns+` FROM identity_people WHERE identity = $1`, identity)
}

func (s *Store) getPerson(ctx context.Context, query string, args ...any) (Person, error) {
	p, err := scanPerson(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Person{}, ErrPersonNotFound
	}
	return p, err
}

// People returns every link, sorted by identity.
func (s *Store) People(ctx context.Context) ([]Person, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+personColumns+` FROM identity_people ORDER BY identity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var people []Person
	for rows.Next() {
		p, err := scanPerson(rows)
		if err != nil {
			return nil, err
		}
		people = append(people, p)
	}
	return people, rows.Err()
}

func scanPerson(row rowScanner) (Person, error) {
	var p Person
	var createdAt int64
	err := row.Scan(&p.Identity, &p.Issuer, &p.Subject, &p.Admin, &createdAt)
	p.CreatedAt = time.UnixMilli(createdAt)
	return p, err
}

// LinkPerson links the person to p.Identity, replacing the identity's previous link.
func (s *Store) LinkPerson(ctx context.Context, p Person) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM identities WHERE name = $1`, p.Identity).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIdentityNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM identity_people WHERE identity = $1`, p.Identity); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO identity_people (`+personColumns+`) VALUES ($1, $2, $3, $4, $5)`,
			p.Identity, p.Issuer, p.Subject, p.Admin, p.CreatedAt.UnixMilli())
		if s.isUniqueViolation(err) {
			return ErrSubjectTaken
		}
		return err
	})
}

// UnlinkPerson removes the identity's link; a missing link is not an error. The person's
// sessions end with it, because every request looks the link up again.
func (s *Store) UnlinkPerson(ctx context.Context, identity string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM identity_people WHERE identity = $1`, identity)
	return err
}

// AdminSessionKind tells a person's session from a break-glass one.
type AdminSessionKind string

const (
	SessionPerson     AdminSessionKind = "person"
	SessionBreakGlass AdminSessionKind = "break-glass"
)

var ErrSessionNotFound = errors.New("admin session not found")

// AdminSession is a signed-in admin UI session. Issuer, Subject and Label are set for a
// person; Credential binds a break-glass session to the admin token it was opened with.
type AdminSession struct {
	Kind       AdminSessionKind
	Issuer     string
	Subject    string
	Label      string
	Credential []byte
	ExpiresAt  time.Time
}

// CreateAdminSession stores a session under the hash of its cookie value and drops expired ones.
func (s *Store) CreateAdminSession(ctx context.Context, idHash [32]byte, session AdminSession) error {
	now := s.now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at < $1`, now.Unix()); err != nil {
		return err
	}
	credential := session.Credential
	if credential == nil {
		credential = []byte{}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_sessions (id_sha256, kind, issuer, subject, label, credential, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		idHash[:], string(session.Kind), session.Issuer, session.Subject, session.Label, credential, session.ExpiresAt.Unix())
	return err
}

// AdminSession returns ErrSessionNotFound for unknown and expired sessions alike.
func (s *Store) AdminSession(ctx context.Context, idHash [32]byte) (AdminSession, error) {
	var session AdminSession
	var kind string
	var expiresAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT kind, issuer, subject, label, credential, expires_at FROM admin_sessions WHERE id_sha256 = $1 AND expires_at > $2`,
		idHash[:], s.now().Unix(),
	).Scan(&kind, &session.Issuer, &session.Subject, &session.Label, &session.Credential, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminSession{}, ErrSessionNotFound
	}
	session.Kind = AdminSessionKind(kind)
	session.ExpiresAt = time.Unix(expiresAt, 0)
	return session, err
}

func (s *Store) DeleteAdminSession(ctx context.Context, idHash [32]byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id_sha256 = $1`, idHash[:])
	return err
}
