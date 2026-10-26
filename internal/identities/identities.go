// Package identities defines agent identities and the store that persists them. Identities
// are managed at runtime through the admin UI; sources and projects stay in the config file.
package identities

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

var (
	ErrNotFound = errors.New("identity not found")
	ErrExists   = errors.New("identity already exists")
)

type Identity struct {
	Name        string
	TokenSHA256 [sha256.Size]byte
	Grants      []Grant
	Limits      LimitOverrides
	CreatedAt   time.Time
}

// Grant allows one capability in one environment of every service of a project.
type Grant struct {
	Project     string
	Environment string
	Capability  api.Capability
}

// LimitOverrides replace the server limits where set.
type LimitOverrides struct {
	MaxRange          *time.Duration
	MaxLogLines       *int
	MaxResponseBytes  *int
	QueryTimeout      *time.Duration
	ConcurrentQueries *int
	RequestsPerMinute *int
}

func (o LimitOverrides) Apply(base config.Limits) config.Limits {
	limits := base
	override(&limits.MaxRange, o.MaxRange)
	override(&limits.MaxLogLines, o.MaxLogLines)
	override(&limits.MaxResponseBytes, o.MaxResponseBytes)
	override(&limits.QueryTimeout, o.QueryTimeout)
	override(&limits.ConcurrentQueries, o.ConcurrentQueries)
	override(&limits.RequestsPerMinute, o.RequestsPerMinute)
	return limits
}

func override[T any](target *T, value *T) {
	if value != nil {
		*target = *value
	}
}

// Store persists identities. Implementations return ErrNotFound for unknown names and
// tokens, and ErrExists when a name or token hash is already taken.
type Store interface {
	FindByTokenHash(ctx context.Context, hash [sha256.Size]byte) (Identity, error)
	List(ctx context.Context) ([]Identity, error)
	Get(ctx context.Context, name string) (Identity, error)
	Create(ctx context.Context, identity Identity) error
	// Update replaces the grants and limit overrides.
	Update(ctx context.Context, name string, grants []Grant, limits LimitOverrides) error
	SetTokenHash(ctx context.Context, name string, hash [sha256.Size]byte) error
	Delete(ctx context.Context, name string) error
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("name must be 1-63 characters: lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	return nil
}

// NewToken returns a random bearer token and its SHA-256, the only form that is stored.
func NewToken() (token string, hash [sha256.Size]byte) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	token = "sonda_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return token, sha256.Sum256([]byte(token))
}
