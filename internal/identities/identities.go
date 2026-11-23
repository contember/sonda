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

// Grant allows one capability in one environment of every service of a project. A grant of a
// per-service capability names one Service instead and leaves Project empty.
type Grant struct {
	Project     string
	Service     string
	Environment string
	Capability  api.Capability
}

// Wildcard in the project, environment or capability of a project grant matches every value,
// including projects, environments and capabilities configured later. Per-service grants never
// take it, and a wildcard capability never covers a per-service capability.
const Wildcard = "*"

// AnyCapability is the wildcard in a grant's capability.
const AnyCapability api.Capability = Wildcard

// ParseCapability parses a stored or submitted grant capability: a capability or AnyCapability.
func ParseCapability(s string) (api.Capability, error) {
	if s == Wildcard {
		return AnyCapability, nil
	}
	return api.ParseCapability(s)
}

// PerService reports whether the capability is granted per service instead of per project.
// Data is the most sensitive capability, so a grant opens the data of one named service only.
func PerService(capability api.Capability) bool {
	return capability == api.CapabilityData
}

// Valid reports whether the grant names a project or a service as its capability requires.
// A per-service grant names its service and environment exactly.
func (g Grant) Valid() bool {
	if PerService(g.Capability) {
		return g.Service != "" && g.Service != Wildcard && g.Environment != Wildcard && g.Project == ""
	}
	return g.Project != "" && g.Service == ""
}

// HasWildcard reports whether any position of the grant is a wildcard.
func (g Grant) HasWildcard() bool {
	return g.Project == Wildcard || g.Environment == Wildcard || g.Capability == AnyCapability
}

// Covers reports whether the grant opens the capability in the environment of the service,
// which belongs to the project. Each position must match; a wildcard matches only its own.
func (g Grant) Covers(project, service, environment string, capability api.Capability) bool {
	if PerService(capability) {
		return g == Grant{Service: service, Environment: environment, Capability: capability}
	}
	return g.Service == "" &&
		matches(g.Project, project) &&
		matches(g.Environment, environment) &&
		(g.Capability == AnyCapability || g.Capability == capability)
}

func matches(pattern, value string) bool {
	return pattern == Wildcard || pattern == value
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
