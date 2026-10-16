// Package config loads and validates the Sonda server configuration.
// The YAML file is parsed into raw structs first, then validated into the typed Config.
package config

import (
	"crypto/sha256"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/contember/sonda/api"
)

type Config struct {
	Server     Server
	Grafana    *Grafana
	Sources    map[string]*Source
	Services   map[string]*Service
	Identities map[string]*Identity
	Limits     Limits
	Redact     []string
}

type Server struct {
	Listen   string
	Database string
}

type Grafana struct {
	URL string
}

type SourceType string

const (
	SourceSentry     SourceType = "sentry"
	SourceLoki       SourceType = "loki"
	SourcePrometheus SourceType = "prometheus"
)

type Source struct {
	Name    string
	Type    SourceType
	URL     string
	Auth    Auth
	Headers map[string]string
	// SentryOrg is set for Sentry sources only.
	SentryOrg string
	// GrafanaDatasourceUID is used only to build Explore links.
	GrafanaDatasourceUID string
}

type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBearer AuthType = "bearer"
	AuthBasic  AuthType = "basic"
)

type Auth struct {
	Type     AuthType
	Token    string
	Username string
	Password string
}

type Service struct {
	Name         string
	Description  string
	Repository   string
	Environments map[string]*Environment
	// Signals maps a signal name to a PromQL expression without service matchers.
	Signals map[string]string
}

type Environment struct {
	Name    string
	Errors  *ErrorBinding
	Logs    *SelectorBinding
	Metrics *SelectorBinding
}

type ErrorBinding struct {
	Source      *Source
	Project     string
	Environment string
}

// SelectorBinding scopes a Loki or Prometheus source to one service. Matchers always
// contain an = or =~ matcher that rejects the empty value, so the scope is never "everything".
type SelectorBinding struct {
	Source   *Source
	Selector string
	Matchers []*labels.Matcher
}

func (e *Environment) Capabilities() []api.Capability {
	var caps []api.Capability
	if e.Errors != nil {
		caps = append(caps, api.CapabilityErrors)
	}
	if e.Logs != nil {
		caps = append(caps, api.CapabilityLogs)
	}
	if e.Metrics != nil {
		caps = append(caps, api.CapabilityMetrics)
	}
	return caps
}

type Identity struct {
	Name        string
	TokenSHA256 [sha256.Size]byte
	Grants      []Grant
	// Limits are the server defaults merged with the identity's overrides.
	Limits Limits
}

type Grant struct {
	Services     []string
	Environments []string
	Capabilities []api.Capability
}

type Limits struct {
	MaxRange          time.Duration
	MaxLogLines       int
	MaxResponseBytes  int
	QueryTimeout      time.Duration
	ConcurrentQueries int
	RequestsPerMinute int
}

var DefaultLimits = Limits{
	MaxRange:          7 * 24 * time.Hour,
	MaxLogLines:       500,
	MaxResponseBytes:  64 * 1024,
	QueryTimeout:      30 * time.Second,
	ConcurrentQueries: 4,
	RequestsPerMinute: 60,
}
