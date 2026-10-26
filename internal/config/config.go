// Package config loads and validates the Sonda server configuration.
// The YAML file is parsed into raw structs first, then validated into the typed Config.
package config

import (
	"crypto/x509"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/telemetry"
)

type Config struct {
	Server   Server
	Admin    *Admin
	Grafana  *Grafana
	Sources  map[string]*Source
	Services map[string]*Service
	Limits   Limits
	Redact   []string
}

type Server struct {
	Listen   string
	Database string
}

// Admin enables the admin UI under /admin. Without it the UI is not served.
type Admin struct {
	Token string
}

type Grafana struct {
	URL string
}

type SourceType string

const (
	SourceSentry     SourceType = "sentry"
	SourceLoki       SourceType = "loki"
	SourcePrometheus SourceType = "prometheus"
	SourceCloudflare SourceType = "cloudflare"
	SourceAWS        SourceType = "aws"
	SourceTempo      SourceType = "tempo"
	SourceKubernetes SourceType = "kubernetes"
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
	// CloudflareAccountID is set for Cloudflare sources only.
	CloudflareAccountID string
	// AWS is set for AWS sources only.
	AWS *AWSSource
	// RootCAs verifies the server certificate instead of the system roots; Kubernetes only.
	RootCAs *x509.CertPool
}

type AWSSource struct {
	Region     string
	RoleARN    string // optional; the default credential chain is used without it
	ExternalID string // optional, only with RoleARN
	// MaxScanBytes stops a Logs Insights query that scans more, because scanning is billed.
	MaxScanBytes int64
}

type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBearer AuthType = "bearer"
	AuthBasic  AuthType = "basic"
)

type Auth struct {
	Type  AuthType
	Token string
	// TokenFile is read on every request instead of Token, because Kubernetes rotates
	// projected service account tokens. It is set only for in-cluster Kubernetes sources.
	TokenFile string
	Username  string
	Password  string
}

type Service struct {
	Name         string
	Description  string
	Repository   string
	Environments map[string]*Environment
	Signals      map[string]Signal
}

// Signal is a named metrics query stored in the service's metrics dialect, without scope.
type Signal struct {
	Dialect api.Dialect
	Query   string // PromQL, or the JSON of a structured metric query
}

type Environment struct {
	Name      string
	Errors    *ErrorBinding
	Logs      *LogBinding
	Metrics   *MetricBinding
	Traces    *TraceBinding
	Workloads *WorkloadBinding
}

type ErrorBinding struct {
	Source      *Source
	Project     string
	Environment string
}

// Selector is a label selector that scopes a Loki or Prometheus source. Matchers always
// contain an = or =~ matcher that rejects the empty value, so the scope is never "everything".
type Selector struct {
	Text     string
	Matchers []*labels.Matcher
}

// LogBinding scopes a log source to one service. Exactly one variant is set, by source type:
// Selector (loki), Script (cloudflare), LogGroups (aws).
type LogBinding struct {
	Source    *Source
	Selector  *Selector
	Script    string
	LogGroups []string
}

func (b *LogBinding) Dialect() api.Dialect {
	switch b.Source.Type {
	case SourceLoki:
		return api.DialectLogQL
	case SourceCloudflare:
		return api.DialectCloudflareQuery
	case SourceAWS:
		return api.DialectLogsInsights
	}
	return ""
}

// MetricBinding scopes a metrics source to one service. Exactly one variant is set, by source
// type: Selector (prometheus), Script with optional CloudflareResources (cloudflare),
// Namespace with Dimensions (aws).
type MetricBinding struct {
	Source   *Source
	Selector *Selector
	Script   string
	// CloudflareResources maps resource names to IDs per kind; kinds without resources are absent.
	CloudflareResources map[telemetry.CloudflareResource]map[string]string
	Namespace           string
	Dimensions          map[string]string
}

func (b *MetricBinding) Dialect() api.Dialect {
	switch b.Source.Type {
	case SourcePrometheus:
		return api.DialectPromQL
	case SourceCloudflare:
		return api.DialectCloudflareMetric
	case SourceAWS:
		return api.DialectCloudWatchMetric
	}
	return ""
}

// TraceBinding scopes a trace source to one service. Exactly one variant is set, by source
// type: ServiceName (tempo, resource.service.name), Script (cloudflare).
type TraceBinding struct {
	Source      *Source
	ServiceName string
	Script      string
}

func (b *TraceBinding) Dialect() api.Dialect {
	switch b.Source.Type {
	case SourceTempo:
		return api.DialectTraceQL
	case SourceCloudflare:
		return api.DialectCloudflareQuery
	}
	return ""
}

// WorkloadBinding scopes a Kubernetes source to the pods and ReplicaSets in Namespace that
// carry all of Labels.
type WorkloadBinding struct {
	Source    *Source
	Namespace string
	Labels    map[string]string
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
	if e.Traces != nil {
		caps = append(caps, api.CapabilityTraces)
	}
	if e.Workloads != nil {
		caps = append(caps, api.CapabilityWorkloads)
	}
	return caps
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
