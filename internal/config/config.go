// Package config loads and validates the Sonda server configuration.
// The YAML file is parsed into raw structs first, then validated into the typed Config.
package config

import (
	"crypto/x509"
	"slices"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/telemetry"
)

type Config struct {
	Server   Server
	Admin    *Admin
	Identity *Identity
	Grafana  *Grafana
	Sources  map[string]*Source
	Projects map[string]*Project
	// Services holds the services of all projects; service names are unique across projects.
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

// Identity makes Sonda an OIDC issuer of its own workload identity at Issuer, the public
// https URL of this Sonda, so cloud providers can trust Sonda without long-lived credentials.
type Identity struct {
	Issuer string
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
	SourceGrafana    SourceType = "grafana"
	SourceVercel     SourceType = "vercel"
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
	// VercelTeamID is set for Vercel sources only.
	VercelTeamID string
	// AWS is set for AWS sources only.
	AWS *AWSSource
	// RootCAs verifies the server certificate instead of the system roots when set.
	RootCAs *x509.CertPool
}

type AWSSource struct {
	Region      string
	Credentials AWSCredentials
	RoleARN     string // optional with the default credential chain; required with the identity
	ExternalID  string // optional, only with RoleARN and the default credential chain
	// MaxScanBytes stops a Logs Insights query that scans more, because scanning is billed.
	MaxScanBytes int64
}

// AWSCredentials selects what an AWS source authenticates with.
type AWSCredentials string

const (
	// AWSDefaultChain uses the default credential chain, then assumes RoleARN when set.
	AWSDefaultChain AWSCredentials = "default"
	// AWSIdentity assumes RoleARN with a token of Sonda's own identity (AssumeRoleWithWebIdentity).
	AWSIdentity AWSCredentials = "identity"
)

type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBearer AuthType = "bearer"
	AuthBasic  AuthType = "basic"
	// AuthEKS sends an EKS bearer token signed with the credentials of an AWS source.
	AuthEKS AuthType = "eks"
)

type Auth struct {
	Type  AuthType
	Token string
	// TokenFile is read on every request instead of Token, because Kubernetes rotates
	// projected service account tokens. It is set only for in-cluster Kubernetes sources.
	TokenFile string
	Username  string
	Password  string
	// EKS is set for eks auth only.
	EKS *EKSAuth
}

// EKSAuth authenticates to the Kubernetes API of an EKS cluster, directly or through its
// service proxy, as the IAM principal of an AWS source.
type EKSAuth struct {
	Cluster string
	// AWS is the aws source whose credentials sign the token; its region is the cluster's.
	AWS *Source
}

// Project groups the services of one product. Identities are granted access per project, so
// a grant covers every service of the project that configures the granted capability.
type Project struct {
	Name        string
	Description string
	Services    map[string]*Service
}

// Offers reports whether any service of the project configures the capability in the environment.
func (p *Project) Offers(env string, capability api.Capability) bool {
	for _, svc := range p.Services {
		if e, ok := svc.Environments[env]; ok && slices.Contains(e.Capabilities(), capability) {
			return true
		}
	}
	return false
}

type Service struct {
	Name         string
	Project      *Project
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
	Alerts    *AlertBinding
}

// AlertBinding scopes the alerts of a Prometheus-compatible ruler (Prometheus, Mimir, or
// Grafana-managed alerting) to the alerts whose labels match Selector.
type AlertBinding struct {
	Source   *Source
	Selector *Selector
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
// Selector (loki), Script (cloudflare), LogGroups (aws), Project with Environment (vercel).
type LogBinding struct {
	Source      *Source
	Selector    *Selector
	Script      string
	LogGroups   []string
	Project     string
	Environment string
}

func (b *LogBinding) Dialect() api.Dialect {
	switch b.Source.Type {
	case SourceLoki:
		return api.DialectLogQL
	case SourceCloudflare:
		return api.DialectCloudflareQuery
	case SourceAWS:
		return api.DialectLogsInsights
	case SourceVercel:
		return api.DialectVercelKQL
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
// TraceBinding scopes a trace source to one service. Exactly one variant is set, by source
// type: ServiceName (tempo), Script (cloudflare), Project with Environment (sentry).
type TraceBinding struct {
	Source      *Source
	ServiceName string
	Script      string
	Project     string
	Environment string
}

func (b *TraceBinding) Dialect() api.Dialect {
	switch b.Source.Type {
	case SourceTempo:
		return api.DialectTraceQL
	case SourceCloudflare:
		return api.DialectCloudflareQuery
	case SourceSentry:
		return api.DialectSentrySearch
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
	if e.Alerts != nil {
		caps = append(caps, api.CapabilityAlerts)
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
