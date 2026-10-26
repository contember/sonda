// Package authz authenticates identities and resolves their grants into scopes.
// A scope is the only way to reach a source, a Sentry project or a label selector.
package authz

import (
	"context"
	"crypto/sha256"
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/telemetry"
)

type Authorizer struct {
	cfg        *config.Config
	identities identities.Store
}

func New(cfg *config.Config, store identities.Store) *Authorizer {
	return &Authorizer{cfg: cfg, identities: store}
}

// Identity is an authenticated identity with its effective limits.
type Identity struct {
	Name   string
	Grants []identities.Grant
	Limits config.Limits
}

// Authenticate looks the identity up by the token's SHA-256. The lookup needs no
// constant-time compare: timing can reveal at most the hash, not the token.
func (a *Authorizer) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, unauthenticated()
	}
	stored, err := a.identities.FindByTokenHash(ctx, sha256.Sum256([]byte(token)))
	if errors.Is(err, identities.ErrNotFound) {
		return nil, unauthenticated()
	}
	if err != nil {
		return nil, err
	}
	return &Identity{Name: stored.Name, Grants: stored.Grants, Limits: stored.Limits.Apply(a.cfg.Limits)}, nil
}

func unauthenticated() error {
	return apierr.New(api.CodeUnauthenticated, "missing or invalid bearer token")
}

// Services returns the services the identity has at least one grant for, sorted by name.
func (a *Authorizer) Services(identity *Identity) []*config.Service {
	var services []*config.Service
	for _, svc := range a.cfg.Services {
		if len(a.environments(identity, svc)) > 0 {
			services = append(services, svc)
		}
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services
}

// Service returns the service if the identity has any grant for it. An unknown service and
// a service without a grant return the same error.
func (a *Authorizer) Service(identity *Identity, name string) (*config.Service, error) {
	svc, ok := a.cfg.Services[name]
	if !ok || len(a.environments(identity, svc)) == 0 {
		return nil, apierr.NotFound("service %q not found", name)
	}
	return svc, nil
}

// Environments returns the granted environments of a service with their granted
// capabilities, sorted by name.
func (a *Authorizer) Environments(identity *Identity, svc *config.Service) []api.EnvironmentDetail {
	granted := a.environments(identity, svc)
	names := make([]string, 0, len(granted))
	for name := range granted {
		names = append(names, name)
	}
	sort.Strings(names)
	details := make([]api.EnvironmentDetail, 0, len(names))
	for _, name := range names {
		details = append(details, api.EnvironmentDetail{
			Name:         name,
			Capabilities: granted[name],
			Backends:     backends(svc.Environments[name], granted[name]),
		})
	}
	return details
}

func backends(env *config.Environment, capabilities []api.Capability) map[api.Capability]api.BackendInfo {
	result := make(map[api.Capability]api.BackendInfo, len(capabilities))
	for _, capability := range capabilities {
		switch capability {
		case api.CapabilityErrors:
			result[capability] = api.BackendInfo{Source: string(env.Errors.Source.Type)}
		case api.CapabilityLogs:
			result[capability] = api.BackendInfo{Source: string(env.Logs.Source.Type), Dialect: env.Logs.Dialect()}
		case api.CapabilityMetrics:
			result[capability] = api.BackendInfo{Source: string(env.Metrics.Source.Type), Dialect: env.Metrics.Dialect()}
		case api.CapabilityTraces:
			result[capability] = api.BackendInfo{Source: string(env.Traces.Source.Type), Dialect: env.Traces.Dialect()}
		case api.CapabilityWorkloads:
			result[capability] = api.BackendInfo{Source: string(env.Workloads.Source.Type)}
		}
	}
	return result
}

// environments maps each granted environment to the capabilities that are both granted
// and configured.
func (a *Authorizer) environments(identity *Identity, svc *config.Service) map[string][]api.Capability {
	result := map[string][]api.Capability{}
	for envName, env := range svc.Environments {
		for _, capability := range env.Capabilities() {
			if a.granted(identity, svc.Name, envName, capability) {
				result[envName] = append(result[envName], capability)
			}
		}
	}
	return result
}

func (a *Authorizer) granted(identity *Identity, service, env string, capability api.Capability) bool {
	return slices.Contains(identity.Grants, identities.Grant{Service: service, Environment: env, Capability: capability})
}

// resolve finds the environment for a capability. An empty environment name is allowed
// when exactly one granted environment offers the capability.
func (a *Authorizer) resolve(identity *Identity, service, envName string, capability api.Capability) (Target, *config.Environment, error) {
	svc, err := a.Service(identity, service)
	if err != nil {
		return Target{}, nil, err
	}
	var candidates []string
	for name, caps := range a.environments(identity, svc) {
		if slices.Contains(caps, capability) {
			candidates = append(candidates, name)
		}
	}
	sort.Strings(candidates)
	if envName == "" {
		switch len(candidates) {
		case 0:
			return Target{}, nil, apierr.NotFound("capability %s is not available for service %q", capability, service)
		case 1:
			envName = candidates[0]
		default:
			return Target{}, nil, apierr.InvalidRequest("environment is required for service %q, one of: %s", service, strings.Join(candidates, ", "))
		}
	}
	if !slices.Contains(candidates, envName) {
		return Target{}, nil, apierr.NotFound("capability %s is not available for %s/%s", capability, service, envName)
	}
	return Target{service: service, environment: envName}, svc.Environments[envName], nil
}

func (a *Authorizer) ErrorScope(identity *Identity, service, env string) (ErrorScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityErrors)
	if err != nil {
		return ErrorScope{}, err
	}
	return ErrorScope{Target: target, binding: environment.Errors}, nil
}

func (a *Authorizer) LogScope(identity *Identity, service, env string) (LogScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityLogs)
	if err != nil {
		return LogScope{}, err
	}
	return LogScope{Target: target, binding: environment.Logs}, nil
}

func (a *Authorizer) MetricScope(identity *Identity, service, env string) (MetricScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityMetrics)
	if err != nil {
		return MetricScope{}, err
	}
	return MetricScope{Target: target, binding: environment.Metrics}, nil
}

func (a *Authorizer) TraceScope(identity *Identity, service, env string) (TraceScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityTraces)
	if err != nil {
		return TraceScope{}, err
	}
	return TraceScope{Target: target, binding: environment.Traces}, nil
}

func (a *Authorizer) WorkloadScope(identity *Identity, service, env string) (WorkloadScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityWorkloads)
	if err != nil {
		return WorkloadScope{}, err
	}
	return WorkloadScope{Target: target, binding: environment.Workloads}, nil
}

// TraceVisibility reports which backend service names of the scope's source the identity may see in
// full: names of trace bindings on the same source, in any service and environment the identity has a
// traces grant for.
func (a *Authorizer) TraceVisibility(identity *Identity, scope TraceScope) func(service string) bool {
	visible := map[string]bool{}
	for _, svc := range a.cfg.Services {
		for envName, env := range svc.Environments {
			if env.Traces == nil || env.Traces.Source != scope.Source() {
				continue
			}
			if a.granted(identity, svc.Name, envName, api.CapabilityTraces) {
				visible[traceServiceName(env.Traces)] = true
			}
		}
	}
	return func(service string) bool { return visible[service] }
}

type Target struct {
	service     string
	environment string
}

func (t Target) Service() string     { return t.service }
func (t Target) Environment() string { return t.environment }

type ErrorScope struct {
	Target
	binding *config.ErrorBinding
}

func (s ErrorScope) Source() *config.Source    { return s.binding.Source }
func (s ErrorScope) Project() string           { return s.binding.Project }
func (s ErrorScope) SentryEnvironment() string { return s.binding.Environment }

// SelectorScope restricts a Loki or Prometheus source to the service's label selector.
type SelectorScope struct {
	Target
	source   *config.Source
	selector *config.Selector
}

func (s SelectorScope) Source() *config.Source { return s.source }

// Matchers returns a deep copy, so callers cannot change the scope.
func (s SelectorScope) Matchers() []*labels.Matcher {
	matchers := make([]*labels.Matcher, len(s.selector.Matchers))
	for i, m := range s.selector.Matchers {
		matchers[i] = labels.MustNewMatcher(m.Type, m.Name, m.Value)
	}
	return matchers
}

func (s SelectorScope) Selector() string {
	parts := make([]string, len(s.selector.Matchers))
	for i, m := range s.selector.Matchers {
		parts[i] = m.String()
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// LogScope restricts a log source to one service. Exactly one of Loki, Cloudflare and
// CloudWatch reports true, by source type.
type LogScope struct {
	Target
	binding *config.LogBinding
}

func (s LogScope) Source() *config.Source { return s.binding.Source }
func (s LogScope) Dialect() api.Dialect   { return s.binding.Dialect() }

func (s LogScope) Loki() (SelectorScope, bool) {
	if s.binding.Source.Type != config.SourceLoki {
		return SelectorScope{}, false
	}
	return SelectorScope{Target: s.Target, source: s.binding.Source, selector: s.binding.Selector}, true
}

func (s LogScope) Cloudflare() (CloudflareScope, bool) {
	if s.binding.Source.Type != config.SourceCloudflare {
		return CloudflareScope{}, false
	}
	return CloudflareScope{Target: s.Target, source: s.binding.Source, script: s.binding.Script}, true
}

func (s LogScope) CloudWatch() (LogGroupScope, bool) {
	if s.binding.Source.Type != config.SourceAWS {
		return LogGroupScope{}, false
	}
	return LogGroupScope{Target: s.Target, source: s.binding.Source, groups: s.binding.LogGroups}, true
}

// MetricScope restricts a metrics source to one service. Exactly one of Prometheus,
// Cloudflare and CloudWatch reports true, by source type.
type MetricScope struct {
	Target
	binding *config.MetricBinding
}

func (s MetricScope) Source() *config.Source { return s.binding.Source }
func (s MetricScope) Dialect() api.Dialect   { return s.binding.Dialect() }

func (s MetricScope) Prometheus() (SelectorScope, bool) {
	if s.binding.Source.Type != config.SourcePrometheus {
		return SelectorScope{}, false
	}
	return SelectorScope{Target: s.Target, source: s.binding.Source, selector: s.binding.Selector}, true
}

func (s MetricScope) Cloudflare() (CloudflareScope, bool) {
	if s.binding.Source.Type != config.SourceCloudflare {
		return CloudflareScope{}, false
	}
	return CloudflareScope{Target: s.Target, source: s.binding.Source, script: s.binding.Script, resources: s.binding.CloudflareResources}, true
}

func (s MetricScope) CloudWatch() (CloudWatchMetricScope, bool) {
	if s.binding.Source.Type != config.SourceAWS {
		return CloudWatchMetricScope{}, false
	}
	return CloudWatchMetricScope{
		Target:     s.Target,
		source:     s.binding.Source,
		namespace:  s.binding.Namespace,
		dimensions: s.binding.Dimensions,
	}, true
}

// TraceScope restricts a trace source to one service. Exactly one of Tempo and Cloudflare
// reports true, by source type.
type TraceScope struct {
	Target
	binding *config.TraceBinding
}

func (s TraceScope) Source() *config.Source { return s.binding.Source }
func (s TraceScope) Dialect() api.Dialect   { return s.binding.Dialect() }

// ServiceName is the name the backend records spans of this service under.
func (s TraceScope) ServiceName() string { return traceServiceName(s.binding) }

func (s TraceScope) Tempo() (TempoScope, bool) {
	if s.binding.Source.Type != config.SourceTempo {
		return TempoScope{}, false
	}
	return TempoScope{Target: s.Target, source: s.binding.Source, serviceName: s.binding.ServiceName}, true
}

func (s TraceScope) Cloudflare() (CloudflareScope, bool) {
	if s.binding.Source.Type != config.SourceCloudflare {
		return CloudflareScope{}, false
	}
	return CloudflareScope{Target: s.Target, source: s.binding.Source, script: s.binding.Script}, true
}

func traceServiceName(b *config.TraceBinding) string {
	if b.Source.Type == config.SourceCloudflare {
		return b.Script
	}
	return b.ServiceName
}

// CloudflareScope restricts a Cloudflare account to one Worker script and, for metrics, to
// the account resources bound to the service.
type CloudflareScope struct {
	Target
	source    *config.Source
	script    string
	resources map[telemetry.CloudflareResource]map[string]string
}

func (s CloudflareScope) Source() *config.Source { return s.source }
func (s CloudflareScope) AccountID() string      { return s.source.CloudflareAccountID }
func (s CloudflareScope) Script() string         { return s.script }

// Resources returns a copy of the bound resources of the kind, by name; empty if none are bound.
func (s CloudflareScope) Resources(kind telemetry.CloudflareResource) map[string]string {
	return maps.Clone(s.resources[kind])
}

// WorkloadScope restricts a Kubernetes cluster to the objects of one namespace that carry
// all of the service's labels.
type WorkloadScope struct {
	Target
	binding *config.WorkloadBinding
}

func (s WorkloadScope) Source() *config.Source { return s.binding.Source }
func (s WorkloadScope) Namespace() string      { return s.binding.Namespace }

// Labels returns a copy, so callers cannot change the scope.
func (s WorkloadScope) Labels() map[string]string { return maps.Clone(s.binding.Labels) }

// LogGroupScope restricts an AWS account to the service's CloudWatch log groups.
type LogGroupScope struct {
	Target
	source *config.Source
	groups []string
}

func (s LogGroupScope) Source() *config.Source { return s.source }

// LogGroups returns a copy, so callers cannot change the scope.
func (s LogGroupScope) LogGroups() []string { return slices.Clone(s.groups) }

// CloudWatchMetricScope restricts an AWS account to one metric namespace and the service's
// dimensions.
type CloudWatchMetricScope struct {
	Target
	source     *config.Source
	namespace  string
	dimensions map[string]string
}

func (s CloudWatchMetricScope) Source() *config.Source { return s.source }
func (s CloudWatchMetricScope) Namespace() string      { return s.namespace }

// Dimensions returns a copy, so callers cannot change the scope.
func (s CloudWatchMetricScope) Dimensions() map[string]string { return maps.Clone(s.dimensions) }

// TempoScope restricts a Tempo source to spans of one resource.service.name.
type TempoScope struct {
	Target
	source      *config.Source
	serviceName string
}

func (s TempoScope) Source() *config.Source { return s.source }
func (s TempoScope) ServiceName() string    { return s.serviceName }
