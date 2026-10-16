// Package authz authenticates identities and resolves their grants into scopes.
// A scope is the only way to reach a source, a Sentry project or a label selector.
package authz

import (
	"crypto/sha256"
	"crypto/subtle"
	"slices"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
)

type Authorizer struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Authorizer {
	return &Authorizer{cfg: cfg}
}

func (a *Authorizer) Authenticate(token string) (*config.Identity, bool) {
	hash := sha256.Sum256([]byte(token))
	var found *config.Identity
	// Compare against every identity, so timing does not depend on which one matches.
	for _, identity := range a.cfg.Identities {
		if subtle.ConstantTimeCompare(hash[:], identity.TokenSHA256[:]) == 1 {
			found = identity
		}
	}
	return found, found != nil
}

// Services returns the services the identity has at least one grant for, sorted by name.
func (a *Authorizer) Services(identity *config.Identity) []*config.Service {
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
func (a *Authorizer) Service(identity *config.Identity, name string) (*config.Service, error) {
	svc, ok := a.cfg.Services[name]
	if !ok || len(a.environments(identity, svc)) == 0 {
		return nil, apierr.NotFound("service %q not found", name)
	}
	return svc, nil
}

// Environments returns the granted environments of a service with their granted
// capabilities, sorted by name.
func (a *Authorizer) Environments(identity *config.Identity, svc *config.Service) []api.EnvironmentDetail {
	granted := a.environments(identity, svc)
	names := make([]string, 0, len(granted))
	for name := range granted {
		names = append(names, name)
	}
	sort.Strings(names)
	details := make([]api.EnvironmentDetail, 0, len(names))
	for _, name := range names {
		details = append(details, api.EnvironmentDetail{Name: name, Capabilities: granted[name]})
	}
	return details
}

// environments maps each granted environment to the capabilities that are both granted
// and configured.
func (a *Authorizer) environments(identity *config.Identity, svc *config.Service) map[string][]api.Capability {
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

func (a *Authorizer) granted(identity *config.Identity, service, env string, capability api.Capability) bool {
	return slices.ContainsFunc(identity.Grants, func(g config.Grant) bool {
		return slices.Contains(g.Services, service) &&
			slices.Contains(g.Environments, env) &&
			slices.Contains(g.Capabilities, capability)
	})
}

// resolve finds the environment for a capability. An empty environment name is allowed
// when exactly one granted environment offers the capability.
func (a *Authorizer) resolve(identity *config.Identity, service, envName string, capability api.Capability) (Target, *config.Environment, error) {
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

func (a *Authorizer) ErrorScope(identity *config.Identity, service, env string) (ErrorScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityErrors)
	if err != nil {
		return ErrorScope{}, err
	}
	return ErrorScope{Target: target, binding: environment.Errors}, nil
}

func (a *Authorizer) LogScope(identity *config.Identity, service, env string) (SelectorScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityLogs)
	if err != nil {
		return SelectorScope{}, err
	}
	return SelectorScope{Target: target, binding: environment.Logs}, nil
}

func (a *Authorizer) MetricScope(identity *config.Identity, service, env string) (SelectorScope, error) {
	target, environment, err := a.resolve(identity, service, env, api.CapabilityMetrics)
	if err != nil {
		return SelectorScope{}, err
	}
	return SelectorScope{Target: target, binding: environment.Metrics}, nil
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
	binding *config.SelectorBinding
}

func (s SelectorScope) Source() *config.Source { return s.binding.Source }

// Matchers returns a deep copy, so callers cannot change the scope.
func (s SelectorScope) Matchers() []*labels.Matcher {
	matchers := make([]*labels.Matcher, len(s.binding.Matchers))
	for i, m := range s.binding.Matchers {
		matchers[i] = labels.MustNewMatcher(m.Type, m.Name, m.Value)
	}
	return matchers
}

func (s SelectorScope) Selector() string {
	parts := make([]string, len(s.binding.Matchers))
	for i, m := range s.binding.Matchers {
		parts[i] = m.String()
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
