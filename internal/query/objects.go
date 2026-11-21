package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
)

var objectsUntrusted = []string{
	"data.controllers[].conditions[].reason", "data.controllers[].conditions[].message",
	"data.autoscalers[].conditions[].reason", "data.autoscalers[].conditions[].message",
	"data.applications[].healthMessage", "data.applications[].operationDetail",
	"data.applications[].conditions[].message",
}

// Objects returns the configuration of the objects that run the service: on Kubernetes its
// controllers and the Services, Ingresses, policies, budgets, autoscalers, ConfigMap keys and
// Argo CD Applications that relate to them; on ECS the service and its task definitions. It is
// the current state; there is no range.
func (s *Service) Objects(ctx context.Context, identity *authz.Identity, service string, env string) (api.Response[api.WorkloadObjects], error) {
	scope, err := s.authz.WorkloadScope(identity, service, env)
	if err != nil {
		return api.Response[api.WorkloadObjects]{}, err
	}
	backend, err := s.workloadBackend(scope)
	if err != nil {
		return api.Response[api.WorkloadObjects]{}, err
	}
	state, err := backend.objects(ctx)
	if err != nil {
		return api.Response[api.WorkloadObjects]{}, err
	}
	meta := api.Meta{Service: scope.Service(), Environment: scope.Environment()}
	meta.Sources = []api.SourceRef{state.source}
	meta.Untrusted = objectsUntrusted
	meta.Truncated = state.truncated
	return api.Response[api.WorkloadObjects]{Data: state.data, Meta: meta}, nil
}
