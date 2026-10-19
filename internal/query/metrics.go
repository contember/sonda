package query

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

const (
	defaultSince   = time.Hour
	maxSeries      = 30
	maxPoints      = 60
	maxMetricNames = 500
)

var seriesUntrusted = []string{"data.series[].labels"}

func (s *Service) metricScope(identity *authz.Identity, service, env string) (authz.MetricScope, metricBackend, error) {
	scope, err := s.authz.MetricScope(identity, service, env)
	if err != nil {
		return authz.MetricScope{}, nil, err
	}
	backend, err := s.metricBackend(scope)
	if err != nil {
		return authz.MetricScope{}, nil, err
	}
	return scope, backend, nil
}

func (s *Service) MetricNames(ctx context.Context, identity *authz.Identity, service string, w api.Window, filter string) (api.Response[[]api.MetricInfo], error) {
	scope, backend, err := s.metricScope(identity, service, w.Environment)
	if err != nil {
		return api.Response[[]api.MetricInfo]{}, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return api.Response[[]api.MetricInfo]{}, err
	}
	all, err := backend.names(ctx, r)
	if err != nil {
		return api.Response[[]api.MetricInfo]{}, err
	}

	var infos []api.MetricInfo
	for _, info := range all {
		if filter != "" && !strings.Contains(info.Name, filter) {
			continue
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	meta := metaFor(scope.Target, r)
	if len(infos) > maxMetricNames {
		infos, meta.Truncated = infos[:maxMetricNames], true
	}
	return api.Response[[]api.MetricInfo]{Data: infos, Meta: meta}, nil
}

// Signal runs a named query of the service, stored in the dialect of its metrics source.
func (s *Service) Signal(ctx context.Context, identity *authz.Identity, service, signal string, w api.Window, step string, withPoints bool) (api.Response[api.MetricResult], error) {
	svc, err := s.authz.Service(identity, service)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	sig, ok := svc.Signals[signal]
	if !ok {
		return api.Response[api.MetricResult]{}, apierr.NotFound("signal %q is not defined for service %q", signal, service)
	}
	scope, backend, err := s.metricScope(identity, service, w.Environment)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	// The config check makes every metrics environment of a service with signals share one dialect.
	if sig.Dialect != backend.dialect() {
		return api.Response[api.MetricResult]{}, fmt.Errorf("signal %s of service %s is %s, but the metrics source uses %s", signal, service, sig.Dialect, backend.dialect())
	}
	return s.queryMetrics(ctx, identity, scope, backend, api.MetricQueryRequest{Window: w, Query: sig.Query, Step: step}, withPoints)
}

func (s *Service) QueryMetrics(ctx context.Context, identity *authz.Identity, service string, req api.MetricQueryRequest, withPoints bool) (api.Response[api.MetricResult], error) {
	scope, backend, err := s.metricScope(identity, service, req.Environment)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	return s.queryMetrics(ctx, identity, scope, backend, req, withPoints)
}

func (s *Service) queryMetrics(ctx context.Context, identity *authz.Identity, scope authz.MetricScope, backend metricBackend, req api.MetricQueryRequest, withPoints bool) (api.Response[api.MetricResult], error) {
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	step, err := policy.ParseStep(req.Step, r, maxPoints)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	result, err := backend.query(ctx, r, req.Query, step)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	if result.step != 0 {
		step = result.step
	}
	series, truncated := shape.Series(result.series, maxSeries, withPoints)
	meta := metaFor(scope.Target, r)
	meta.Truncated = truncated
	meta.Sources = []api.SourceRef{result.source}
	meta.Untrusted = seriesUntrusted
	return api.Response[api.MetricResult]{
		Data: api.MetricResult{Query: result.query, Step: step.String(), Series: series},
		Meta: meta,
	}, nil
}

func metaFor(target authz.Target, r api.TimeRange) api.Meta {
	return api.Meta{Service: target.Service(), Environment: target.Environment(), Range: &r}
}
