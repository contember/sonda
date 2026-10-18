package query

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/prometheus"
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

func (s *Service) metricScope(identity *authz.Identity, service, env string) (authz.SelectorScope, *prometheus.Client, error) {
	scope, err := s.authz.MetricScope(identity, service, env)
	if err != nil {
		return authz.SelectorScope{}, nil, err
	}
	return scope, s.connectors.Prometheus[scope.Source().Name], nil
}

func (s *Service) MetricNames(ctx context.Context, identity *authz.Identity, service string, w api.Window, filter string) (api.Response[[]api.MetricInfo], error) {
	scope, client, err := s.metricScope(identity, service, w.Environment)
	if err != nil {
		return api.Response[[]api.MetricInfo]{}, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return api.Response[[]api.MetricInfo]{}, err
	}
	names, err := client.MetricNames(ctx, scope, r)
	if err != nil {
		return api.Response[[]api.MetricInfo]{}, err
	}
	metadata, err := client.Metadata(ctx)
	if err != nil {
		return api.Response[[]api.MetricInfo]{}, err
	}

	var infos []api.MetricInfo
	for _, name := range names {
		if filter != "" && !strings.Contains(name, filter) {
			continue
		}
		info := api.MetricInfo{Name: name}
		if entries := metadata[name]; len(entries) > 0 {
			info.Type, info.Help = string(entries[0].Type), entries[0].Help
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

func (s *Service) Signal(ctx context.Context, identity *authz.Identity, service, signal string, w api.Window, step string, withPoints bool) (api.Response[api.MetricResult], error) {
	svc, err := s.authz.Service(identity, service)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	expr, ok := svc.Signals[signal]
	if !ok {
		return api.Response[api.MetricResult]{}, apierr.NotFound("signal %q is not defined for service %q", signal, service)
	}
	return s.QueryMetrics(ctx, identity, service, api.MetricQueryRequest{Window: w, Query: expr, Step: step}, withPoints)
}

func (s *Service) QueryMetrics(ctx context.Context, identity *authz.Identity, service string, req api.MetricQueryRequest, withPoints bool) (api.Response[api.MetricResult], error) {
	scope, client, err := s.metricScope(identity, service, req.Environment)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	step, err := policy.ParseStep(req.Step, r, maxPoints)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	q, err := policy.ScopePromQL(scope, req.Query)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	recordQuery(ctx, scope.Target, q.String())
	matrix, err := client.QueryRange(ctx, q, r, step)
	if err != nil {
		return api.Response[api.MetricResult]{}, err
	}
	series, truncated := shape.Series(matrix, maxSeries, withPoints)
	meta := metaFor(scope.Target, r)
	meta.Truncated = truncated
	meta.Sources = []api.SourceRef{shape.SourceRef(s.cfg.Grafana, scope.Source(), q.String(), r)}
	meta.Untrusted = seriesUntrusted
	return api.Response[api.MetricResult]{
		Data: api.MetricResult{Query: q.String(), Step: step.String(), Series: series},
		Meta: meta,
	}, nil
}

func metaFor(target authz.Target, r api.TimeRange) api.Meta {
	return api.Meta{Service: target.Service(), Environment: target.Environment(), Range: &r}
}
