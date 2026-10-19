package query

import (
	"context"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/prometheus"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

type prometheusMetrics struct {
	scope   authz.SelectorScope
	client  *prometheus.Client
	grafana *config.Grafana
}

func newPrometheusMetrics(scope authz.SelectorScope, client *prometheus.Client, grafana *config.Grafana) metricBackend {
	return &prometheusMetrics{scope: scope, client: client, grafana: grafana}
}

func (b *prometheusMetrics) dialect() api.Dialect { return api.DialectPromQL }

// names lists the metric names within the scope with type and help from the metadata.
func (b *prometheusMetrics) names(ctx context.Context, r api.TimeRange) ([]api.MetricInfo, error) {
	names, err := b.client.MetricNames(ctx, b.scope, r)
	if err != nil {
		return nil, err
	}
	metadata, err := b.client.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	infos := make([]api.MetricInfo, 0, len(names))
	for _, name := range names {
		info := api.MetricInfo{Name: name}
		if entries := metadata[name]; len(entries) > 0 {
			info.Type, info.Help = string(entries[0].Type), entries[0].Help
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (b *prometheusMetrics) query(ctx context.Context, r api.TimeRange, text string, step time.Duration) (metricQuery, error) {
	q, err := policy.ScopePromQL(b.scope, text)
	if err != nil {
		return metricQuery{}, err
	}
	recordQuery(ctx, b.scope.Target, q.String())
	matrix, err := b.client.QueryRange(ctx, q, r, step)
	if err != nil {
		return metricQuery{}, err
	}
	return metricQuery{query: q.String(), series: matrix, source: shape.SourceRef(b.grafana, b.scope.Source(), q.String(), r)}, nil
}
