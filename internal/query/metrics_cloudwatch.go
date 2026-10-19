package query

import (
	"context"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

type cloudWatchMetrics struct {
	scope  authz.CloudWatchMetricScope
	client *aws.Client
}

func newCloudWatchMetrics(scope authz.CloudWatchMetricScope, client *aws.Client) metricBackend {
	return &cloudWatchMetrics{scope: scope, client: client}
}

func (b *cloudWatchMetrics) dialect() api.Dialect { return api.DialectCloudWatchMetric }

// names ignores the range: ListMetrics reports metrics with data in the last two weeks.
func (b *cloudWatchMetrics) names(ctx context.Context, r api.TimeRange) ([]api.MetricInfo, error) {
	names, err := b.client.MetricNames(ctx, b.scope)
	if err != nil {
		return nil, err
	}
	infos := make([]api.MetricInfo, 0, len(names))
	for _, name := range names {
		infos = append(infos, api.MetricInfo{Name: name})
	}
	return infos, nil
}

func (b *cloudWatchMetrics) query(ctx context.Context, r api.TimeRange, text string, step time.Duration) (metricQuery, error) {
	q, err := policy.ScopeCloudWatchMetric(b.scope, text)
	if err != nil {
		return metricQuery{}, err
	}
	recordQuery(ctx, b.scope.Target, q.String())
	matrix, err := b.client.MetricData(ctx, q, r, step)
	if err != nil {
		return metricQuery{}, err
	}
	return metricQuery{query: q.String(), series: matrix, source: shape.CloudWatchMetricSourceRef(q.String())}, nil
}
