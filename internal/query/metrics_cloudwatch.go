package query

import (
	"context"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/aws"
)

type cloudWatchMetrics struct {
	scope  authz.CloudWatchMetricScope
	client *aws.Client
}

func newCloudWatchMetrics(scope authz.CloudWatchMetricScope, client *aws.Client) metricBackend {
	return &cloudWatchMetrics{scope: scope, client: client}
}

func (b *cloudWatchMetrics) dialect() api.Dialect { return api.DialectCloudWatchMetric }

func (b *cloudWatchMetrics) names(ctx context.Context, r api.TimeRange) ([]api.MetricInfo, error) {
	return nil, notImplemented(b.dialect())
}

func (b *cloudWatchMetrics) query(ctx context.Context, r api.TimeRange, text string, step time.Duration) (metricQuery, error) {
	return metricQuery{}, notImplemented(b.dialect())
}
