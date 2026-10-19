package query

import (
	"context"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/cloudflare"
)

type cloudflareMetrics struct {
	scope  authz.CloudflareScope
	client *cloudflare.Client
}

func newCloudflareMetrics(scope authz.CloudflareScope, client *cloudflare.Client) metricBackend {
	return &cloudflareMetrics{scope: scope, client: client}
}

func (b *cloudflareMetrics) dialect() api.Dialect { return api.DialectCloudflareMetric }

func (b *cloudflareMetrics) names(ctx context.Context, r api.TimeRange) ([]api.MetricInfo, error) {
	return nil, notImplemented(b.dialect())
}

func (b *cloudflareMetrics) query(ctx context.Context, r api.TimeRange, text string, step time.Duration) (metricQuery, error) {
	return metricQuery{}, notImplemented(b.dialect())
}
