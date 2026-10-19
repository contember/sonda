package query

import (
	"context"
	"encoding/json"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/shape"
	"github.com/contember/sonda/internal/telemetry"
)

// cloudflareMetricHelp describes the catalog in telemetry.CloudflareMetrics. Values are per time bucket.
var cloudflareMetricHelp = map[string]string{
	"requests":     "Invocations of the Worker (sum)",
	"errors":       "Invocations that ended with an error (sum)",
	"subrequests":  "Subrequests made by the Worker (sum)",
	"cpu_time_p50": "CPU time per invocation, 50th percentile, in microseconds",
	"cpu_time_p99": "CPU time per invocation, 99th percentile, in microseconds",
	"duration_p50": "Request duration per invocation, 50th percentile, in ms",
	"duration_p99": "Request duration per invocation, 99th percentile, in ms",
}

type cloudflareMetrics struct {
	scope  authz.CloudflareScope
	client *cloudflare.Client
}

func newCloudflareMetrics(scope authz.CloudflareScope, client *cloudflare.Client) metricBackend {
	return &cloudflareMetrics{scope: scope, client: client}
}

func (b *cloudflareMetrics) dialect() api.Dialect { return api.DialectCloudflareMetric }

// names returns the fixed catalog; it does not depend on the range.
func (b *cloudflareMetrics) names(context.Context, api.TimeRange) ([]api.MetricInfo, error) {
	infos := make([]api.MetricInfo, 0, len(telemetry.CloudflareMetrics))
	for _, name := range telemetry.CloudflareMetrics {
		infos = append(infos, api.MetricInfo{Name: name, Help: cloudflareMetricHelp[name]})
	}
	return infos, nil
}

func (b *cloudflareMetrics) query(ctx context.Context, r api.TimeRange, text string, step time.Duration) (metricQuery, error) {
	m, err := telemetry.DecodeCloudflareMetricQuery(text)
	if err != nil {
		return metricQuery{}, apierr.InvalidQuery("invalid Cloudflare metric query: %v", err)
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return metricQuery{}, err
	}
	recordQuery(ctx, b.scope.Target, string(canonical))
	matrix, bucket, err := b.client.Metric(ctx, b.scope, m, r, step)
	if err != nil {
		return metricQuery{}, err
	}
	return metricQuery{
		query:  string(canonical),
		series: matrix,
		source: shape.CloudflareSourceRef(b.scope.Source(), string(canonical), r),
		step:   bucket,
	}, nil
}
