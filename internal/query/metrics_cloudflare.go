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

// cloudflareMetricHelp describes the catalog in telemetry.CloudflareMetrics. Values are per time
// bucket; metrics of bound resources have one series per resource, labeled by its name.
var cloudflareMetricHelp = map[string]string{
	"requests":     "Invocations of the Worker (sum)",
	"errors":       "Invocations that ended with an error (sum)",
	"subrequests":  "Subrequests made by the Worker (sum)",
	"cpu_time_p50": "CPU time per invocation, 50th percentile, in microseconds",
	"cpu_time_p99": "CPU time per invocation, 99th percentile, in microseconds",
	"duration_p50": "Request duration per invocation, 50th percentile, in ms",
	"duration_p99": "Request duration per invocation, 99th percentile, in ms",

	"do_requests":               "Durable Object invocations, by namespace (sum)",
	"do_errors":                 "Durable Object invocations that ended with an error, by namespace (sum)",
	"do_wall_time_p50":          "Wall time per Durable Object invocation, 50th percentile, in ms",
	"do_wall_time_p99":          "Wall time per Durable Object invocation, 99th percentile, in ms",
	"do_cpu_time":               "CPU time of Durable Objects, by namespace (sum), in microseconds",
	"do_exceeded_cpu_errors":    "Durable Object CPU limit errors, by namespace (sum)",
	"do_exceeded_memory_errors": "Durable Object memory limit errors, by namespace (sum)",
	"do_fatal_internal_errors":  "Durable Object fatal internal errors, by namespace (sum)",
	"do_sql_rows_read":          "Rows read by SQLite-backed Durable Objects, by namespace (sum)",
	"do_sql_rows_written":       "Rows written by SQLite-backed Durable Objects, by namespace (sum)",
	"do_sql_stored_bytes":       "SQLite storage of Durable Objects, by namespace (max), in bytes",

	"d1_read_queries":   "D1 read queries, by database (sum)",
	"d1_write_queries":  "D1 write queries, by database (sum)",
	"d1_rows_read":      "D1 rows read, by database (sum)",
	"d1_rows_written":   "D1 rows written, by database (sum)",
	"d1_query_time_p50": "D1 query batch time, 50th percentile, in ms",
	"d1_query_time_p99": "D1 query batch time, 99th percentile, in ms",

	"queue_backlog_messages":     "Messages in the queue backlog, by queue (avg)",
	"queue_backlog_bytes":        "Size of the queue backlog, by queue (avg), in bytes",
	"queue_consumer_concurrency": "Concurrent queue consumers, by queue (avg)",
	"queue_operations":           "Billable queue message operations, by queue (sum)",
	"queue_lag_time":             "Time from writing a message to reading or deleting it, by queue (avg), in ms",
	"queue_retries":              "Retries per read or delete operation, by queue (avg)",

	"r2_requests":     "R2 operations, by bucket (sum)",
	"r2_stored_bytes": "R2 payload size, by bucket and storage class (max), in bytes",
	"r2_objects":      "R2 objects, by bucket and storage class (max)",
}

type cloudflareMetrics struct {
	scope  authz.CloudflareScope
	client *cloudflare.Client
}

func newCloudflareMetrics(scope authz.CloudflareScope, client *cloudflare.Client) metricBackend {
	return &cloudflareMetrics{scope: scope, client: client}
}

func (b *cloudflareMetrics) dialect() api.Dialect { return api.DialectCloudflareMetric }

// names returns the catalog entries of the script and of the bound resource kinds; it does
// not depend on the range.
func (b *cloudflareMetrics) names(context.Context, api.TimeRange) ([]api.MetricInfo, error) {
	var infos []api.MetricInfo
	for name, metric := range telemetry.CloudflareMetrics {
		if metric.Resource == telemetry.CloudflareScript || len(b.scope.Resources(metric.Resource)) > 0 {
			infos = append(infos, api.MetricInfo{Name: name, Help: cloudflareMetricHelp[name]})
		}
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
