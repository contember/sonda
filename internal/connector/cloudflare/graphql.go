package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/telemetry"
)

// maxMetricRows caps the rows of one GraphQL query: time buckets times resources times dimension values.
const maxMetricRows = 10000

// metricQuery reads one dataset of the scoped resources. Only catalog constants are formatted
// into it; the scope and the range are GraphQL variables.
const metricQuery = `query SondaMetric($accountTag: string, $resources: [string!], $datetimeStart: string, $datetimeEnd: string) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      rows: %s(limit: %d, filter: {%s_in: $resources, datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd}, orderBy: [%s_ASC]) {
        %s { %s }
        dimensions { %s }
      }
    }
  }
}`

// dataset is a GraphQL Analytics node and the dimension that identifies its scoped resource.
type dataset struct {
	node     string
	resource telemetry.CloudflareResource
	field    string
	// label names the resource in series labels; empty for the Worker dataset, which reads one script.
	label string
}

var (
	workerInvocations = dataset{"workersInvocationsAdaptive", telemetry.CloudflareScript, "scriptName", ""}
	doInvocations     = dataset{"durableObjectsInvocationsAdaptiveGroups", telemetry.CloudflareDurableObjectNamespaces, "namespaceId", "namespace"}
	doPeriodic        = dataset{"durableObjectsPeriodicGroups", telemetry.CloudflareDurableObjectNamespaces, "namespaceId", "namespace"}
	doSQLStorage      = dataset{"durableObjectsSqlStorageGroups", telemetry.CloudflareDurableObjectNamespaces, "namespaceId", "namespace"}
	d1Analytics       = dataset{"d1AnalyticsAdaptiveGroups", telemetry.CloudflareD1Databases, "databaseId", "database"}
	queueBacklog      = dataset{"queueBacklogAdaptiveGroups", telemetry.CloudflareQueues, "queueId", "queue"}
	queueConsumers    = dataset{"queueConsumerMetricsAdaptiveGroups", telemetry.CloudflareQueues, "queueId", "queue"}
	queueOperations   = dataset{"queueMessageOperationsAdaptiveGroups", telemetry.CloudflareQueues, "queueId", "queue"}
	r2Operations      = dataset{"r2OperationsAdaptiveGroups", telemetry.CloudflareR2Buckets, "bucketName", "bucket"}
	r2Storage         = dataset{"r2StorageAdaptiveGroups", telemetry.CloudflareR2Buckets, "bucketName", "bucket"}
)

const microsecondsAsMilli = 1.0 / 1000

// metricField reads one aggregate of a dataset: block is sum, avg, max or quantiles.
type metricField struct {
	dataset dataset
	block   string
	field   string
	scale   float64
}

var metricFields = map[string]metricField{
	"requests":     {workerInvocations, "sum", "requests", 1},
	"errors":       {workerInvocations, "sum", "errors", 1},
	"subrequests":  {workerInvocations, "sum", "subrequests", 1},
	"cpu_time_p50": {workerInvocations, "quantiles", "cpuTimeP50", 1},
	"cpu_time_p99": {workerInvocations, "quantiles", "cpuTimeP99", 1},
	"duration_p50": {workerInvocations, "quantiles", "requestDurationP50", microsecondsAsMilli},
	"duration_p99": {workerInvocations, "quantiles", "requestDurationP99", microsecondsAsMilli},

	"do_requests":               {doInvocations, "sum", "requests", 1},
	"do_errors":                 {doInvocations, "sum", "errors", 1},
	"do_wall_time_p50":          {doInvocations, "quantiles", "wallTimeP50", microsecondsAsMilli},
	"do_wall_time_p99":          {doInvocations, "quantiles", "wallTimeP99", microsecondsAsMilli},
	"do_cpu_time":               {doPeriodic, "sum", "cpuTime", 1},
	"do_exceeded_cpu_errors":    {doPeriodic, "sum", "exceededCpuErrors", 1},
	"do_exceeded_memory_errors": {doPeriodic, "sum", "exceededMemoryErrors", 1},
	"do_fatal_internal_errors":  {doPeriodic, "sum", "fatalInternalErrors", 1},
	"do_sql_rows_read":          {doPeriodic, "sum", "rowsRead", 1},
	"do_sql_rows_written":       {doPeriodic, "sum", "rowsWritten", 1},
	"do_sql_stored_bytes":       {doSQLStorage, "max", "storedBytes", 1},

	"d1_read_queries":   {d1Analytics, "sum", "readQueries", 1},
	"d1_write_queries":  {d1Analytics, "sum", "writeQueries", 1},
	"d1_rows_read":      {d1Analytics, "sum", "rowsRead", 1},
	"d1_rows_written":   {d1Analytics, "sum", "rowsWritten", 1},
	"d1_query_time_p50": {d1Analytics, "quantiles", "queryBatchTimeMsP50", 1},
	"d1_query_time_p99": {d1Analytics, "quantiles", "queryBatchTimeMsP99", 1},

	"queue_backlog_messages":     {queueBacklog, "avg", "messages", 1},
	"queue_backlog_bytes":        {queueBacklog, "avg", "bytes", 1},
	"queue_consumer_concurrency": {queueConsumers, "avg", "concurrency", 1},
	"queue_operations":           {queueOperations, "sum", "billableOperations", 1},
	"queue_lag_time":             {queueOperations, "avg", "lagTime", 1},
	"queue_retries":              {queueOperations, "avg", "retryCount", 1},

	"r2_requests":     {r2Operations, "sum", "requests", 1},
	"r2_stored_bytes": {r2Storage, "max", "payloadSize", 1},
	"r2_objects":      {r2Storage, "max", "objectCount", 1},
}

type timeBucket struct {
	size   time.Duration
	field  string
	layout string
}

// timeBuckets go from the finest; a query uses the finest bucket not finer than the step, so
// it returns no more points than the step allows. Every dataset in the catalog has them all.
var timeBuckets = []timeBucket{
	{time.Minute, "datetimeMinute", time.RFC3339},
	{15 * time.Minute, "datetimeFifteenMinutes", time.RFC3339},
	{time.Hour, "datetimeHour", time.RFC3339},
	{24 * time.Hour, "date", time.DateOnly},
}

// metricRow holds the selected aggregates and dimensions. Only string dimensions are selected.
type metricRow struct {
	Sum        map[string]float64 `json:"sum"`
	Avg        map[string]float64 `json:"avg"`
	Max        map[string]float64 `json:"max"`
	Quantiles  map[string]float64 `json:"quantiles"`
	Dimensions map[string]string  `json:"dimensions"`
}

func (r metricRow) value(f metricField) float64 {
	blocks := map[string]map[string]float64{"sum": r.Sum, "avg": r.Avg, "max": r.Max, "quantiles": r.Quantiles}
	return blocks[f.block][f.field] * f.scale
}

type graphQLRequest struct {
	Query     string           `json:"query"`
	Variables metricsVariables `json:"variables"`
}

type metricsVariables struct {
	AccountTag    string   `json:"accountTag"`
	Resources     []string `json:"resources"`
	DatetimeStart string   `json:"datetimeStart"`
	DatetimeEnd   string   `json:"datetimeEnd"`
}

type graphQLResponse struct {
	Data *struct {
		Viewer struct {
			Accounts []struct {
				Rows []metricRow `json:"rows"`
			} `json:"accounts"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// Metric reads one catalog metric of the scoped script or resources, with one series per
// resource and value of the requested dimensions. It returns the time bucket it used as the
// effective step.
func (c *Client) Metric(ctx context.Context, scope authz.CloudflareScope, m telemetry.CloudflareMetricQuery, r api.TimeRange, step time.Duration) (model.Matrix, time.Duration, error) {
	field, ok := metricFields[m.Metric]
	if !ok {
		return nil, 0, apierr.InvalidQuery("unknown metric %q", m.Metric)
	}
	ds := field.dataset
	for _, name := range m.By {
		if !slices.Contains(telemetry.CloudflareMetrics[m.Metric].Dimensions, name) {
			return nil, 0, apierr.InvalidQuery("unknown dimension %q of metric %s", name, m.Metric)
		}
	}
	names, err := scopedResources(scope, ds.resource, m.Metric)
	if err != nil {
		return nil, 0, err
	}
	bucket := bucketFor(step)
	dimensions := append([]string{ds.field, bucket.field}, m.By...)
	body, err := json.Marshal(graphQLRequest{
		Query: fmt.Sprintf(metricQuery, ds.node, maxMetricRows, ds.field, bucket.field, field.block, field.field, strings.Join(dimensions, " ")),
		Variables: metricsVariables{
			AccountTag:    scope.AccountID(),
			Resources:     slices.Sorted(maps.Keys(names)),
			DatetimeStart: r.From.UTC().Format(time.RFC3339),
			DatetimeEnd:   r.To.UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		return nil, 0, err
	}
	var resp graphQLResponse
	if err := c.post(ctx, strings.TrimRight(c.source.URL, "/")+"/graphql", body, &resp); err != nil {
		return nil, 0, err
	}
	if len(resp.Errors) > 0 {
		return nil, 0, apierr.Upstream("source %s returned a GraphQL error: %s", c.source.Name, resp.Errors[0].Message)
	}
	if resp.Data == nil {
		return nil, 0, apierr.Upstream("source %s returned no GraphQL data", c.source.Name)
	}
	matrix := newMatrixBuilder()
	for _, account := range resp.Data.Viewer.Accounts {
		if len(account.Rows) >= maxMetricRows {
			return nil, 0, apierr.New(api.CodeLimitExceeded, "too many rows; use a shorter range, a longer step or fewer by dimensions")
		}
		for _, row := range account.Rows {
			name, ok := names[row.Dimensions[ds.field]]
			if !ok {
				return nil, 0, c.outsideScope()
			}
			at, err := time.Parse(bucket.layout, row.Dimensions[bucket.field])
			if err != nil {
				return nil, 0, apierr.Upstream("source %s returned an invalid %s %q", c.source.Name, bucket.field, row.Dimensions[bucket.field])
			}
			labels := model.Metric{}
			if ds.label != "" {
				labels[model.LabelName(ds.label)] = model.LabelValue(name)
			}
			for _, dimension := range m.By {
				labels[model.LabelName(dimension)] = model.LabelValue(row.Dimensions[dimension])
			}
			matrix.add(labels, at, row.value(field))
		}
	}
	return matrix.build(), bucket.size, nil
}

// scopedResources maps the IDs the metric may read to the names that label them in series.
func scopedResources(scope authz.CloudflareScope, kind telemetry.CloudflareResource, metric string) (map[string]string, error) {
	if kind == telemetry.CloudflareScript {
		return map[string]string{scope.Script(): scope.Script()}, nil
	}
	named := scope.Resources(kind)
	if len(named) == 0 {
		return nil, apierr.InvalidQuery("metric %s needs %s in the metrics binding of service %s in %s", metric, kind, scope.Service(), scope.Environment())
	}
	ids := make(map[string]string, len(named))
	for name, id := range named {
		ids[id] = name
	}
	return ids, nil
}

func bucketFor(step time.Duration) timeBucket {
	for _, bucket := range timeBuckets {
		if bucket.size >= step {
			return bucket
		}
	}
	return timeBuckets[len(timeBuckets)-1]
}
