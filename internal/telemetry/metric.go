package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// CloudflareResource is a kind of Cloudflare resource a metrics binding scopes. Except for the
// script, the value is the name of the binding field that maps resource names to IDs.
type CloudflareResource string

const (
	CloudflareScript                  CloudflareResource = "script"
	CloudflareDurableObjectNamespaces CloudflareResource = "durable_object_namespaces"
	CloudflareD1Databases             CloudflareResource = "d1_databases"
	CloudflareQueues                  CloudflareResource = "queues"
	CloudflareR2Buckets               CloudflareResource = "r2_buckets"
)

// CloudflareBoundResources are the resource kinds a metrics binding maps by name.
var CloudflareBoundResources = []CloudflareResource{
	CloudflareDurableObjectNamespaces, CloudflareD1Databases, CloudflareQueues, CloudflareR2Buckets,
}

// CloudflareMetric is a catalog entry: the resource kind it reads and the dimensions it can
// be split by. Dimensions are GraphQL field names of the metric's dataset.
type CloudflareMetric struct {
	Resource   CloudflareResource
	Dimensions []string
}

// CloudflareMetrics is the catalog over Cloudflare GraphQL Analytics. The Cloudflare
// connector maps each name to a GraphQL dataset and field; keep the names stable.
var CloudflareMetrics = map[string]CloudflareMetric{
	"requests":     {CloudflareScript, workerDimensions},
	"errors":       {CloudflareScript, workerDimensions},
	"subrequests":  {CloudflareScript, workerDimensions},
	"cpu_time_p50": {CloudflareScript, workerDimensions},
	"cpu_time_p99": {CloudflareScript, workerDimensions},
	"duration_p50": {CloudflareScript, workerDimensions},
	"duration_p99": {CloudflareScript, workerDimensions},

	"do_requests":               {CloudflareDurableObjectNamespaces, []string{"status"}},
	"do_errors":                 {CloudflareDurableObjectNamespaces, []string{"status"}},
	"do_wall_time_p50":          {CloudflareDurableObjectNamespaces, []string{"status"}},
	"do_wall_time_p99":          {CloudflareDurableObjectNamespaces, []string{"status"}},
	"do_cpu_time":               {CloudflareDurableObjectNamespaces, nil},
	"do_exceeded_cpu_errors":    {CloudflareDurableObjectNamespaces, nil},
	"do_exceeded_memory_errors": {CloudflareDurableObjectNamespaces, nil},
	"do_fatal_internal_errors":  {CloudflareDurableObjectNamespaces, nil},
	"do_sql_rows_read":          {CloudflareDurableObjectNamespaces, nil},
	"do_sql_rows_written":       {CloudflareDurableObjectNamespaces, nil},
	"do_sql_stored_bytes":       {CloudflareDurableObjectNamespaces, nil},

	"d1_read_queries":   {CloudflareD1Databases, d1Dimensions},
	"d1_write_queries":  {CloudflareD1Databases, d1Dimensions},
	"d1_rows_read":      {CloudflareD1Databases, d1Dimensions},
	"d1_rows_written":   {CloudflareD1Databases, d1Dimensions},
	"d1_query_time_p50": {CloudflareD1Databases, d1Dimensions},
	"d1_query_time_p99": {CloudflareD1Databases, d1Dimensions},

	"queue_backlog_messages":     {CloudflareQueues, nil},
	"queue_backlog_bytes":        {CloudflareQueues, nil},
	"queue_consumer_concurrency": {CloudflareQueues, nil},
	"queue_operations":           {CloudflareQueues, queueOperationDimensions},
	"queue_lag_time":             {CloudflareQueues, queueOperationDimensions},
	"queue_retries":              {CloudflareQueues, queueOperationDimensions},

	"r2_requests":     {CloudflareR2Buckets, []string{"actionType", "actionStatus"}},
	"r2_stored_bytes": {CloudflareR2Buckets, []string{"storageClass"}},
	"r2_objects":      {CloudflareR2Buckets, []string{"storageClass"}},
}

var (
	workerDimensions         = []string{"status", "scriptVersion"}
	d1Dimensions             = []string{"databaseRole"}
	queueOperationDimensions = []string{"actionType", "outcome", "consumerType"}
)

// CloudflareMetricQuery is the native metrics query of Cloudflare sources, and the form of
// a Cloudflare signal given as a YAML mapping.
type CloudflareMetricQuery struct {
	Metric string   `json:"metric"`
	By     []string `json:"by,omitempty"`
}

// CloudWatchMetricQuery is the native metrics query of AWS sources, and the form of a
// CloudWatch signal given as a YAML mapping.
type CloudWatchMetricQuery struct {
	Metric     string            `json:"metric"`
	Stat       string            `json:"stat"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
}

func DecodeCloudflareMetricQuery(text string) (CloudflareMetricQuery, error) {
	var q CloudflareMetricQuery
	if err := decodeStrict(text, &q); err != nil {
		return q, err
	}
	if q.Metric == "" {
		return q, errors.New("metric is required")
	}
	metric, ok := CloudflareMetrics[q.Metric]
	if !ok {
		return q, fmt.Errorf("unknown metric %q, expected one of %v", q.Metric, slices.Sorted(maps.Keys(CloudflareMetrics)))
	}
	for _, dimension := range q.By {
		if !slices.Contains(metric.Dimensions, dimension) {
			return q, fmt.Errorf("unknown dimension %q of metric %s, expected one of %v", dimension, q.Metric, metric.Dimensions)
		}
	}
	return q, nil
}

var cloudWatchStat = regexp.MustCompile(`^(?:SampleCount|Average|Sum|Minimum|Maximum|p\d+(?:\.\d+)?)$`)

func DecodeCloudWatchMetricQuery(text string) (CloudWatchMetricQuery, error) {
	var q CloudWatchMetricQuery
	if err := decodeStrict(text, &q); err != nil {
		return q, err
	}
	if q.Metric == "" {
		return q, errors.New("metric is required")
	}
	if q.Stat == "" {
		return q, errors.New("stat is required")
	}
	if !cloudWatchStat.MatchString(q.Stat) {
		return q, fmt.Errorf("unknown stat %q, expected SampleCount, Average, Sum, Minimum, Maximum or a percentile like p99", q.Stat)
	}
	return q, nil
}

// decodeStrict rejects unknown fields and trailing data, so a typo cannot silently drop a filter.
func decodeStrict(text string, target any) error {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid query JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("query must be a single JSON object")
	}
	return nil
}
