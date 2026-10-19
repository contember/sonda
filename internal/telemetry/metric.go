package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// CloudflareMetrics is the catalog over Cloudflare GraphQL workersInvocationsAdaptive. The
// Cloudflare connector maps each name to a GraphQL field; keep the names stable.
var CloudflareMetrics = []string{"requests", "errors", "subrequests", "cpu_time_p50", "cpu_time_p99", "duration_p50", "duration_p99"}

var CloudflareDimensions = []string{"status", "scriptVersion"}

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
	if !slices.Contains(CloudflareMetrics, q.Metric) {
		return q, fmt.Errorf("unknown metric %q, expected one of %v", q.Metric, CloudflareMetrics)
	}
	for _, dimension := range q.By {
		if !slices.Contains(CloudflareDimensions, dimension) {
			return q, fmt.Errorf("unknown dimension %q, expected one of %v", dimension, CloudflareDimensions)
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
