package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/telemetry"
)

// maxInvocationRows caps the rows of one GraphQL query: time buckets times dimension values.
const maxInvocationRows = 10000

// invocationsQuery reads workersInvocationsAdaptive of one script. Only catalog constants are
// formatted into it; the scope and the range are GraphQL variables.
const invocationsQuery = `query SondaWorkerMetric($accountTag: string, $scriptName: string, $datetimeStart: string, $datetimeEnd: string) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      workersInvocationsAdaptive(limit: %d, filter: {scriptName: $scriptName, datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd}) {
        %s
        dimensions { scriptName %s }
      }
    }
  }
}`

type metricField struct {
	selection string
	value     func(invocationRow) float64
}

var metricFields = map[string]metricField{
	"requests":     {"sum { requests }", func(r invocationRow) float64 { return r.Sum.Requests }},
	"errors":       {"sum { errors }", func(r invocationRow) float64 { return r.Sum.Errors }},
	"subrequests":  {"sum { subrequests }", func(r invocationRow) float64 { return r.Sum.Subrequests }},
	"cpu_time_p50": {"quantiles { cpuTimeP50 }", func(r invocationRow) float64 { return r.Quantiles.CPUTimeP50 }},
	"cpu_time_p99": {"quantiles { cpuTimeP99 }", func(r invocationRow) float64 { return r.Quantiles.CPUTimeP99 }},
	"duration_p50": {"quantiles { durationP50 }", func(r invocationRow) float64 { return r.Quantiles.DurationP50 }},
	"duration_p99": {"quantiles { durationP99 }", func(r invocationRow) float64 { return r.Quantiles.DurationP99 }},
}

var dimensionFields = map[string]func(invocationRow) string{
	"status":        func(r invocationRow) string { return r.Dimensions.Status },
	"scriptVersion": func(r invocationRow) string { return r.Dimensions.ScriptVersion },
}

type timeBucket struct {
	size  time.Duration
	field string
	value func(invocationRow) string
}

// timeBuckets go from the coarsest; a query uses the coarsest bucket that fits into the step.
var timeBuckets = []timeBucket{
	{time.Hour, "datetimeHour", func(r invocationRow) string { return r.Dimensions.DatetimeHour }},
	{15 * time.Minute, "datetimeFifteenMinutes", func(r invocationRow) string { return r.Dimensions.DatetimeFifteenMinutes }},
	{time.Minute, "datetimeMinute", func(r invocationRow) string { return r.Dimensions.DatetimeMinute }},
}

type invocationRow struct {
	Sum struct {
		Requests    float64 `json:"requests"`
		Errors      float64 `json:"errors"`
		Subrequests float64 `json:"subrequests"`
	} `json:"sum"`
	Quantiles struct {
		CPUTimeP50  float64 `json:"cpuTimeP50"`
		CPUTimeP99  float64 `json:"cpuTimeP99"`
		DurationP50 float64 `json:"durationP50"`
		DurationP99 float64 `json:"durationP99"`
	} `json:"quantiles"`
	Dimensions struct {
		ScriptName             string `json:"scriptName"`
		Status                 string `json:"status"`
		ScriptVersion          string `json:"scriptVersion"`
		DatetimeMinute         string `json:"datetimeMinute"`
		DatetimeFifteenMinutes string `json:"datetimeFifteenMinutes"`
		DatetimeHour           string `json:"datetimeHour"`
	} `json:"dimensions"`
}

type graphQLRequest struct {
	Query     string           `json:"query"`
	Variables metricsVariables `json:"variables"`
}

type metricsVariables struct {
	AccountTag    string `json:"accountTag"`
	ScriptName    string `json:"scriptName"`
	DatetimeStart string `json:"datetimeStart"`
	DatetimeEnd   string `json:"datetimeEnd"`
}

type graphQLResponse struct {
	Data *struct {
		Viewer struct {
			Accounts []struct {
				WorkersInvocationsAdaptive []invocationRow `json:"workersInvocationsAdaptive"`
			} `json:"accounts"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// Metric reads one catalog metric of the scoped script, bucketed by the coarsest time
// dimension that fits into step, with one series per value of the requested dimensions.
func (c *Client) Metric(ctx context.Context, scope authz.CloudflareScope, m telemetry.CloudflareMetricQuery, r api.TimeRange, step time.Duration) (model.Matrix, error) {
	field, ok := metricFields[m.Metric]
	if !ok {
		return nil, apierr.InvalidQuery("unknown metric %q", m.Metric)
	}
	dimensions := make([]string, 0, len(m.By))
	for _, name := range m.By {
		if _, ok := dimensionFields[name]; !ok {
			return nil, apierr.InvalidQuery("unknown dimension %q", name)
		}
		dimensions = append(dimensions, name)
	}
	bucket := bucketFor(step)
	body, err := json.Marshal(graphQLRequest{
		Query: fmt.Sprintf(invocationsQuery, maxInvocationRows, field.selection, strings.Join(append([]string{bucket.field}, dimensions...), " ")),
		Variables: metricsVariables{
			AccountTag:    scope.AccountID(),
			ScriptName:    scope.Script(),
			DatetimeStart: r.From.UTC().Format(time.RFC3339),
			DatetimeEnd:   r.To.UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		return nil, err
	}
	var resp graphQLResponse
	if err := c.post(ctx, strings.TrimRight(c.source.URL, "/")+"/graphql", body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Errors) > 0 {
		return nil, apierr.Upstream("source %s returned a GraphQL error: %s", c.source.Name, resp.Errors[0].Message)
	}
	if resp.Data == nil {
		return nil, apierr.Upstream("source %s returned no GraphQL data", c.source.Name)
	}
	matrix := newMatrixBuilder()
	for _, account := range resp.Data.Viewer.Accounts {
		for _, row := range account.WorkersInvocationsAdaptive {
			if row.Dimensions.ScriptName != scope.Script() {
				return nil, c.outsideScope()
			}
			at, err := time.Parse(time.RFC3339, bucket.value(row))
			if err != nil {
				return nil, apierr.Upstream("source %s returned an invalid %s %q", c.source.Name, bucket.field, bucket.value(row))
			}
			labels := model.Metric{}
			for _, name := range dimensions {
				labels[model.LabelName(name)] = model.LabelValue(dimensionFields[name](row))
			}
			matrix.add(labels, at, field.value(row))
		}
	}
	return matrix.build(), nil
}

func bucketFor(step time.Duration) timeBucket {
	for _, bucket := range timeBuckets {
		if bucket.size <= step {
			return bucket
		}
	}
	return timeBuckets[len(timeBuckets)-1]
}
