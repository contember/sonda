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
      workersInvocationsAdaptive(limit: %d, filter: {scriptName: $scriptName, datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd}, orderBy: [%s_ASC]) {
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
	"duration_p50": {"quantiles { requestDurationP50 }", func(r invocationRow) float64 { return r.Quantiles.RequestDurationP50 / 1000 }},
	"duration_p99": {"quantiles { requestDurationP99 }", func(r invocationRow) float64 { return r.Quantiles.RequestDurationP99 / 1000 }},
}

var dimensionFields = map[string]func(invocationRow) string{
	"status":        func(r invocationRow) string { return r.Dimensions.Status },
	"scriptVersion": func(r invocationRow) string { return r.Dimensions.ScriptVersion },
}

type timeBucket struct {
	size   time.Duration
	field  string
	layout string
	value  func(invocationRow) string
}

// timeBuckets go from the finest; a query uses the finest bucket not finer than the step, so
// it returns no more points than the step allows.
var timeBuckets = []timeBucket{
	{time.Minute, "datetimeMinute", time.RFC3339, func(r invocationRow) string { return r.Dimensions.DatetimeMinute }},
	{15 * time.Minute, "datetimeFifteenMinutes", time.RFC3339, func(r invocationRow) string { return r.Dimensions.DatetimeFifteenMinutes }},
	{time.Hour, "datetimeHour", time.RFC3339, func(r invocationRow) string { return r.Dimensions.DatetimeHour }},
	{24 * time.Hour, "date", time.DateOnly, func(r invocationRow) string { return r.Dimensions.Date }},
}

type invocationRow struct {
	Sum struct {
		Requests    float64 `json:"requests"`
		Errors      float64 `json:"errors"`
		Subrequests float64 `json:"subrequests"`
	} `json:"sum"`
	Quantiles struct {
		CPUTimeP50         float64 `json:"cpuTimeP50"`
		CPUTimeP99         float64 `json:"cpuTimeP99"`
		RequestDurationP50 float64 `json:"requestDurationP50"` // µs
		RequestDurationP99 float64 `json:"requestDurationP99"` // µs
	} `json:"quantiles"`
	Dimensions struct {
		ScriptName             string `json:"scriptName"`
		Status                 string `json:"status"`
		ScriptVersion          string `json:"scriptVersion"`
		DatetimeMinute         string `json:"datetimeMinute"`
		DatetimeFifteenMinutes string `json:"datetimeFifteenMinutes"`
		DatetimeHour           string `json:"datetimeHour"`
		Date                   string `json:"date"`
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

// Metric reads one catalog metric of the scoped script, with one series per value of the
// requested dimensions. It returns the time bucket it used as the effective step.
func (c *Client) Metric(ctx context.Context, scope authz.CloudflareScope, m telemetry.CloudflareMetricQuery, r api.TimeRange, step time.Duration) (model.Matrix, time.Duration, error) {
	field, ok := metricFields[m.Metric]
	if !ok {
		return nil, 0, apierr.InvalidQuery("unknown metric %q", m.Metric)
	}
	dimensions := make([]string, 0, len(m.By))
	for _, name := range m.By {
		if _, ok := dimensionFields[name]; !ok {
			return nil, 0, apierr.InvalidQuery("unknown dimension %q", name)
		}
		dimensions = append(dimensions, name)
	}
	bucket := bucketFor(step)
	body, err := json.Marshal(graphQLRequest{
		Query: fmt.Sprintf(invocationsQuery, maxInvocationRows, bucket.field, field.selection, strings.Join(append([]string{bucket.field}, dimensions...), " ")),
		Variables: metricsVariables{
			AccountTag:    scope.AccountID(),
			ScriptName:    scope.Script(),
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
		if len(account.WorkersInvocationsAdaptive) >= maxInvocationRows {
			return nil, 0, apierr.New(api.CodeLimitExceeded, "too many rows; use a shorter range, a longer step or fewer by dimensions")
		}
		for _, row := range account.WorkersInvocationsAdaptive {
			if row.Dimensions.ScriptName != scope.Script() {
				return nil, 0, c.outsideScope()
			}
			at, err := time.Parse(bucket.layout, bucket.value(row))
			if err != nil {
				return nil, 0, apierr.Upstream("source %s returned an invalid %s %q", c.source.Name, bucket.field, bucket.value(row))
			}
			labels := model.Metric{}
			for _, name := range dimensions {
				labels[model.LabelName(name)] = model.LabelValue(dimensionFields[name](row))
			}
			matrix.add(labels, at, field.value(row))
		}
	}
	return matrix.build(), bucket.size, nil
}

func bucketFor(step time.Duration) timeBucket {
	for _, bucket := range timeBuckets {
		if bucket.size >= step {
			return bucket
		}
	}
	return timeBuckets[len(timeBuckets)-1]
}
