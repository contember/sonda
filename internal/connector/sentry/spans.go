package sentry

import (
	"context"
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

// allProjects is Sentry's project filter for every project the token can access.
const allProjects = "-1"

var spanFields = []string{
	"id", "parent_span", "trace", "project", "environment", "transaction",
	"span.op", "span.description", "span.status", "span.duration", "precise.start_ts",
}

// spanRow is one row of the spans dataset of the organization events endpoint. Fields that a
// span lacks come back as null and stay empty.
type spanRow struct {
	ID          string  `json:"id"`
	ParentSpan  string  `json:"parent_span"`
	Trace       string  `json:"trace"`
	Project     string  `json:"project"`
	Environment string  `json:"environment"`
	Transaction string  `json:"transaction"`
	Op          string  `json:"span.op"`
	Description string  `json:"span.description"`
	Status      string  `json:"span.status"`
	DurationMs  float64 `json:"span.duration"`
	Start       float64 `json:"precise.start_ts"`
}

// Spans returns the newest spans of the scope's project and environment that match the query.
// The events endpoint is organization-wide, so every span is checked against the scope again.
func (c *Client) Spans(ctx context.Context, scope authz.SentrySpanScope, q policy.SentrySpanQuery, r api.TimeRange, limit int) ([]telemetry.Span, error) {
	params := url.Values{"projectSlug": {scope.Project()}, "environment": {scope.SentryEnvironment()}}
	rows, err := c.spans(ctx, params, q, r, limit)
	if err != nil {
		return nil, err
	}
	spans := make([]telemetry.Span, len(rows))
	for i, row := range rows {
		if row.Project != scope.Project() || row.Environment != scope.SentryEnvironment() {
			return nil, apierr.New(api.CodeInternal, "source %s returned data outside the scope", c.source.Name)
		}
		spans[i] = row.span()
	}
	return spans, nil
}

// TraceSpans returns the spans of all projects that match the query, at most limit. It is not
// scope-checked: the caller keeps only what the identity may see.
func (c *Client) TraceSpans(ctx context.Context, q policy.SentrySpanQuery, r api.TimeRange, limit int) ([]telemetry.Span, error) {
	rows, err := c.spans(ctx, url.Values{"project": {allProjects}}, q, r, limit)
	if err != nil {
		return nil, err
	}
	spans := make([]telemetry.Span, len(rows))
	for i, row := range rows {
		spans[i] = row.span()
	}
	return spans, nil
}

func (c *Client) spans(ctx context.Context, params url.Values, q policy.SentrySpanQuery, r api.TimeRange, limit int) ([]spanRow, error) {
	params.Set("dataset", "spans")
	params["field"] = spanFields
	params.Set("query", q.String())
	params.Set("sort", "-timestamp")
	params.Set("per_page", strconv.Itoa(limit))
	params.Set("start", formatTime(r.From))
	params.Set("end", formatTime(r.To))
	var resp struct {
		Data []spanRow `json:"data"`
	}
	if err := c.get(ctx, c.orgPath("events/"), params, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// span maps a row to a span. The service is the project slug; the environment is kept as an
// attribute, so the caller can check it.
func (row spanRow) span() telemetry.Span {
	span := telemetry.Span{
		TraceID:    row.Trace,
		SpanID:     row.ID,
		ParentID:   row.ParentSpan,
		Service:    row.Project,
		Name:       row.Description,
		Start:      fromSeconds(row.Start),
		Duration:   time.Duration(row.DurationMs * float64(time.Millisecond)),
		Attributes: map[string]string{},
	}
	for key, value := range map[string]string{"environment": row.Environment, "span.op": row.Op, "transaction": row.Transaction} {
		if value != "" {
			span.Attributes[key] = value
		}
	}
	if span.Name == "" {
		span.Name = row.Op
	}
	switch row.Status {
	case "":
		span.Status = telemetry.StatusUnset
	case "ok":
		span.Status = telemetry.StatusOK
	default:
		span.Status, span.StatusMessage = telemetry.StatusError, row.Status
	}
	return span
}

func fromSeconds(seconds float64) time.Time {
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*1e9)).UTC()
}
