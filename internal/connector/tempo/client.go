// Package tempo queries the Grafana Tempo HTTP API.
package tempo

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

// spansPerSpanset caps the matched spans Tempo returns per trace.
const spansPerSpanset = 10

type Client struct {
	source *config.Source
	http   *http.Client
}

func New(src *config.Source, client *http.Client) *Client {
	return &Client{source: src, http: client}
}

// Search returns at most limit traces that match the query. The matched spans carry no
// service; Tempo does not report it per span.
func (c *Client) Search(ctx context.Context, q policy.TraceQL, r api.TimeRange, limit int) ([]telemetry.TraceSummary, error) {
	params := rangeParams(r)
	params.Set("q", q.String())
	params.Set("limit", strconv.Itoa(limit))
	params.Set("spss", strconv.Itoa(spansPerSpanset))
	var resp searchResponse
	if err := c.get(ctx, "/api/search", params, &resp); err != nil {
		return nil, err
	}
	traces := make([]telemetry.TraceSummary, 0, min(len(resp.Traces), limit))
	for _, t := range resp.Traces[:min(len(resp.Traces), limit)] {
		summary, err := t.summary()
		if err != nil {
			return nil, apierr.Upstream("source %s returned an invalid trace: %v", c.source.Name, err)
		}
		traces = append(traces, summary)
	}
	return traces, nil
}

// Trace returns all spans of a trace. A missing trace is a not_found error.
func (c *Client) Trace(ctx context.Context, id string, r api.TimeRange) ([]telemetry.Span, error) {
	var resp traceResponse
	err := c.fetch(ctx, "/api/v2/traces/"+url.PathEscape(id), rangeParams(r), &resp)
	if upstream.IsNotFound(err) {
		return nil, apierr.NotFound("trace %q not found", id)
	}
	if err != nil {
		return nil, c.convert(err)
	}
	spans, err := resp.Trace.spans()
	if err != nil {
		return nil, apierr.Upstream("source %s returned an invalid trace: %v", c.source.Name, err)
	}
	// Tempo answers an unknown trace ID with an empty trace.
	if len(spans) == 0 {
		return nil, apierr.NotFound("trace %q not found", id)
	}
	return spans, nil
}

// rangeParams widens the range to whole seconds, the resolution of Tempo's start and end.
func rangeParams(r api.TimeRange) url.Values {
	end := r.To.Truncate(time.Second)
	if end.Before(r.To) {
		end = end.Add(time.Second)
	}
	return url.Values{
		"start": {strconv.FormatInt(r.From.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
	}
}

func (c *Client) get(ctx context.Context, path string, params url.Values, out any) error {
	if err := c.fetch(ctx, path, params, out); err != nil {
		return c.convert(err)
	}
	return nil
}

func (c *Client) fetch(ctx context.Context, path string, params url.Values, out any) error {
	target := strings.TrimRight(c.source.URL, "/") + path + "?" + params.Encode()
	return upstream.GetJSON(ctx, c.http, c.source.Name, target, out)
}

// convert reports Tempo's 400 responses as query errors; they explain what is wrong with
// the query.
func (c *Client) convert(err error) error {
	var se *upstream.StatusError
	if errors.As(err, &se) && se.Status == http.StatusBadRequest {
		return apierr.InvalidQuery("source %s rejected the query: %s", c.source.Name, se.Body)
	}
	return upstream.Wrap(c.source.Name, err)
}
