// Package loki queries the Loki HTTP API.
package loki

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/policy"
)

type Client struct {
	source *config.Source
	http   *http.Client
}

func New(src *config.Source) *Client {
	return &Client{source: src, http: upstream.HTTPClient(src)}
}

type Entry struct {
	Time time.Time
	Line string
}

type Stream struct {
	Labels  map[string]string
	Entries []Entry
}

type Field struct {
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Cardinality int      `json:"cardinality"`
	Parsers     []string `json:"parsers"`
}

type queryResponse struct {
	Data struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type rawStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// Lines returns the newest lines of a log query, newest first.
func (c *Client) Lines(ctx context.Context, q policy.LogQL, r api.TimeRange, limit int) ([]Stream, error) {
	params := rangeParams(q, r)
	params.Set("limit", strconv.Itoa(limit))
	params.Set("direction", "backward")
	var resp queryResponse
	if err := c.get(ctx, "/loki/api/v1/query_range", params, &resp); err != nil {
		return nil, err
	}
	if resp.Data.ResultType != "streams" {
		return nil, apierr.Upstream("source %s returned %s instead of streams", c.source.Name, resp.Data.ResultType)
	}
	var raw []rawStream
	if err := json.Unmarshal(resp.Data.Result, &raw); err != nil {
		return nil, apierr.Upstream("source %s returned invalid streams: %v", c.source.Name, err)
	}
	streams := make([]Stream, 0, len(raw))
	for _, rs := range raw {
		s := Stream{Labels: rs.Stream, Entries: make([]Entry, 0, len(rs.Values))}
		for _, v := range rs.Values {
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return nil, apierr.Upstream("source %s returned an invalid timestamp %q", c.source.Name, v[0])
			}
			s.Entries = append(s.Entries, Entry{Time: time.Unix(0, ns).UTC(), Line: v[1]})
		}
		streams = append(streams, s)
	}
	return streams, nil
}

// Matrix runs a metric query over a range.
func (c *Client) Matrix(ctx context.Context, q policy.LogQL, r api.TimeRange, step time.Duration) (model.Matrix, error) {
	params := rangeParams(q, r)
	params.Set("step", strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
	var resp queryResponse
	if err := c.get(ctx, "/loki/api/v1/query_range", params, &resp); err != nil {
		return nil, err
	}
	var matrix model.Matrix
	if resp.Data.ResultType != "matrix" || json.Unmarshal(resp.Data.Result, &matrix) != nil {
		return nil, apierr.Upstream("source %s returned %s instead of a matrix", c.source.Name, resp.Data.ResultType)
	}
	return matrix, nil
}

// Instant runs a metric query at one point in time.
func (c *Client) Instant(ctx context.Context, q policy.LogQL, at time.Time) (model.Vector, error) {
	params := url.Values{"query": {q.String()}, "time": {strconv.FormatInt(at.UnixNano(), 10)}}
	var resp queryResponse
	if err := c.get(ctx, "/loki/api/v1/query", params, &resp); err != nil {
		return nil, err
	}
	var vector model.Vector
	if resp.Data.ResultType != "vector" || json.Unmarshal(resp.Data.Result, &vector) != nil {
		return nil, apierr.Upstream("source %s returned %s instead of a vector", c.source.Name, resp.Data.ResultType)
	}
	return vector, nil
}

// Series returns the label sets of the streams within the scope.
func (c *Client) Series(ctx context.Context, scope authz.SelectorScope, r api.TimeRange) ([]map[string]string, error) {
	params := url.Values{
		"match[]": {scope.Selector()},
		"start":   {strconv.FormatInt(r.From.UnixNano(), 10)},
		"end":     {strconv.FormatInt(r.To.UnixNano(), 10)},
	}
	var resp struct {
		Data []map[string]string `json:"data"`
	}
	if err := c.get(ctx, "/loki/api/v1/series", params, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// DetectedFields returns fields parsed from log lines within the scope. It returns nil
// without an error on Loki versions that lack the endpoint.
func (c *Client) DetectedFields(ctx context.Context, scope authz.SelectorScope, r api.TimeRange) ([]Field, error) {
	params := url.Values{
		"query": {scope.Selector()},
		"start": {strconv.FormatInt(r.From.UnixNano(), 10)},
		"end":   {strconv.FormatInt(r.To.UnixNano(), 10)},
	}
	var resp struct {
		Fields []Field `json:"fields"`
	}
	err := c.fetch(ctx, "/loki/api/v1/detected_fields", params, &resp)
	if upstream.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, c.convert(err)
	}
	return resp.Fields, nil
}

func rangeParams(q policy.LogQL, r api.TimeRange) url.Values {
	return url.Values{
		"query": {q.String()},
		"start": {strconv.FormatInt(r.From.UnixNano(), 10)},
		"end":   {strconv.FormatInt(r.To.UnixNano(), 10)},
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

// convert reports Loki's 400 responses as query errors; they explain what is wrong with
// the query or which limit it hit.
func (c *Client) convert(err error) error {
	var se *upstream.StatusError
	if errors.As(err, &se) && se.Status == http.StatusBadRequest {
		return apierr.InvalidQuery("source %s rejected the query: %s", c.source.Name, se.Body)
	}
	return upstream.Wrap(c.source.Name, err)
}
