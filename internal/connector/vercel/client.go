// Package vercel reads runtime logs through the Vercel Observability events API, the API the
// Vercel CLI's logs command uses.
package vercel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

const (
	eventsPath      = "/v1/observability/events"
	runtimeLogEvent = "vercel.log"
	// maxPageSize is the most events Vercel returns for one request.
	maxPageSize    = 1000
	maxBodyBytes   = 32 << 20
	maxErrorLength = 300
)

var (
	lineFields  = []string{"projectId", "environment", "deploymentId", "requestId", "requestMethod", "requestPath", "source", "level", "message"}
	countFields = []string{"projectId", "environment"}
)

// RuntimeFields are the runtime log fields Vercel filters on, besides bare message words.
var RuntimeFields = []api.LogField{
	{Name: "level", Type: "string"},
	{Name: "source", Type: "string"},
	{Name: "deploymentId", Type: "string"},
	{Name: "requestId", Type: "string"},
	{Name: "domain", Type: "string"},
	{Name: "requestPath", Type: "string"},
	{Name: "requestMethod", Type: "string"},
	{Name: "region", Type: "string"},
	{Name: "service", Type: "string"},
	{Name: "traceId", Type: "string"},
	{Name: "spanId", Type: "string"},
	{Name: "runtime", Type: "string"},
	{Name: "stream", Type: "string"},
	{Name: "isSystemLog", Type: "boolean"},
	{Name: "truncated", Type: "boolean"},
}

type Client struct {
	source *config.Source
	http   *http.Client
}

func New(src *config.Source, client *http.Client) *Client {
	return &Client{source: src, http: client}
}

type eventsRequest struct {
	Event     string       `json:"event"`
	Scope     requestScope `json:"scope"`
	TimeRange timeRange    `json:"timeRange"`
	Select    []string     `json:"select"`
	Filter    string       `json:"filter"`
	Order     string       `json:"order"`
	Limit     int          `json:"limit"`
	Cursor    string       `json:"cursor,omitempty"`
}

type requestScope struct {
	OwnerID    string   `json:"ownerId"`
	ProjectIDs []string `json:"projectIds"`
}

type timeRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type eventsResponse struct {
	Events     []logEvent `json:"events"`
	Pagination pagination `json:"pagination"`
}

type pagination struct {
	HasMore    bool   `json:"hasMore"`
	NextCursor string `json:"nextCursor"`
}

type logEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	ProjectID     string    `json:"projectId"`
	Environment   string    `json:"environment"`
	DeploymentID  string    `json:"deploymentId"`
	RequestID     string    `json:"requestId"`
	RequestMethod string    `json:"requestMethod"`
	RequestPath   string    `json:"requestPath"`
	Source        string    `json:"source"`
	Level         string    `json:"level"`
	Message       string    `json:"message"`
}

type errorResponse struct {
	Error struct {
		Message string `json:"message"`
		Issues  []struct {
			Path    string `json:"path"`
			Message string `json:"message"`
		} `json:"issues"`
	} `json:"error"`
}

// Lines returns the newest matching logs, at most limit, grouped into streams, and whether more
// logs match.
func (c *Client) Lines(ctx context.Context, scope authz.VercelScope, q policy.VercelQuery, r api.TimeRange, limit int) ([]telemetry.LogStream, bool, error) {
	page, err := c.events(ctx, scope, q, r, lineFields, min(limit, maxPageSize), "")
	if err != nil {
		return nil, false, err
	}
	streams := newStreamSet()
	for _, e := range page.Events {
		streams.add(e)
	}
	return streams.list, page.Pagination.HasMore, nil
}

// Count pages through the matching logs, because Vercel reports no total. It stops after at
// least limit logs and then reports the count as incomplete.
func (c *Client) Count(ctx context.Context, scope authz.VercelScope, q policy.VercelQuery, r api.TimeRange, limit int) (int64, bool, error) {
	var count int64
	cursor := ""
	for count < int64(limit) {
		page, err := c.events(ctx, scope, q, r, countFields, maxPageSize, cursor)
		if err != nil {
			return 0, false, err
		}
		count += int64(len(page.Events))
		next := page.Pagination.NextCursor
		if !page.Pagination.HasMore {
			return count, true, nil
		}
		if next == "" || next == cursor {
			return count, false, nil
		}
		cursor = next
	}
	return count, false, nil
}

// events fetches one page and checks that every event belongs to the scope.
func (c *Client) events(ctx context.Context, scope authz.VercelScope, q policy.VercelQuery, r api.TimeRange, fields []string, limit int, cursor string) (eventsResponse, error) {
	body, err := json.Marshal(eventsRequest{
		Event:     runtimeLogEvent,
		Scope:     requestScope{OwnerID: scope.TeamID(), ProjectIDs: []string{scope.Project()}},
		TimeRange: timeRange{Start: timestamp(r.From), End: timestamp(r.To)},
		Select:    fields,
		Filter:    q.String(),
		Order:     "desc",
		Limit:     limit,
		Cursor:    cursor,
	})
	if err != nil {
		return eventsResponse{}, err
	}
	var resp eventsResponse
	target := strings.TrimRight(c.source.URL, "/") + eventsPath + "?" + url.Values{"teamId": {scope.TeamID()}}.Encode()
	if err := c.post(ctx, target, body, &resp); err != nil {
		return eventsResponse{}, err
	}
	for _, e := range resp.Events {
		if e.ProjectID != scope.Project() || e.Environment != scope.VercelEnvironment() {
			return eventsResponse{}, c.outsideScope()
		}
	}
	return resp, nil
}

// post sends a JSON body and decodes the JSON response. HTTP 400 means Vercel rejected the
// query or its range, so it is reported as a query error with Vercel's message.
func (c *Client) post(ctx context.Context, target string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return upstream.Wrap(c.source.Name, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return upstream.Wrap(c.source.Name, err)
	}
	if resp.StatusCode == http.StatusBadRequest {
		return apierr.InvalidQuery("source %s rejected the query: %s", c.source.Name, responseError(data))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return upstream.Wrap(c.source.Name, &upstream.StatusError{Source: c.source.Name, Status: resp.StatusCode, Body: responseError(data)})
	}
	if err := json.Unmarshal(data, out); err != nil {
		return apierr.Upstream("source %s returned invalid JSON: %v", c.source.Name, err)
	}
	return nil
}

// responseError prefers the message and issues of a Vercel error over the raw body.
func responseError(data []byte) string {
	var resp errorResponse
	if json.Unmarshal(data, &resp) == nil && resp.Error.Message != "" {
		text := resp.Error.Message
		for _, issue := range resp.Error.Issues {
			text += fmt.Sprintf("; %s: %s", issue.Path, issue.Message)
		}
		return text
	}
	text := strings.TrimSpace(string(data))
	if len(text) > maxErrorLength {
		return text[:maxErrorLength] + "…"
	}
	return text
}

// outsideScope is the defense-in-depth error: the request scope names the project and the
// filter the environment, so logs of others mean the scoping failed.
func (c *Client) outsideScope() error {
	return apierr.New(api.CodeInternal, "source %s returned data outside the scope", c.source.Name)
}

func timestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// streamKey groups the logs of one request.
type streamKey struct {
	level, source, deploymentID, requestID, requestMethod, requestPath string
}

func (k streamKey) labels() map[string]string {
	labels := map[string]string{}
	for name, value := range map[string]string{
		"level":         k.level,
		"source":        k.source,
		"deploymentId":  k.deploymentID,
		"requestId":     k.requestID,
		"requestMethod": k.requestMethod,
		"requestPath":   k.requestPath,
	} {
		if value != "" {
			labels[name] = value
		}
	}
	return labels
}

type streamSet struct {
	index map[streamKey]int
	list  []telemetry.LogStream
}

func newStreamSet() *streamSet {
	return &streamSet{index: map[streamKey]int{}}
}

func (s *streamSet) add(e logEvent) {
	key := streamKey{level: e.Level, source: e.Source, deploymentID: e.DeploymentID, requestID: e.RequestID, requestMethod: e.RequestMethod, requestPath: e.RequestPath}
	i, ok := s.index[key]
	if !ok {
		i = len(s.list)
		s.index[key] = i
		s.list = append(s.list, telemetry.LogStream{Labels: key.labels()})
	}
	s.list[i].Entries = append(s.list[i].Entries, telemetry.LogEntry{Time: e.Timestamp.UTC(), Line: e.Message})
}
