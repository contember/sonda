package vercel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

var testRange = api.TimeRange{From: time.UnixMilli(1_700_000_000_000).UTC(), To: time.UnixMilli(1_700_003_600_000).UTC()}

type request struct {
	target string
	auth   string
	body   eventsRequest
}

// fake answers each request with the next response; the last one repeats.
type fake struct {
	status    int
	responses []string
	requests  []request
}

func (f *fake) handler(w http.ResponseWriter, r *http.Request) {
	var body eventsRequest
	data, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(data, &body)
	f.requests = append(f.requests, request{target: r.URL.RequestURI(), auth: r.Header.Get("Authorization"), body: body})
	w.Header().Set("Content-Type", "application/json")
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	_, _ = io.WriteString(w, f.responses[min(len(f.requests), len(f.responses))-1])
}

func setup(t *testing.T, f *fake) (*Client, authz.VercelScope, policy.VercelQuery) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(`
sources:
  vercel: { type: vercel, url: "`+server.URL+`", team_id: team_1, auth: { type: bearer, token: secret } }
projects:
  web:
    services:
      web:
        environments:
          production:
            logs: { source: vercel, project: prj_1, environment: production }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "web", Environment: "production", Capability: api.CapabilityLogs},
	}}
	logScope, err := authz.New(cfg, nil).LogScope(identity, "web", "production")
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := logScope.Vercel()
	q, err := policy.ScopeVercelQuery(scope, "level:error")
	if err != nil {
		t.Fatal(err)
	}
	src := cfg.Sources["vercel"]
	return New(src, upstream.HTTPClient(src, nil)), scope, q
}

func page(hasMore bool, cursor string, events ...string) string {
	return `{"events":[` + strings.Join(events, ",") + `],"pagination":{"hasMore":` + map[bool]string{true: "true", false: "false"}[hasMore] +
		`,"nextCursor":` + map[bool]string{true: `"` + cursor + `"`, false: "null"}[cursor != ""] + `}}`
}

const (
	logA  = `{"timestamp":"2026-10-26T14:18:34.617Z","projectId":"prj_1","environment":"production","deploymentId":"dpl_1","requestId":"r1","requestMethod":"GET","requestPath":"/a","source":"function","level":"error","message":"TypeError: boom"}`
	logA2 = `{"timestamp":"2026-10-26T14:18:34.500Z","projectId":"prj_1","environment":"production","deploymentId":"dpl_1","requestId":"r1","requestMethod":"GET","requestPath":"/a","source":"function","level":"error","message":"at handler"}`
	logB  = `{"timestamp":"2026-10-26T14:10:00Z","projectId":"prj_1","environment":"production","source":"function","level":"error","message":"no request"}`
	short = `{"timestamp":"2026-10-26T14:10:00Z","projectId":"prj_1","environment":"production"}`
)

func TestLines(t *testing.T) {
	f := &fake{responses: []string{page(true, "c1", logA, logA2, logB)}}
	client, scope, q := setup(t, f)
	streams, more, err := client.Lines(context.Background(), scope, q, testRange, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if !more {
		t.Error("more = false")
	}
	want := []telemetry.LogStream{
		{
			Labels: map[string]string{"level": "error", "source": "function", "deploymentId": "dpl_1", "requestId": "r1", "requestMethod": "GET", "requestPath": "/a"},
			Entries: []telemetry.LogEntry{
				{Time: time.Date(2026, 10, 26, 14, 18, 34, 617_000_000, time.UTC), Line: "TypeError: boom"},
				{Time: time.Date(2026, 10, 26, 14, 18, 34, 500_000_000, time.UTC), Line: "at handler"},
			},
		},
		{
			Labels:  map[string]string{"level": "error", "source": "function"},
			Entries: []telemetry.LogEntry{{Time: time.Date(2026, 10, 26, 14, 10, 0, 0, time.UTC), Line: "no request"}},
		},
	}
	if !reflect.DeepEqual(streams, want) {
		t.Errorf("streams = %+v", streams)
	}

	got := f.requests[0]
	if got.target != "/v1/observability/events?teamId=team_1" || got.auth != "Bearer secret" {
		t.Errorf("request = %s, auth %q", got.target, got.auth)
	}
	wantBody := eventsRequest{
		Event:     "vercel.log",
		Scope:     requestScope{OwnerID: "team_1", ProjectIDs: []string{"prj_1"}},
		TimeRange: timeRange{Start: "2023-11-14T22:13:20.000Z", End: "2023-11-14T23:13:20.000Z"},
		Select:    lineFields,
		Filter:    `environment:"production" AND (level:error)`,
		Order:     "desc",
		Limit:     1000,
	}
	if !reflect.DeepEqual(got.body, wantBody) {
		t.Errorf("body = %+v", got.body)
	}
}

// The scope is enforced upstream; a log of another project or environment means it failed.
func TestLinesOutsideScope(t *testing.T) {
	for _, event := range []string{
		strings.Replace(logA, `"environment":"production"`, `"environment":"preview"`, 1),
		strings.Replace(logA, `"projectId":"prj_1"`, `"projectId":"prj_2"`, 1),
		`{"timestamp":"2026-10-26T14:10:00Z","message":"no scope fields"}`,
	} {
		client, scope, q := setup(t, &fake{responses: []string{page(false, "", logB, event)}})
		_, _, err := client.Lines(context.Background(), scope, q, testRange, 10)
		if e, ok := apierr.As(err); !ok || e.Code != api.CodeInternal || !strings.Contains(e.Message, "outside the scope") {
			t.Errorf("%s: error = %v", event, err)
		}
	}
}

func TestCount(t *testing.T) {
	f := &fake{responses: []string{page(true, "c1", short, short), page(true, "c2", short), page(false, "", short)}}
	client, scope, q := setup(t, f)
	count, complete, err := client.Count(context.Background(), scope, q, testRange, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 || !complete {
		t.Errorf("count = %d, complete = %v", count, complete)
	}
	var cursors []string
	for _, r := range f.requests {
		if r.body.Limit != maxPageSize || !reflect.DeepEqual(r.body.Select, countFields) {
			t.Errorf("count request = %+v", r.body)
		}
		cursors = append(cursors, r.body.Cursor)
	}
	if !reflect.DeepEqual(cursors, []string{"", "c1", "c2"}) {
		t.Errorf("cursors = %q", cursors)
	}
}

func TestCountStops(t *testing.T) {
	tests := []struct {
		name      string
		responses []string
		limit     int
		want      int64
		requests  int
	}{
		{"at the limit", []string{page(true, "c1", short, short), page(true, "c2", short, short), page(true, "c3", short, short)}, 3, 4, 2},
		{"without a cursor", []string{page(true, "", short)}, 10, 1, 1},
		{"on a repeated cursor", []string{page(true, "c1", short), page(true, "c1", short)}, 10, 2, 2},
	}
	for _, tt := range tests {
		f := &fake{responses: tt.responses}
		client, scope, q := setup(t, f)
		count, complete, err := client.Count(context.Background(), scope, q, testRange, tt.limit)
		if err != nil {
			t.Fatal(err)
		}
		if count != tt.want || complete || len(f.requests) != tt.requests {
			t.Errorf("%s: count = %d, complete = %v, requests = %d", tt.name, count, complete, len(f.requests))
		}
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		status   int
		response string
		code     api.ErrorCode
		message  string
	}{
		{
			http.StatusBadRequest,
			`{"error":{"code":"invalid_request","message":"Invalid events request","issues":[{"path":"filter","message":"Expected \")\" to close the expression at 1:19"}]}}`,
			api.CodeInvalidQuery,
			`source vercel rejected the query: Invalid events request; filter: Expected ")" to close the expression at 1:19`,
		},
		{
			http.StatusBadRequest,
			`{"error":{"code":"bad_request","message":"The pro plan does not retain runtime logs for the requested time range."}}`,
			api.CodeInvalidQuery,
			"source vercel rejected the query: The pro plan does not retain runtime logs for the requested time range.",
		},
		{
			http.StatusForbidden,
			`{"error":{"code":"forbidden","message":"Forbidden"}}`,
			api.CodeUpstreamError,
			"source vercel returned HTTP 403: Forbidden",
		},
	}
	for _, tt := range tests {
		client, scope, q := setup(t, &fake{status: tt.status, responses: []string{tt.response}})
		_, _, err := client.Lines(context.Background(), scope, q, testRange, 10)
		if e, ok := apierr.As(err); !ok || e.Code != tt.code || e.Message != tt.message {
			t.Errorf("HTTP %d: error = %v", tt.status, err)
		}
	}
}
