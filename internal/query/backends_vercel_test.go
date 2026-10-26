package query

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/connector/vercel"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
)

const vercelLog = `{"timestamp":"2026-10-26T14:18:34.617Z","projectId":"prj_1","environment":"production","level":"error","message":"boom"}`

// vercelBackend answers the requests with responses in order, repeating the last one.
func vercelBackend(t *testing.T, responses ...string) (logBackend, *[]string) {
	t.Helper()
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		_, _ = io.WriteString(w, responses[min(len(bodies), len(responses))-1])
	}))
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(`
sources:
  vercel: { type: vercel, url: "`+server.URL+`", team_id: team_1, auth: { type: bearer, token: t } }
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
	src := cfg.Sources["vercel"]
	return newVercelLogs(scope, vercel.New(src, upstream.HTTPClient(src, nil))), &bodies
}

func vercelPage(more bool, cursor string, n int) string {
	events := make([]string, n)
	for i := range events {
		events[i] = vercelLog
	}
	next := "null"
	if cursor != "" {
		next = `"` + cursor + `"`
	}
	hasMore := "false"
	if more {
		hasMore = "true"
	}
	return `{"events":[` + strings.Join(events, ",") + `],"pagination":{"hasMore":` + hasMore + `,"nextCursor":` + next + `}}`
}

func TestVercelLogSearchTotal(t *testing.T) {
	tests := []struct {
		name       string
		responses  []string
		total      int64
		lowerBound bool
		requests   int
	}{
		{"all lines in the sample", []string{vercelPage(false, "", 2)}, 2, false, 1},
		{"counted", []string{vercelPage(true, "c1", 2), vercelPage(true, "c1", 3), vercelPage(false, "", 1)}, 4, false, 3},
		{"counting stopped", []string{vercelPage(true, "c1", 2), vercelPage(true, "", 3)}, 3, true, 2},
	}
	for _, tt := range tests {
		logs, bodies := vercelBackend(t, tt.responses...)
		found, err := logs.search(context.Background(), cloudflareRange, policy.LogFilter{Contains: []string{"boom"}}, 2)
		if err != nil {
			t.Fatal(err)
		}
		if found.total != tt.total || found.totalLowerBound != tt.lowerBound || len(*bodies) != tt.requests {
			t.Errorf("%s: total %d, lower bound %v, requests %d", tt.name, found.total, found.totalLowerBound, len(*bodies))
		}
		if found.query != `environment:"production" AND boom` || found.source.Kind != "vercel" {
			t.Errorf("%s: query %q, source %+v", tt.name, found.query, found.source)
		}
	}
}

func TestVercelLogQuery(t *testing.T) {
	logs, bodies := vercelBackend(t, vercelPage(true, "c1", 1))
	result, err := logs.query(context.Background(), cloudflareRange, "level:error", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.series != nil || len(result.streams) != 1 || len(*bodies) != 1 {
		t.Errorf("series %v, streams %v, requests %d", result.series, result.streams, len(*bodies))
	}
	if !strings.Contains((*bodies)[0], `"filter":"environment:\"production\" AND (level:error)"`) || !strings.Contains((*bodies)[0], `"limit":100`) {
		t.Errorf("body %s", (*bodies)[0])
	}
	if _, err := logs.query(context.Background(), cloudflareRange, "level:error) OR (x", 100, ""); err == nil {
		t.Error("query with an unbalanced group accepted")
	}
}
