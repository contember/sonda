package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/query"
	"github.com/contember/sonda/internal/store"
)

// upstreams fakes Prometheus, Loki and Sentry and records the queries they receive.
type upstreams struct {
	mu      sync.Mutex
	queries []string
}

func (u *upstreams) record(q string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.queries = append(u.queries, q)
}

func (u *upstreams) last() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.queries[len(u.queries)-1]
}

func (u *upstreams) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/query_range", func(w http.ResponseWriter, r *http.Request) {
		u.record(r.FormValue("query"))
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"api"},"values":[[1700000000,"1"],[1700000060,"3"]]}]}}`)
	})
	mux.HandleFunc("/loki/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		u.record(r.FormValue("query"))
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1700000000,"30"]}]}}`)
	})
	mux.HandleFunc("/loki/api/v1/query_range", func(w http.ResponseWriter, r *http.Request) {
		u.record(r.FormValue("query"))
		now := time.Now().UnixNano()
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"api"},"values":[
			["%d","level=error msg=\"db timeout\" password=hunter2 attempt=1"],
			["%d","level=error msg=\"db timeout\" password=hunter2 attempt=2"],
			["%d","level=info msg=\"request done\" path=/x status=200"]]}]}}`, now, now-1, now-2)
	})
	mux.HandleFunc("/api/0/projects/acme/api/issues/", func(w http.ResponseWriter, r *http.Request) {
		u.record(r.FormValue("query") + " env=" + r.FormValue("environment"))
		fmt.Fprint(w, `[
			{"id":"1","shortId":"API-1","title":"Timeout","count":"10","userCount":2,"firstSeen":"2026-01-01T00:00:00Z","lastSeen":"2026-01-02T00:00:00Z","project":{"slug":"api"}},
			{"id":"2","shortId":"BILLING-1","title":"Leak","count":"5","userCount":1,"firstSeen":"2026-01-01T00:00:00Z","lastSeen":"2026-01-02T00:00:00Z","project":{"slug":"billing"}}]`)
	})
	for project, fixture := range map[string]string{"shop": "contember_reader.json", "shopw": "contember_writer.json"} {
		mux.HandleFunc("POST /content/"+project+"/live", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Query string `json:"query"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if strings.Contains(body.Query, "__schema") {
				data, _ := os.ReadFile(filepath.Join("..", "gqlguard", "testdata", fixture))
				_, _ = w.Write(data)
				return
			}
			if strings.Contains(body.Query, "_Relation") {
				data, _ := os.ReadFile(filepath.Join("..", "gqlguard", "testdata", strings.TrimSuffix(fixture, ".json")+"_relations.json"))
				_, _ = w.Write(data)
				return
			}
			u.record(body.Query)
			fmt.Fprint(w, `{"data":{"listArticle":[{"title":"Hello","secret":"password=hunter2"}]},"extensions":{"dbQueries":["select"]}}`)
		})
	}
	mux.HandleFunc("/api/0/organizations/acme/issues/2/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"2","project":{"slug":"billing"}}`)
	})
	return mux
}

type testEnv struct {
	server   *httptest.Server
	upstream *upstreams
	dbPath   string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	up := &upstreams{}
	fake := httptest.NewServer(up.handler())
	t.Cleanup(fake.Close)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
sources:
  sentry: { type: sentry, url: %[1]q, org: acme, auth: { type: bearer, token: s } }
  loki: { type: loki, url: %[1]q }
  prom: { type: prometheus, url: %[1]q }
  tempo: { type: tempo, url: %[1]q }
  cf: { type: cloudflare, url: %[1]q, account_id: acc, auth: { type: bearer, token: t } }
  content: { type: contember, url: %[1]q, auth: { type: bearer, token: c } }
services:
  shop:
    environments:
      production:
        data: { source: content, project: shop, deny_fields: [Article.secretNote, "*.email"] }
  shopw:
    environments:
      production:
        data: { source: content, project: shopw }
  api:
    environments:
      production:
        errors: { source: sentry, project: api, environment: production }
        logs: { source: loki, selector: '{app="api"}' }
        metrics: { source: prom, selector: '{job="api"}' }
        traces: { source: tempo, service: api }
    signals:
      rps: sum(rate(http_requests_total[5m]))
  billing:
    environments:
      production:
        logs: { source: loki, selector: '{app="billing"}' }
  worker:
    environments:
      production:
        logs: { source: cf, script: worker }
`, fake.URL)), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "sonda.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	requestsPerMinute := 6
	for _, identity := range []identities.Identity{
		{
			Name:        "agent",
			TokenSHA256: sha256.Sum256([]byte("agent-token")),
			Grants: []identities.Grant{
				{Service: "api", Environment: "production", Capability: api.CapabilityErrors},
				{Service: "api", Environment: "production", Capability: api.CapabilityLogs},
				{Service: "api", Environment: "production", Capability: api.CapabilityMetrics},
				{Service: "api", Environment: "production", Capability: api.CapabilityTraces},
				{Service: "worker", Environment: "production", Capability: api.CapabilityLogs},
				{Service: "shop", Environment: "production", Capability: api.CapabilityData},
				{Service: "shopw", Environment: "production", Capability: api.CapabilityData},
			},
		},
		{
			Name:        "other",
			TokenSHA256: sha256.Sum256([]byte("other-token")),
			Grants: []identities.Grant{
				{Service: "api", Environment: "production", Capability: api.CapabilityLogs},
				{Service: "billing", Environment: "production", Capability: api.CapabilityLogs},
			},
			Limits: identities.LimitOverrides{RequestsPerMinute: &requestsPerMinute},
		},
	} {
		if err := st.Create(context.Background(), identity); err != nil {
			t.Fatal(err)
		}
	}
	authorizer := authz.New(cfg, st)
	connectors, err := query.NewConnectors(cfg)
	if err != nil {
		t.Fatal(err)
	}
	q, err := query.New(cfg, authorizer, connectors, st)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(q, authorizer, st, slog.New(slog.NewTextHandler(io.Discard, nil))))
	t.Cleanup(server.Close)
	return &testEnv{server: server, upstream: up, dbPath: dbPath}
}

func (e *testEnv) call(t *testing.T, token, method, path string, body any, out any) int {
	t.Helper()
	var payload io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		payload = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, e.server.URL+path, payload)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

func TestMetricsQueryIsScopedUpstream(t *testing.T) {
	env := newTestEnv(t)
	var resp api.Response[api.MetricResult]
	status := env.call(t, "agent-token", "POST", "/v1/services/api/metrics/query",
		api.MetricQueryRequest{Query: `up or up{job="billing"}`}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if got, want := env.upstream.last(), `up{job="api"} or up{job="api",job="billing"}`; got != want {
		t.Errorf("upstream received %s, want %s", got, want)
	}
	if len(resp.Data.Series) != 1 || *resp.Data.Series[0].Summary.Last != 3 {
		t.Errorf("series = %+v", resp.Data.Series)
	}
}

func TestLogSearchGroupsRedactsAndProtectsResults(t *testing.T) {
	env := newTestEnv(t)
	var resp api.Response[api.LogSearchResult]
	status := env.call(t, "agent-token", "POST", "/v1/services/api/logs/search",
		api.LogSearchRequest{Contains: []string{"timeout"}}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if resp.Data.Total != 30 || resp.Data.SampleSize != 3 || !resp.Meta.Sampled || resp.Meta.ResultID == "" {
		t.Fatalf("result = %+v meta = %+v", resp.Data, resp.Meta)
	}
	for _, g := range resp.Data.Groups {
		if strings.Contains(g.Example, "hunter2") || strings.Contains(g.Pattern, "hunter2") {
			t.Errorf("secret not redacted: %+v", g)
		}
	}

	path := "/v1/results/" + resp.Meta.ResultID
	var page api.Response[api.ResultPage]
	if status := env.call(t, "agent-token", "GET", path+"?group=0", nil, &page); status != http.StatusOK || page.Data.Total != 2 {
		t.Errorf("owner page: status %d, %+v", status, page.Data)
	}
	if status := env.call(t, "other-token", "GET", path, nil, nil); status != http.StatusNotFound {
		t.Errorf("other identity read the result: status %d", status)
	}
}

func TestSentryIssuesOfOtherProjectsAreHidden(t *testing.T) {
	env := newTestEnv(t)
	var list api.Response[[]api.Issue]
	if status := env.call(t, "agent-token", "GET", "/v1/services/api/errors", nil, &list); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if len(list.Data) != 1 || list.Data[0].ID != "1" {
		t.Errorf("issues = %+v", list.Data)
	}
	if got := env.upstream.last(); got != "is:unresolved env=production" {
		t.Errorf("upstream query = %s", got)
	}
	if status := env.call(t, "agent-token", "GET", "/v1/services/api/errors/2", nil, nil); status != http.StatusNotFound {
		t.Errorf("issue of another project: status %d", status)
	}
}

func TestAuthorizationErrors(t *testing.T) {
	env := newTestEnv(t)
	var errResp api.ErrorResponse
	if status := env.call(t, "wrong", "GET", "/v1/services", nil, &errResp); status != http.StatusUnauthorized || errResp.Error.Code != api.CodeUnauthenticated {
		t.Errorf("bad token: %d %+v", status, errResp)
	}
	if status := env.call(t, "agent-token", "GET", "/v1/services/billing", nil, &errResp); status != http.StatusNotFound {
		t.Errorf("ungranted service: %d", status)
	}
	if status := env.call(t, "other-token", "POST", "/v1/services/api/metrics/query", api.MetricQueryRequest{Query: "up"}, nil); status != http.StatusNotFound {
		t.Errorf("ungranted capability: %d", status)
	}
}

func TestRateLimitAndAudit(t *testing.T) {
	env := newTestEnv(t)
	// requests_per_minute 6 gives a burst of one request.
	if status := env.call(t, "other-token", "GET", "/v1/services", nil, nil); status != http.StatusOK {
		t.Fatalf("first request: %d", status)
	}
	var errResp api.ErrorResponse
	if status := env.call(t, "other-token", "GET", "/v1/services", nil, &errResp); status != http.StatusTooManyRequests || errResp.Error.Code != api.CodeRateLimited {
		t.Errorf("second request: %d %+v", status, errResp)
	}
	env.call(t, "agent-token", "POST", "/v1/services/api/metrics/query", api.MetricQueryRequest{Query: "up"}, nil)
	env.call(t, "wrong", "GET", "/v1/services", nil, nil)

	db, err := sql.Open("sqlite", env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT identity, status, error_code, service, queries FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var identity, code, service, queries string
		var status int
		if err := rows.Scan(&identity, &status, &code, &service, &queries); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s %d %s %s %s", identity, status, code, service, queries))
	}
	want := []string{
		"other 200   ",
		"other 429 rate_limited  ",
		`agent 200  api up{job="api"}`,
		" 401 unauthenticated  ",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestOverviewReportsPartialFailures(t *testing.T) {
	env := newTestEnv(t)
	var resp api.Response[api.Overview]
	if status := env.call(t, "agent-token", "GET", "/v1/services/api/overview", nil, &resp); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	o := resp.Data
	// The fake Sentry has no releases endpoint, so only that part fails.
	if o.Releases == nil || !strings.Contains(o.Releases.Error, "HTTP 404") {
		t.Errorf("releases = %+v", o.Releases)
	}
	if o.Issues == nil || o.Issues.Error != "" || len(o.Issues.Items) != 1 {
		t.Errorf("issues = %+v", o.Issues)
	}
	if len(o.Signals) != 1 || o.Signals[0].Name != "rps" || len(o.Signals[0].Series) != 1 {
		t.Errorf("signals = %+v", o.Signals)
	}
}

func TestTracesAreAuthorizedBeforeTheBackend(t *testing.T) {
	env := newTestEnv(t)
	requests := []struct {
		method, path string
		body         any
		// The fake upstream has no Tempo API, so a granted request ends with this backend error.
		wantMessage string
	}{
		{"POST", "/traces/search", api.TraceSearchRequest{MinDuration: "1s"}, "source tempo returned HTTP 404"},
		{"POST", "/traces/query", api.TraceQueryRequest{Query: "{}"}, "source tempo returned HTTP 404"},
		{"GET", "/traces/0123456789ABCDEF", nil, `trace "0123456789abcdef" not found for service "api"`},
	}
	for _, req := range requests {
		var errResp api.ErrorResponse
		status := env.call(t, "agent-token", req.method, "/v1/services/api"+req.path, req.body, &errResp)
		if !strings.Contains(errResp.Error.Message, req.wantMessage) {
			t.Errorf("%s granted: %d %+v", req.path, status, errResp)
		}
		errResp = api.ErrorResponse{}
		status = env.call(t, "agent-token", req.method, "/v1/services/billing"+req.path, req.body, &errResp)
		if status != http.StatusNotFound || errResp.Error.Message != `service "billing" not found` {
			t.Errorf("%s of ungranted service: %d %+v", req.path, status, errResp)
		}
	}

	var errResp api.ErrorResponse
	if status := env.call(t, "other-token", "POST", "/v1/services/api/traces/search", api.TraceSearchRequest{}, &errResp); status != http.StatusNotFound || errResp.Error.Code != api.CodeNotFound {
		t.Errorf("ungranted traces capability: %d %+v", status, errResp)
	}
	if status := env.call(t, "agent-token", "GET", "/v1/services/api/traces/not-a-trace-id", nil, &errResp); status != http.StatusBadRequest || errResp.Error.Code != api.CodeInvalidRequest {
		t.Errorf("invalid trace ID: %d %+v", status, errResp)
	}
	if status := env.call(t, "agent-token", "POST", "/v1/services/api/traces/search", api.TraceSearchRequest{MinDuration: "2s", MaxDuration: "1s"}, &errResp); status != http.StatusBadRequest || errResp.Error.Code != api.CodeInvalidRequest {
		t.Errorf("invalid duration range: %d %+v", status, errResp)
	}
}

func TestLogSearchWhere(t *testing.T) {
	env := newTestEnv(t)
	var resp api.Response[api.LogSearchResult]
	status := env.call(t, "agent-token", "POST", "/v1/services/api/logs/search",
		api.LogSearchRequest{Where: []string{"level=error", `user!=a"b`}}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	want := `{app="api"} | level="error" | user!="a\"b"`
	if resp.Data.Query != want || env.upstream.last() != want {
		t.Errorf("query = %s, upstream received %s, want %s", resp.Data.Query, env.upstream.last(), want)
	}

	var errResp api.ErrorResponse
	status = env.call(t, "agent-token", "POST", "/v1/services/api/logs/search", api.LogSearchRequest{Where: []string{"level"}}, &errResp)
	if status != http.StatusBadRequest || errResp.Error.Code != api.CodeInvalidRequest {
		t.Errorf("invalid where: %d %+v", status, errResp)
	}
}

func TestPipelineIsLokiOnly(t *testing.T) {
	env := newTestEnv(t)
	var errResp api.ErrorResponse
	status := env.call(t, "agent-token", "POST", "/v1/services/worker/logs/search", api.LogSearchRequest{Pipeline: "| json"}, &errResp)
	if status != http.StatusBadRequest || !strings.Contains(errResp.Error.Message, "pipeline is supported only for Loki sources") {
		t.Errorf("pipeline on cloudflare: %d %+v", status, errResp)
	}
	errResp = api.ErrorResponse{}
	status = env.call(t, "agent-token", "POST", "/v1/services/worker/logs/search", api.LogSearchRequest{Contains: []string{"x"}}, &errResp)
	if status != http.StatusBadGateway || errResp.Error.Code != api.CodeUpstreamError {
		t.Errorf("cloudflare search: %d %+v", status, errResp)
	}
}

func TestDataSchemaHidesDeniedFields(t *testing.T) {
	env := newTestEnv(t)
	var resp api.Response[api.DataSchema]
	if status := env.call(t, "agent-token", "GET", "/v1/services/shop/data/schema", nil, &resp); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if len(resp.Data.Entities) != 3 {
		t.Fatalf("entities = %+v", resp.Data.Entities)
	}
	for _, e := range resp.Data.Entities {
		for _, f := range e.Fields {
			if f.Name == "secretNote" || f.Name == "email" {
				t.Errorf("%s.%s is visible", e.Name, f.Name)
			}
		}
	}
}

func TestDataQueryIsNormalizedAndRedacted(t *testing.T) {
	env := newTestEnv(t)
	var resp api.Response[api.DataQueryResult]
	status := env.call(t, "agent-token", "POST", "/v1/services/shop/data/query", api.DataQueryRequest{
		Query:     `query($n: Int!) { listArticle(limit: $n) { ...F } } fragment F on Article { title }`,
		Variables: json.RawMessage(`{"n": 5}`),
	}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	want := `query { listArticle(limit: 5) { title } }`
	if got := env.upstream.last(); got != want {
		t.Errorf("upstream received %s, want %s", got, want)
	}
	if resp.Data.Query != want || resp.Data.Rows != 5 {
		t.Errorf("result = %+v", resp.Data)
	}
	if strings.Contains(string(resp.Data.Data), "hunter2") || strings.Contains(string(resp.Data.Data), "dbQueries") {
		t.Errorf("data not redacted or extensions leaked: %s", resp.Data.Data)
	}
	if len(resp.Meta.Untrusted) == 0 {
		t.Error("data not marked untrusted")
	}
}

func TestDataQueryRejectsDeniedFieldBeforeUpstream(t *testing.T) {
	env := newTestEnv(t)
	var resp api.ErrorResponse
	status := env.call(t, "agent-token", "POST", "/v1/services/shop/data/query", api.DataQueryRequest{
		Query: `{ listArticle(limit: 1, filter: {secretNote: {isNull: false}}) { id } }`,
	}, &resp)
	if status != http.StatusBadRequest || resp.Error.Code != api.CodeInvalidQuery {
		t.Fatalf("status %d, error %+v", status, resp.Error)
	}
	env.upstream.mu.Lock()
	defer env.upstream.mu.Unlock()
	if len(env.upstream.queries) != 0 {
		t.Errorf("upstream received %v", env.upstream.queries)
	}
}

func TestDataRefusesWriteKey(t *testing.T) {
	env := newTestEnv(t)
	var resp api.ErrorResponse
	status := env.call(t, "agent-token", "POST", "/v1/services/shopw/data/query", api.DataQueryRequest{
		Query: `{ listArticle(limit: 1) { id } }`,
	}, &resp)
	if status != http.StatusBadGateway || !strings.Contains(resp.Error.Message, "can write") {
		t.Fatalf("status %d, error %+v", status, resp.Error)
	}
}

func TestDataNeedsDataGrant(t *testing.T) {
	env := newTestEnv(t)
	var resp api.ErrorResponse
	if status := env.call(t, "other-token", "GET", "/v1/services/shop/data/schema", nil, &resp); status != http.StatusNotFound {
		t.Fatalf("status %d", status)
	}
}
