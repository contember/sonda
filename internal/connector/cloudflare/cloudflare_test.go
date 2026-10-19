package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

var testRange = api.TimeRange{From: time.UnixMilli(1_700_000_000_000).UTC(), To: time.UnixMilli(1_700_003_600_000).UTC()}

type request struct {
	path string
	auth string
	body string
}

type fake struct {
	status   int
	response string
	requests []request
}

func (f *fake) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, request{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: string(body)})
	w.Header().Set("Content-Type", "application/json")
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	_, _ = io.WriteString(w, f.response)
}

func setup(t *testing.T, f *fake) (*Client, authz.CloudflareScope) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(`
sources:
  cf: { type: cloudflare, url: "`+server.URL+`/client/v4", account_id: acc-1, auth: { type: bearer, token: secret } }
services:
  api:
    environments:
      production:
        logs: { source: cf, script: api-worker }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Service: "api", Environment: "production", Capability: api.CapabilityLogs},
	}}
	logScope, err := authz.New(cfg, nil).LogScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := logScope.Cloudflare()
	client, err := New(cfg.Sources["cf"])
	if err != nil {
		t.Fatal(err)
	}
	return client, scope
}

func success(result string) string {
	return `{"success":true,"errors":[],"messages":[],"result":` + result + `}`
}

func scopedQuery(t *testing.T, scope authz.CloudflareScope, text string, views ...string) policy.CloudflareQuery {
	t.Helper()
	if len(views) == 0 {
		views = []string{policy.CloudflareViewEvents, policy.CloudflareViewCalculations, policy.CloudflareViewInvocations}
	}
	q, err := policy.ScopeCloudflareQuery(scope, text, views...)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

type sentQuery struct {
	QueryID    string `json:"queryId"`
	View       string `json:"view"`
	Parameters *struct {
		FilterCombination string            `json:"filterCombination"`
		Filters           []json.RawMessage `json:"filters"`
		Datasets          []string          `json:"datasets"`
	} `json:"parameters"`
	Datasets []string `json:"datasets"`
}

const scopeLeaf = `{"key":"$metadata.service","operation":"eq","type":"string","value":"api-worker"}`

func TestLinesRequestAndStreams(t *testing.T) {
	f := &fake{response: success(`{"events":{"count":2,"events":[
		{"$metadata":{"id":"1","service":"api-worker","level":"error","message":"boom"},"$workers":{"scriptName":"api-worker","outcome":"exception","eventType":"fetch","scriptVersion":{"id":"v1"}},"source":"boom","timestamp":1700000001000},
		{"$metadata":{"id":"2","service":"api-worker","level":"log"},"$workers":{"scriptName":"api-worker","eventType":"cron"},"source":{"msg":"hi", "n": 1},"timestamp":1700000002500}
	]}}`)}
	client, scope := setup(t, f)
	q := scopedQuery(t, scope, `{"filters":[{"key":"$metadata.service","operation":"eq","type":"string","value":"other"}]}`)
	streams, err := client.Lines(context.Background(), scope, q, testRange)
	if err != nil {
		t.Fatal(err)
	}

	if len(f.requests) != 1 {
		t.Fatalf("requests = %d", len(f.requests))
	}
	sent := f.requests[0]
	if sent.path != "/client/v4/accounts/acc-1/workers/observability/telemetry/query" || sent.auth != "Bearer secret" {
		t.Errorf("request %s with auth %q", sent.path, sent.auth)
	}
	var body sentQuery
	if err := json.Unmarshal([]byte(sent.body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Parameters == nil || body.Parameters.FilterCombination != "and" || len(body.Parameters.Filters) != 2 || string(body.Parameters.Filters[0]) != scopeLeaf {
		t.Errorf("parameters are not scoped: %s", sent.body)
	}
	if body.Datasets != nil || body.Parameters.Datasets != nil || !strings.HasPrefix(body.QueryID, "sonda-") {
		t.Errorf("body = %s", sent.body)
	}

	want := []telemetry.LogStream{
		{
			Labels:  map[string]string{"service": "api-worker", "level": "error", "outcome": "exception", "eventType": "fetch", "scriptVersion": "v1"},
			Entries: []telemetry.LogEntry{{Time: time.UnixMilli(1700000001000).UTC(), Line: "boom"}},
		},
		{
			Labels:  map[string]string{"service": "api-worker", "level": "log", "eventType": "cron"},
			Entries: []telemetry.LogEntry{{Time: time.UnixMilli(1700000002500).UTC(), Line: `{"msg":"hi","n":1}`}},
		},
	}
	if !reflect.DeepEqual(streams, want) {
		t.Errorf("streams = %+v, want %+v", streams, want)
	}
}

func TestLinesInvocations(t *testing.T) {
	f := &fake{response: success(`{"invocations":{
		"req-b":[{"$metadata":{"id":"2","service":"api-worker","message":"second"},"timestamp":2000}],
		"req-a":[{"$metadata":{"id":"1","service":"api-worker","message":"first"},"timestamp":1000}]
	}}`)}
	client, scope := setup(t, f)
	streams, err := client.Lines(context.Background(), scope, scopedQuery(t, scope, `{"view":"invocations"}`), testRange)
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 2 || streams[0].Labels["requestId"] != "req-a" || streams[1].Entries[0].Line != "second" {
		t.Errorf("streams = %+v", streams)
	}
}

func TestPostCheckRejectsForeignService(t *testing.T) {
	tests := []struct{ name, events string }{
		{"metadata service", `{"$metadata":{"id":"1","service":"other"},"timestamp":1}`},
		{"script name", `{"$metadata":{"id":"1"},"$workers":{"scriptName":"other","eventType":"fetch"},"timestamp":1}`},
		{"no service", `{"$metadata":{"id":"1","message":"x"},"timestamp":1}`},
		{"script name differs from service", `{"$metadata":{"id":"1","service":"api-worker"},"$workers":{"scriptName":"other","eventType":"fetch"},"timestamp":1}`},
	}
	for _, tt := range tests {
		f := &fake{response: success(`{"events":{"events":[{"$metadata":{"id":"0","service":"api-worker"},"timestamp":1},` + tt.events + `]}}`)}
		client, scope := setup(t, f)
		streams, err := client.Lines(context.Background(), scope, scopedQuery(t, scope, `{}`), testRange)
		if !isCode(err, api.CodeInternal) || !strings.Contains(err.Error(), "outside the scope") || streams != nil {
			t.Errorf("%s: streams %v, error %v", tt.name, streams, err)
		}
	}

	f := &fake{response: success(`{"invocations":{"r":[{"$metadata":{"id":"1","service":"other"},"timestamp":1}]}}`)}
	client, scope := setup(t, f)
	if _, err := client.Lines(context.Background(), scope, scopedQuery(t, scope, `{"view":"invocations"}`), testRange); !isCode(err, api.CodeInternal) {
		t.Errorf("invocations: %v", err)
	}

	f = &fake{response: success(`{"traces":[{"traceId":"t1","service":["other"],"spans":1}]}`)}
	client, scope = setup(t, f)
	if _, err := client.Traces(context.Background(), scope, scopedQuery(t, scope, `{}`, policy.CloudflareViewTraces), testRange); !isCode(err, api.CodeInternal) {
		t.Errorf("traces: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		response string
		code     api.ErrorCode
		message  string
	}{
		{"bad request", 400, `{"success":false,"errors":[{"code":10001,"message":"invalid filter key"}],"result":null}`, api.CodeInvalidQuery, "invalid filter key"},
		{"forbidden", 403, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`, api.CodeUpstreamError, "HTTP 403: Authentication error"},
		{"plain body", 502, `bad gateway`, api.CodeUpstreamError, "HTTP 502: bad gateway"},
		{"not successful", 200, `{"success":false,"errors":[{"code":1,"message":"quota exceeded"}],"result":null}`, api.CodeUpstreamError, "quota exceeded"},
		{"invalid json", 200, `{"success":`, api.CodeUpstreamError, "invalid JSON"},
	}
	for _, tt := range tests {
		f := &fake{status: tt.status, response: tt.response}
		client, scope := setup(t, f)
		_, err := client.Lines(context.Background(), scope, scopedQuery(t, scope, `{}`), testRange)
		if !isCode(err, tt.code) || !strings.Contains(err.Error(), tt.message) {
			t.Errorf("%s: error = %v, want %s containing %q", tt.name, err, tt.code, tt.message)
		}
	}
}

const serviceGroupBy = `"groupBys":[{"type":"string","value":"$metadata.service"}]`

func TestCount(t *testing.T) {
	f := &fake{response: success(`{"calculations":[{"calculation":"count","aggregates":[
		{"value":41.6,"count":41.6,"sampleInterval":1,"groups":[{"key":"$metadata.service","value":"api-worker"}]}
	],"series":[]}]}`)}
	client, scope := setup(t, f)
	_, count, err := policy.CloudflareLogSearch(scope, policy.LogFilter{Contains: []string{"x"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	total, err := client.Count(context.Background(), scope, count, testRange)
	if err != nil || total != 42 {
		t.Errorf("total = %d, %v", total, err)
	}
	body := f.requests[0].body
	for _, part := range []string{`"view":"calculations"`, `"calculations":[{"operator":"count"}]`, `"filters":[` + scopeLeaf + `]`, serviceGroupBy} {
		if !strings.Contains(body, part) {
			t.Errorf("count body lacks %s: %s", part, body)
		}
	}
}

func TestCalculations(t *testing.T) {
	f := &fake{response: success(`{"calculations":[
		{"calculation":"count","alias":"n","aggregates":[],"series":[
			{"time":"2023-11-14T22:14:00Z","data":[
				{"value":1,"groups":[{"key":"$metadata.statusCode","value":500},{"key":"$metadata.service","value":"api-worker"}]},
				{"value":2,"groups":[{"key":"$metadata.statusCode","value":200},{"key":"$metadata.service","value":"api-worker"}]}
			]},
			{"time":"2023-11-14T22:13:00Z","data":[{"value":3,"groups":[{"key":"$metadata.statusCode","value":500},{"key":"$metadata.service","value":"api-worker"}]}]}
		]},
		{"calculation":"p99","aggregates":[{"value":12.5,"groups":[{"key":"$metadata.level","value":"error"},{"key":"$metadata.service","value":"api-worker"}]}],"series":[]}
	]}`)}
	client, scope := setup(t, f)
	q := scopedQuery(t, scope, `{"view":"calculations","calculations":[{"operator":"count","alias":"n"}],"groupBys":[{"type":"number","value":"$metadata.statusCode"}]}`)
	matrix, err := client.Calculations(context.Background(), scope, q, testRange)
	if err != nil {
		t.Fatal(err)
	}
	body := f.requests[0].body
	for _, part := range []string{`"filters":[` + scopeLeaf + `]`, `"groupBys":[{"type":"number","value":"$metadata.statusCode"},{"type":"string","value":"$metadata.service"}]`} {
		if !strings.Contains(body, part) {
			t.Errorf("calculations body lacks %s: %s", part, body)
		}
	}
	byLabels := map[string]*model.SampleStream{}
	for _, s := range matrix {
		byLabels[s.Metric.String()] = s
	}
	errors500 := byLabels[`{$metadata.statusCode="500", calculation="n"}`]
	if errors500 == nil || len(errors500.Values) != 2 || errors500.Values[0].Value != 3 || errors500.Values[0].Timestamp.Time().UTC().Format(time.RFC3339) != "2023-11-14T22:13:00Z" {
		t.Errorf("500 series = %+v (all: %v)", errors500, matrix)
	}
	p99 := byLabels[`{$metadata.level="error", calculation="p99"}`]
	if len(matrix) != 3 || p99 == nil || p99.Values[0].Value != 12.5 || !p99.Values[0].Timestamp.Time().Equal(testRange.To) {
		t.Errorf("matrix = %v", matrix)
	}

	f.response = success(`{"calculations":[]}`)
	matrix, err = client.Calculations(context.Background(), scope, q, testRange)
	if err != nil || matrix == nil || len(matrix) != 0 {
		t.Errorf("empty calculations = %v, %v", matrix, err)
	}
}

func TestZeroMatches(t *testing.T) {
	tests := []struct{ name, calculations string }{
		{"no calculations", `[]`},
		{"no aggregates", `[{"calculation":"count","aggregates":[],"series":[]}]`},
		{"zero without service group", `[{"calculation":"count","aggregates":[{"value":0,"count":0,"sampleInterval":1}],"series":[]}]`},
		{"zero series point without service group", `[{"calculation":"count","aggregates":[{"value":0}],"series":[{"time":"2023-11-14T22:14:00Z","data":[{"value":0,"groups":[]}]}]}]`},
	}
	for _, tt := range tests {
		f := &fake{response: success(`{"calculations":` + tt.calculations + `}`)}
		client, scope := setup(t, f)
		_, count, _ := policy.CloudflareLogSearch(scope, policy.LogFilter{}, 10)
		if total, err := client.Count(context.Background(), scope, count, testRange); err != nil || total != 0 {
			t.Errorf("%s count: total %d, error %v", tt.name, total, err)
		}
		matrix, err := client.Calculations(context.Background(), scope, scopedQuery(t, scope, `{"view":"calculations"}`), testRange)
		if err != nil || matrix == nil || len(matrix) != 0 {
			t.Errorf("%s calculations: matrix %v, error %v", tt.name, matrix, err)
		}
	}
}

func TestCalculationsPostCheck(t *testing.T) {
	tests := []struct{ name, calculation string }{
		{"foreign aggregate", `{"calculation":"count","aggregates":[{"value":1,"groups":[{"key":"$metadata.service","value":"other"}]}],"series":[]}`},
		{"non-zero aggregate without service", `{"calculation":"count","aggregates":[{"value":1}],"series":[]}`},
		{"foreign series point", `{"calculation":"count","aggregates":[],"series":[{"time":"2023-11-14T22:14:00Z","data":[
			{"value":1,"groups":[{"key":"$metadata.service","value":"api-worker"}]},{"value":1,"groups":[{"key":"$metadata.service","value":"other"}]}]}]}`},
		{"non-zero series point without service", `{"calculation":"count","aggregates":[],"series":[{"time":"2023-11-14T22:14:00Z","data":[{"value":1,"groups":[]}]}]}`},
	}
	for _, tt := range tests {
		f := &fake{response: success(`{"calculations":[` + tt.calculation + `]}`)}
		client, scope := setup(t, f)
		matrix, err := client.Calculations(context.Background(), scope, scopedQuery(t, scope, `{"view":"calculations"}`), testRange)
		if !isCode(err, api.CodeInternal) || matrix != nil {
			t.Errorf("%s calculations: matrix %v, error %v", tt.name, matrix, err)
		}
		_, count, _ := policy.CloudflareLogSearch(scope, policy.LogFilter{}, 10)
		if total, err := client.Count(context.Background(), scope, count, testRange); !isCode(err, api.CodeInternal) || total != 0 {
			t.Errorf("%s count: total %d, error %v", tt.name, total, err)
		}
	}
}

func TestTraces(t *testing.T) {
	f := &fake{response: success(`{"traces":[
		{"traceId":"t1","rootSpanName":"GET /","rootTransactionName":"tx","service":["api-worker"],"spans":4,"traceDurationMs":12.5,"traceStartMs":1700000000000,"traceEndMs":1700000000012,"errors":["boom"]},
		{"traceId":"t2","rootSpanName":"","rootTransactionName":"queue","service":["gateway","api-worker"],"spans":2,"traceDurationMs":1,"traceStartMs":1700000001000}
	]}`)}
	client, scope := setup(t, f)
	q, err := policy.CloudflareTraceSearch(scope, policy.TraceFilter{Errors: true}, 3)
	if err != nil {
		t.Fatal(err)
	}
	traces, err := client.Traces(context.Background(), scope, q, testRange)
	if err != nil {
		t.Fatal(err)
	}
	want := []telemetry.TraceSummary{
		{TraceID: "t1", RootService: "api-worker", RootName: "GET /", Start: time.UnixMilli(1700000000000).UTC(), Duration: 12500 * time.Microsecond, SpanCount: 4, ErrorCount: 1},
		{TraceID: "t2", RootName: "queue", Start: time.UnixMilli(1700000001000).UTC(), Duration: time.Millisecond, SpanCount: 2},
	}
	if len(traces) != len(want) {
		t.Fatalf("traces = %+v", traces)
	}
	for i := range want {
		if traces[i].TraceID != want[i].TraceID || traces[i].RootService != want[i].RootService || traces[i].RootName != want[i].RootName ||
			!traces[i].Start.Equal(want[i].Start) || traces[i].Duration != want[i].Duration || traces[i].SpanCount != want[i].SpanCount || traces[i].ErrorCount != want[i].ErrorCount {
			t.Errorf("trace %d = %+v, want %+v", i, traces[i], want[i])
		}
	}
	if !strings.Contains(f.requests[0].body, `"view":"traces"`) || !strings.Contains(f.requests[0].body, scopeLeaf) {
		t.Errorf("body = %s", f.requests[0].body)
	}
}

func TestTraceSpans(t *testing.T) {
	f := &fake{response: success(`{"events":{"events":[
		{"$metadata":{"id":"1","service":"gateway","traceId":"abc","spanId":"s1","spanName":"fetch","startTime":1700000000000,"duration":20,"trigger":"GET /"},"$workers":{"scriptName":"gateway","eventType":"fetch","outcome":"ok","cpuTimeMs":3},"timestamp":1700000000000},
		{"$metadata":{"id":"2","service":"api-worker","traceId":"abc","spanId":"s2","parentSpanId":"s1","spanName":"kv_get","startTime":1700000000005,"duration":2.5,"error":"KV timeout"},"timestamp":1700000000005},
		{"$metadata":{"id":"3","service":"api-worker","traceId":"abc","spanId":"s2","message":"log inside span"},"timestamp":1700000000006},
		{"$metadata":{"id":"4","service":"api-worker","traceId":"abc","spanId":"s2","spanName":"kv_get","startTime":1700000000005},"timestamp":1700000000005}
	]}}`)}
	client, scope := setup(t, f)
	spans, err := client.Trace(context.Background(), policy.CloudflareTraceByID(scope, "abc"), testRange)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 {
		t.Fatalf("spans = %+v", spans)
	}
	root, child := spans[0], spans[1]
	if root.Service != "gateway" || root.Name != "fetch" || root.Duration != 20*time.Millisecond || root.Status != telemetry.StatusUnset ||
		root.Attributes["$metadata.trigger"] != "GET /" || root.Attributes["$workers.cpuTimeMs"] != "3" || root.Attributes["$workers.outcome"] != "ok" {
		t.Errorf("root = %+v", root)
	}
	if child.ParentID != "s1" || child.TraceID != "abc" || child.Status != telemetry.StatusError || child.StatusMessage != "KV timeout" ||
		child.Duration != 2500*time.Microsecond || !child.Start.Equal(time.UnixMilli(1700000000005)) {
		t.Errorf("child = %+v", child)
	}
	wantFilters := `"filters":[{"key":"$metadata.traceId","operation":"eq","type":"string","value":"abc"},{"key":"$metadata.spanName","operation":"exists","type":"string"}]`
	if !strings.Contains(f.requests[0].body, wantFilters) {
		t.Errorf("body = %s", f.requests[0].body)
	}
}

func TestTraceSpanLimit(t *testing.T) {
	q := policy.CloudflareTraceByID(authz.CloudflareScope{}, "abc")
	events := make([]string, q.Limit())
	for i := range events {
		events[i] = `{"$metadata":{"id":"e","service":"api-worker","spanId":"s` + strconv.Itoa(i) + `","spanName":"x"},"timestamp":1}`
	}
	f := &fake{response: success(`{"events":{"events":[` + strings.Join(events, ",") + `]}}`)}
	client, _ := setup(t, f)
	spans, err := client.Trace(context.Background(), q, testRange)
	if !isCode(err, api.CodeLimitExceeded) || !strings.Contains(err.Error(), "2000 spans") || spans != nil {
		t.Errorf("spans %d, error %v", len(spans), err)
	}
}

func TestKeys(t *testing.T) {
	f := &fake{response: success(`[{"key":"$metadata.level","type":"string","lastSeenAt":1700000000000},{"key":"$metadata.statusCode","type":"number","lastSeenAt":1}]`)}
	client, scope := setup(t, f)
	keys, err := client.Keys(context.Background(), scope, testRange)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[1].Key != "$metadata.statusCode" || keys[1].Type != "number" {
		t.Errorf("keys = %+v", keys)
	}
	sent := f.requests[0]
	if sent.path != "/client/v4/accounts/acc-1/workers/observability/telemetry/keys" || !strings.Contains(sent.body, `"filters":[`+scopeLeaf+`]`) {
		t.Errorf("request %s %s", sent.path, sent.body)
	}
}

type sentGraphQL struct {
	Query     string            `json:"query"`
	Variables map[string]string `json:"variables"`
}

func TestMetric(t *testing.T) {
	f := &fake{response: `{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[
		{"sum":{"requests":5},"dimensions":{"scriptName":"api-worker","status":"success","datetimeFifteenMinutes":"2023-11-14T22:30:00Z"}},
		{"sum":{"requests":2},"dimensions":{"scriptName":"api-worker","status":"clientError","datetimeFifteenMinutes":"2023-11-14T22:15:00Z"}},
		{"sum":{"requests":7},"dimensions":{"scriptName":"api-worker","status":"success","datetimeFifteenMinutes":"2023-11-14T22:15:00Z"}}
	]}]}},"errors":null}`}
	client, scope := setup(t, f)
	m := telemetry.CloudflareMetricQuery{Metric: "requests", By: []string{"status"}}
	matrix, step, err := client.Metric(context.Background(), scope, m, testRange, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if step != 15*time.Minute {
		t.Errorf("effective step = %s", step)
	}

	sent := f.requests[0]
	if sent.path != "/client/v4/graphql" || sent.auth != "Bearer secret" {
		t.Errorf("request %s with auth %q", sent.path, sent.auth)
	}
	var body sentGraphQL
	if err := json.Unmarshal([]byte(sent.body), &body); err != nil {
		t.Fatal(err)
	}
	wantVariables := map[string]string{
		"accountTag":    "acc-1",
		"scriptName":    "api-worker",
		"datetimeStart": "2023-11-14T22:13:20Z",
		"datetimeEnd":   "2023-11-14T23:13:20Z",
	}
	for name, value := range wantVariables {
		if body.Variables[name] != value {
			t.Errorf("variable %s = %q, want %q", name, body.Variables[name], value)
		}
	}
	if strings.Contains(body.Query, "api-worker") || strings.Contains(body.Query, "acc-1") {
		t.Errorf("scope is interpolated into the query: %s", body.Query)
	}
	for _, part := range []string{"sum { requests }", "dimensions { scriptName datetimeFifteenMinutes status }", "scriptName: $scriptName", "orderBy: [datetimeFifteenMinutes_ASC]"} {
		if !strings.Contains(body.Query, part) {
			t.Errorf("query lacks %q: %s", part, body.Query)
		}
	}

	if len(matrix) != 2 {
		t.Fatalf("matrix = %v", matrix)
	}
	for _, s := range matrix {
		switch s.Metric["status"] {
		case "success":
			if len(s.Values) != 2 || s.Values[0].Value != 7 || s.Values[1].Value != 5 {
				t.Errorf("success = %v", s.Values)
			}
		case "clientError":
			if len(s.Values) != 1 || s.Values[0].Value != 2 {
				t.Errorf("clientError = %v", s.Values)
			}
		default:
			t.Errorf("unexpected series %v", s.Metric)
		}
	}
}

func TestMetricBuckets(t *testing.T) {
	tests := []struct {
		step time.Duration
		want string
	}{
		{15 * time.Second, "datetimeMinute"},
		{time.Minute, "datetimeMinute"},
		{5 * time.Minute, "datetimeFifteenMinutes"},
		{15 * time.Minute, "datetimeFifteenMinutes"},
		{30 * time.Minute, "datetimeHour"},
		{time.Hour, "datetimeHour"},
		{2 * time.Hour, "date"},
		{24 * time.Hour, "date"},
		{48 * time.Hour, "date"},
	}
	for _, tt := range tests {
		if got := bucketFor(tt.step).field; got != tt.want {
			t.Errorf("step %s: bucket %s, want %s", tt.step, got, tt.want)
		}
	}
}

func TestMetricRequestDurationByDay(t *testing.T) {
	f := &fake{response: `{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[
		{"quantiles":{"requestDurationP99":2500},"dimensions":{"scriptName":"api-worker","date":"2023-11-14"}}
	]}]}}}`}
	client, scope := setup(t, f)
	matrix, step, err := client.Metric(context.Background(), scope, telemetry.CloudflareMetricQuery{Metric: "duration_p99"}, testRange, 3*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.requests[0].body, "quantiles { requestDurationP99 }") || !strings.Contains(f.requests[0].body, "orderBy: [date_ASC]") {
		t.Errorf("body = %s", f.requests[0].body)
	}
	if step != 24*time.Hour || len(matrix) != 1 || matrix[0].Values[0].Value != 2.5 ||
		matrix[0].Values[0].Timestamp.Time().UTC().Format(time.DateOnly) != "2023-11-14" {
		t.Errorf("step %s, matrix %v", step, matrix)
	}
}

func TestMetricRowLimit(t *testing.T) {
	rows := make([]string, maxInvocationRows)
	for i := range rows {
		rows[i] = `{"sum":{"requests":1},"dimensions":{"scriptName":"api-worker","datetimeMinute":"2023-11-14T22:15:00Z"}}`
	}
	f := &fake{response: `{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[` + strings.Join(rows, ",") + `]}]}}}`}
	client, scope := setup(t, f)
	matrix, _, err := client.Metric(context.Background(), scope, telemetry.CloudflareMetricQuery{Metric: "requests"}, testRange, time.Minute)
	if !isCode(err, api.CodeLimitExceeded) || matrix != nil {
		t.Errorf("matrix %d series, error %v", len(matrix), err)
	}
}

func TestMetricCatalogIsComplete(t *testing.T) {
	for _, name := range telemetry.CloudflareMetrics {
		if _, ok := metricFields[name]; !ok {
			t.Errorf("metric %s has no GraphQL field", name)
		}
	}
	for _, name := range telemetry.CloudflareDimensions {
		if _, ok := dimensionFields[name]; !ok {
			t.Errorf("dimension %s has no GraphQL field", name)
		}
	}
}

func TestMetricErrors(t *testing.T) {
	tests := []struct {
		name     string
		response string
		code     api.ErrorCode
		message  string
	}{
		{"graphql error", `{"data":null,"errors":[{"message":"not authorized for that account"}]}`, api.CodeUpstreamError, "not authorized"},
		{"no data", `{"data":null,"errors":null}`, api.CodeUpstreamError, "no GraphQL data"},
		{"foreign script", `{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[{"sum":{"requests":1},"dimensions":{"scriptName":"other","datetimeMinute":"2023-11-14T22:15:00Z"}}]}]}}}`, api.CodeInternal, "outside the scope"},
	}
	for _, tt := range tests {
		f := &fake{response: tt.response}
		client, scope := setup(t, f)
		_, _, err := client.Metric(context.Background(), scope, telemetry.CloudflareMetricQuery{Metric: "requests"}, testRange, time.Minute)
		if !isCode(err, tt.code) || !strings.Contains(err.Error(), tt.message) {
			t.Errorf("%s: error = %v, want %s containing %q", tt.name, err, tt.code, tt.message)
		}
	}
}

func isCode(err error, code api.ErrorCode) bool {
	e, ok := apierr.As(err)
	return ok && e.Code == code
}
