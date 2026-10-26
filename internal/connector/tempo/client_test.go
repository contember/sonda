package tempo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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

var testRange = api.TimeRange{
	From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	To:   time.Date(2026, 1, 1, 1, 0, 0, 500, time.UTC),
}

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	src := &config.Source{Name: "tempo", Type: config.SourceTempo, URL: server.URL, Headers: map[string]string{"X-Scope-OrgID": "team"}}
	return New(src, upstream.HTTPClient(src, nil))
}

const searchBody = `{"traces":[
	{"traceID":"b6f45c3bab6cb1199fbe53f769f217f","rootServiceName":"svc-b","rootTraceName":"GET /report",
	 "startTimeUnixNano":"1767225600000000000","durationMs":120.5,
	 "spanSet":{"spans":[{"spanID":"009ff9a1e31800a3"}],"matched":1},
	 "spanSets":[
		{"spans":[{"spanID":"009ff9a1e31800a3","name":"render","startTimeUnixNano":"1767225600010000000","durationNanos":"80000000",
		  "attributes":[{"key":"http.status_code","value":{"intValue":"500"}},{"key":"cached","value":{"boolValue":false}}]}],"matched":1},
		{"spans":[{"spanID":"009ff9a1e31800a3","startTimeUnixNano":"1767225600010000000","durationNanos":"80000000"},
		          {"spanID":"ff9a1e31800a3","startTimeUnixNano":"1767225600020000000","durationNanos":"1000"}],"matched":2}],
	 "serviceStats":{"svc-a":{"spanCount":2,"errorCount":1},"svc-b":{"spanCount":3}}},
	{"traceID":"2","rootServiceName":"svc-a","startTimeUnixNano":"1767225600000000000"},
	{"traceID":"3","rootServiceName":"svc-a","startTimeUnixNano":"1767225600000000000"}
],"metrics":{"completedJobs":1}}`

func TestSearch(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		got := map[string]string{
			"path": r.URL.Path, "q": r.FormValue("q"), "start": r.FormValue("start"), "end": r.FormValue("end"),
			"limit": r.FormValue("limit"), "spss": r.FormValue("spss"), "org": r.Header.Get("X-Scope-OrgID"),
		}
		want := map[string]string{
			"path": "/api/search", "q": `{ resource.service.name = "svc-a" }`, "start": "1767225600", "end": "1767229201",
			"limit": "2", "spss": "10", "org": "team",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("request %v, want %v", got, want)
		}
		fmt.Fprint(w, searchBody)
	})
	traces, err := client.Search(context.Background(), testTraceQL(t), testRange, 2)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(0, 1767225600010000000).UTC()
	want := []telemetry.TraceSummary{
		{
			TraceID:     "0b6f45c3bab6cb1199fbe53f769f217f",
			RootService: "svc-b",
			RootName:    "GET /report",
			Start:       time.Unix(0, 1767225600000000000).UTC(),
			Duration:    120500 * time.Microsecond,
			SpanCount:   5,
			ErrorCount:  1,
			Matched: []telemetry.Span{
				{
					TraceID: "0b6f45c3bab6cb1199fbe53f769f217f", SpanID: "009ff9a1e31800a3", Name: "render",
					Start: start, Duration: 80 * time.Millisecond,
					Attributes: map[string]string{"http.status_code": "500", "cached": "false"},
				},
				{
					TraceID: "0b6f45c3bab6cb1199fbe53f769f217f", SpanID: "000ff9a1e31800a3",
					Start: start.Add(10 * time.Millisecond), Duration: time.Microsecond,
				},
			},
		},
		{TraceID: "00000000000000000000000000000002", RootService: "svc-a", Start: time.Unix(0, 1767225600000000000).UTC()},
	}
	if !reflect.DeepEqual(traces, want) {
		t.Errorf("got  %+v\nwant %+v", traces, want)
	}
}

func TestSearchErrors(t *testing.T) {
	tests := []struct {
		status int
		body   string
		code   api.ErrorCode
	}{
		{http.StatusBadRequest, "invalid TraceQL query: parse error", api.CodeInvalidQuery},
		{http.StatusInternalServerError, "boom", api.CodeUpstreamError},
		{http.StatusOK, `{"traces":[{"traceID":"not hex"}]}`, api.CodeUpstreamError},
		{http.StatusOK, `{"traces":[{"traceID":"1","startTimeUnixNano":"soon"}]}`, api.CodeUpstreamError},
	}
	for _, tt := range tests {
		client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.status)
			fmt.Fprint(w, tt.body)
		})
		_, err := client.Search(context.Background(), testTraceQL(t), testRange, 10)
		if e, ok := apierr.As(err); !ok || e.Code != tt.code {
			t.Errorf("HTTP %d %s: %v", tt.status, tt.body, err)
		}
	}
}

// The v2 endpoint writes IDs in base64 and enums as names; other encoders write hex and numbers.
const traceBody = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"svc-b"}}]},
	 "scopeSpans":[{"spans":[{"traceId":"SelmT7RcvzdPQnQk3VrzdQ==","spanId":"6bWsFDcWbmY=","name":"GET /report",
	   "kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1767225600000000000","endTimeUnixNano":"1767225600500000000",
	   "attributes":[{"key":"ratio","value":{"doubleValue":0.5}},{"key":"tags","value":{"arrayValue":{"values":[{"stringValue":"a"},{"intValue":1}]}}}],
	   "status":{"code":"STATUS_CODE_ERROR","message":"failed"}}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"svc-a"}}]},
	 "scopeSpans":[{"spans":[{"traceId":"49e9664fb45cbf374f427424dd5af375","spanId":"b879d1830cdb253b","parentSpanId":"e9b5ac1437166e66",
	   "name":"render","kind":3,"startTimeUnixNano":1767225600050000000,"endTimeUnixNano":"1767225600450000000",
	   "events":[{"timeUnixNano":"1767225600060000000","name":"retry","attributes":[{"key":"attempt","value":{"intValue":"2"}}]}],
	   "status":{}}]}]}
]}}`

func TestTrace(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/traces/49e9664fb45cbf374f427424dd5af375" || r.FormValue("start") != "1767225600" {
			t.Errorf("request %s", r.URL)
		}
		fmt.Fprint(w, traceBody)
	})
	spans, err := client.Trace(context.Background(), "49e9664fb45cbf374f427424dd5af375", testRange)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(0, 1767225600000000000).UTC()
	want := []telemetry.Span{
		{
			TraceID: "49e9664fb45cbf374f427424dd5af375", SpanID: "e9b5ac1437166e66", Service: "svc-b",
			Name: "GET /report", Kind: "SERVER", Start: start, Duration: 500 * time.Millisecond,
			Status: telemetry.StatusError, StatusMessage: "failed",
			Attributes: map[string]string{"ratio": "0.5", "tags": `["a","1"]`},
		},
		{
			TraceID: "49e9664fb45cbf374f427424dd5af375", SpanID: "b879d1830cdb253b", ParentID: "e9b5ac1437166e66",
			Service: "svc-a", Name: "render", Kind: "CLIENT", Start: start.Add(50 * time.Millisecond),
			Duration: 400 * time.Millisecond, Status: telemetry.StatusUnset,
			Events: []telemetry.SpanEvent{{Time: start.Add(60 * time.Millisecond), Name: "retry", Attributes: map[string]string{"attempt": "2"}}},
		},
	}
	if !reflect.DeepEqual(spans, want) {
		t.Errorf("got  %+v\nwant %+v", spans, want)
	}
}

func TestTraceErrors(t *testing.T) {
	tests := []struct {
		status int
		body   string
		code   api.ErrorCode
	}{
		{http.StatusNotFound, "trace not found", api.CodeNotFound},
		{http.StatusOK, `{"trace":{},"metrics":{}}`, api.CodeNotFound},
		{http.StatusBadRequest, "trace IDs can only contain hex characters", api.CodeInvalidQuery},
		{http.StatusBadGateway, "", api.CodeUpstreamError},
		{http.StatusOK, `{"trace":{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"x","spanId":"y"}]}]}]}}`, api.CodeUpstreamError},
		{http.StatusOK, `{"trace":{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"01","spanId":"02","kind":9}]}]}]}}`, api.CodeUpstreamError},
		{http.StatusOK, `{"trace":{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"01","spanId":"02","status":{"code":"BROKEN"}}]}]}]}}`, api.CodeUpstreamError},
	}
	for _, tt := range tests {
		client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.status)
			fmt.Fprint(w, tt.body)
		})
		_, err := client.Trace(context.Background(), "0123456789abcdef", testRange)
		if e, ok := apierr.As(err); !ok || e.Code != tt.code {
			t.Errorf("HTTP %d %s: %v", tt.status, tt.body, err)
		}
	}
}

func testTraceQL(t *testing.T) policy.TraceQL {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  tempo: { type: tempo, url: "http://tempo" }
projects:
  api:
    services:
      api:
        environments:
          production:
            traces: { source: tempo, service: svc-a }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Grants: []identities.Grant{{Project: "api", Environment: "production", Capability: api.CapabilityTraces}}}
	scope, err := authz.New(cfg, nil).TraceScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	tempoScope, _ := scope.Tempo()
	q, err := policy.ScopeTraceQL(tempoScope, "{}")
	if err != nil {
		t.Fatal(err)
	}
	return q
}
