package query

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
)

var cloudflareRange = api.TimeRange{From: time.UnixMilli(1_700_000_000_000).UTC(), To: time.UnixMilli(1_700_003_600_000).UTC()}

// cloudflareBackends serves every request with response and records the request bodies.
func cloudflareBackends(t *testing.T, response string) (logBackend, traceBackend, *[]string) {
	t.Helper()
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":`+response+`}`)
	}))
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(`
sources:
  cf: { type: cloudflare, url: "`+server.URL+`", account_id: acc, auth: { type: bearer, token: t } }
services:
  api:
    environments:
      production:
        logs: { source: cf, script: api-worker }
        traces: { source: cf, script: api-worker }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	a := authz.New(cfg, nil)
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Service: "api", Environment: "production", Capability: api.CapabilityLogs},
		{Service: "api", Environment: "production", Capability: api.CapabilityTraces},
	}}
	logScope, err := a.LogScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	traceScope, err := a.TraceScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	client, err := cloudflare.New(cfg.Sources["cf"])
	if err != nil {
		t.Fatal(err)
	}
	logs, _ := logScope.Cloudflare()
	traces, _ := traceScope.Cloudflare()
	return newCloudflareLogs(logs, client), newCloudflareTraces(traces, client), &bodies
}

func TestCloudflareLogQueryResultForm(t *testing.T) {
	logs, _, _ := cloudflareBackends(t, `{"calculations":[]}`)
	result, err := logs.query(context.Background(), cloudflareRange, `{"view":"calculations","calculations":[{"operator":"count"}]}`, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.series == nil || result.streams != nil {
		t.Errorf("calculations: series %v, streams %v", result.series, result.streams)
	}

	logs, _, bodies := cloudflareBackends(t, `{"events":{"events":[{"$metadata":{"id":"1","service":"api-worker","message":"hi"},"timestamp":1}]}}`)
	result, err = logs.query(context.Background(), cloudflareRange, `{"limit":500}`, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.series != nil || len(result.streams) != 1 {
		t.Errorf("events: series %v, streams %v", result.series, result.streams)
	}
	if !strings.Contains((*bodies)[0], `"limit":100`) || result.source.Kind != "cloudflare" || result.query == "" {
		t.Errorf("body %s, result %+v", (*bodies)[0], result)
	}

	if _, err := logs.query(context.Background(), cloudflareRange, `{"view":"traces"}`, 100, ""); err == nil {
		t.Error("logs query accepted the traces view")
	}
}

func TestCloudflareLogFieldsSorted(t *testing.T) {
	logs, _, _ := cloudflareBackends(t, `[{"key":"b","type":"number","lastSeenAt":1},{"key":"a","type":"string","lastSeenAt":1}]`)
	fields, err := logs.fields(context.Background(), cloudflareRange)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields.Fields) != 2 || fields.Fields[0].Name != "a" || fields.Fields[0].Type != "string" || fields.Labels == nil {
		t.Errorf("fields = %+v", fields)
	}
}

func TestCloudflareTraceSearchHonorsLimit(t *testing.T) {
	_, traces, bodies := cloudflareBackends(t, `{"traces":[
		{"traceId":"t1","service":["api-worker"],"traceStartMs":1},
		{"traceId":"t2","service":["api-worker"],"traceStartMs":2},
		{"traceId":"t3","service":["api-worker"],"traceStartMs":3}
	]}`)
	found, err := traces.search(context.Background(), cloudflareRange, policy.TraceFilter{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(found.traces) != 2 || !strings.Contains((*bodies)[0], `"limit":2`) {
		t.Errorf("traces %+v, body %s", found.traces, (*bodies)[0])
	}
	found, err = traces.query(context.Background(), cloudflareRange, `{"limit":1000}`, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(found.traces) != 2 || !strings.Contains((*bodies)[1], `"view":"traces","limit":2`) {
		t.Errorf("query traces %+v, body %s", found.traces, (*bodies)[1])
	}
}

func TestCloudflareMetricsReportBucketAsStep(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[
			{"sum":{"requests":3},"dimensions":{"scriptName":"api-worker","datetimeHour":"2023-11-14T22:00:00Z"}}
		]}]}}}`)
	}))
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(`
sources:
  cf: { type: cloudflare, url: "`+server.URL+`", account_id: acc, auth: { type: bearer, token: t } }
services:
  api:
    environments:
      production:
        metrics: { source: cf, script: api-worker }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Service: "api", Environment: "production", Capability: api.CapabilityMetrics},
	}}
	scope, err := authz.New(cfg, nil).MetricScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	client, err := cloudflare.New(cfg.Sources["cf"])
	if err != nil {
		t.Fatal(err)
	}
	cf, _ := scope.Cloudflare()
	metrics := newCloudflareMetrics(cf, client)

	result, err := metrics.query(context.Background(), cloudflareRange, `{"metric":"requests"}`, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.step != time.Hour || len(result.series) != 1 || result.query != `{"metric":"requests"}` {
		t.Errorf("result = %+v", result)
	}
	if _, err := metrics.query(context.Background(), cloudflareRange, `{"metric":"requests","scriptName":"other"}`, time.Minute); err == nil {
		t.Error("unknown field accepted")
	}

	infos, err := metrics.names(context.Background(), cloudflareRange)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range infos {
		if info.Help == "" {
			t.Errorf("metric %s has no help", info.Name)
		}
	}
}
