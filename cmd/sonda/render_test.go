package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
)

func TestRenderTrace(t *testing.T) {
	start := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	resp := api.Response[api.Trace]{Data: api.Trace{
		TraceID:  "4bf92f3577b34da6a3ce929d0e0e4736",
		Services: []string{"engine-api", "tenant-api"},
		Spans: []api.Span{
			{SpanID: "a", Depth: 0, Service: "engine-api", Granted: true, Name: "POST /graphql", Start: start, DurationMs: 412.34, Status: "error"},
			{SpanID: "b", ParentID: "a", Depth: 1, Service: "engine-api", Granted: true, Name: "SELECT", Start: start, DurationMs: 1250},
			{SpanID: "c", ParentID: "b", Depth: 2, Service: "tenant-api", Start: start, DurationMs: 15},
		},
	}}
	want := []string{
		"# trace 4bf92f3577b34da6a3ce929d0e0e4736: engine-api, tenant-api",
		"engine-api        POST /graphql  412.3ms  error",
		"  engine-api      SELECT         1.25s",
		"    [tenant-api]  (not granted)  15.0ms",
	}

	var out bytes.Buffer
	renderTrace(&out, resp)
	if got := trimLines(out.String()); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRenderTraceSearch(t *testing.T) {
	start := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	resp := api.Response[api.TraceSearchResult]{Data: api.TraceSearchResult{
		Query: `{ resource.service.name = "engine-api" }`,
		Traces: []api.TraceSummary{
			{TraceID: "t1", RootService: "engine-api", RootName: "POST /graphql", Start: start, DurationMs: 412.3, Matched: []api.Span{{SpanID: "a"}, {SpanID: "b"}}},
			{TraceID: "t2", RootService: "tenant-api", Start: start, DurationMs: 15},
		},
	}}
	stamp := start.Local().Format(time.Stamp)
	want := []string{
		`# { resource.service.name = "engine-api" }`,
		"TRACE  ROOT                      START            DURATION  MATCHED",
		"t1     engine-api POST /graphql  " + stamp + "  412.3ms   2",
		"t2     tenant-api                " + stamp + "  15.0ms    -",
	}

	var out bytes.Buffer
	renderTraceSearch(&out, resp)
	if got := trimLines(out.String()); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFormatCapability(t *testing.T) {
	backends := map[api.Capability]api.BackendInfo{
		api.CapabilityErrors: {Source: "sentry"},
		api.CapabilityLogs:   {Source: "cloudflare", Dialect: api.DialectCloudflareQuery},
	}
	tests := []struct {
		capability api.Capability
		want       string
	}{
		{api.CapabilityErrors, "errors(sentry)"},
		{api.CapabilityLogs, "logs(cloudflare: cloudflare-query)"},
		{api.CapabilityTraces, "traces"},
	}
	for _, tt := range tests {
		if got := formatCapability(tt.capability, backends); got != tt.want {
			t.Errorf("formatCapability(%s) = %q, want %q", tt.capability, got, tt.want)
		}
	}
}

// trimLines drops the trailing padding that tabwriter leaves before an empty last column.
func trimLines(s string) []string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " ")
	}
	return lines
}

func TestRenderWorkloads(t *testing.T) {
	at := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	resp := api.Response[api.Workloads]{Data: api.Workloads{
		Pods: []api.Pod{{Name: "engine-api-7d9f-x2k4p", Phase: "Running", Restarts: 4, Containers: []api.Container{
			{Name: "app", State: "waiting", Reason: "CrashLoopBackOff", LastTermination: &api.Termination{Reason: "OOMKilled", ExitCode: 137, Finished: at}},
		}}},
		Rollouts: []api.Rollout{{Name: "engine-api-7d9f", Revision: "12", Created: at, Replicas: 2, ReadyReplicas: 1, Images: []string{"engine:1.4"}}},
		Events:   []api.WorkloadEvent{{Type: "Warning", Reason: "BackOff", Object: "Pod/engine-api-7d9f-x2k4p", Message: "Back-off restarting", Count: 9, LastSeen: at}},
	}}
	want := []string{
		"",
		"PODS",
		"  engine-api-7d9f-x2k4p  Running  not ready  restarts=4  app: CrashLoopBackOff; app last exit: OOMKilled (137) at 2026-10-26T10:00:00Z",
		"",
		"ROLLOUTS",
		"  engine-api-7d9f  rev 12  2026-10-26T10:00:00Z  1/2 ready  engine:1.4",
		"",
		"EVENTS",
		"  2026-10-26T10:00:00Z Warning BackOff Pod/engine-api-7d9f-x2k4p ×9: Back-off restarting",
	}
	var out bytes.Buffer
	renderWorkloads(&out, resp)
	if got := trimLines(out.String()); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
