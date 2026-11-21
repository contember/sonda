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
	want := []string{
		`# { resource.service.name = "engine-api" }`,
		"TRACE  ROOT                      START                 DURATION  MATCHED",
		"t1     engine-api POST /graphql  2026-10-19T10:00:00Z  412.3ms   2",
		"t2     tenant-api                2026-10-19T10:00:00Z  15.0ms    -",
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
			{Name: "app", Image: "engine:1.4", Digest: "sha256:abc", State: "waiting", Reason: "CrashLoopBackOff", LastTermination: &api.Termination{Reason: "OOMKilled", ExitCode: 137, Finished: at}},
			{Name: "sidecar", Image: "proxy:2"},
		}}},
		Rollouts: []api.Rollout{{Name: "engine-api-7d9f", Revision: "12", Created: at, Replicas: 2, ReadyReplicas: 1, Images: []string{"engine:1.4"}}},
		Events: []api.WorkloadEvent{
			{Type: "Warning", Reason: "BackOff", Object: "Pod/engine-api-7d9f-x2k4p", Message: "Back-off restarting", Count: 9, LastSeen: at},
			{Type: "Normal", Object: "Service/web", Message: "(service web) has reached a steady state.", Count: 1, LastSeen: at},
		},
	}}
	want := []string{
		"",
		"PODS",
		"  engine-api-7d9f-x2k4p  Running  not ready  restarts=4  -  app: CrashLoopBackOff; app last exit: OOMKilled (137) at 2026-10-26T10:00:00Z",
		"",
		"IMAGES",
		"  engine:1.4 sha256:abc  containers=1",
		"  proxy:2 -  containers=1",
		"",
		"ROLLOUTS",
		"  engine-api-7d9f  rev 12  2026-10-26T10:00:00Z  1/2 ready  engine:1.4",
		"",
		"EVENTS",
		"  2026-10-26T10:00:00Z Warning BackOff Pod/engine-api-7d9f-x2k4p ×9: Back-off restarting",
		"  2026-10-26T10:00:00Z Normal Service/web ×1: (service web) has reached a steady state.",
	}
	var out bytes.Buffer
	renderWorkloads(&out, resp)
	if got := trimLines(out.String()); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRenderAlerts(t *testing.T) {
	at := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	resp := api.Response[[]api.Alert]{
		Meta: api.Meta{Service: "engine", Environment: "production"},
		Data: []api.Alert{
			{Name: "ErrorRate", State: "firing", StateReason: "Error", ActiveAt: &at, Annotations: map[string]string{"description": "5xx above 1%"}},
			{Name: "HighLatency", State: "pending", ActiveAt: &at, Value: "2.4", Annotations: map[string]string{"summary": "p99 above 2s", "description": "long"}},
		},
	}
	want := []string{
		"# engine/production now",
		"  firing (Error)  ErrorRate    since 2026-10-26T10:00:00Z  value=-    5xx above 1%",
		"  pending         HighLatency  since 2026-10-26T10:00:00Z  value=2.4  p99 above 2s",
	}
	var out bytes.Buffer
	renderAlerts(&out, resp)
	if got := trimLines(out.String()); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRenderResources(t *testing.T) {
	at := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	days := 20
	resp := api.Response[api.Resources]{Data: api.Resources{
		Databases: []api.Database{{
			Identifier: "shop-db", Kind: "cluster", Engine: "aurora-postgresql", EngineVersion: "16.4", VersionStatus: "available", Status: "available",
			Upgrades:            api.Upgrades{Minor: []string{"16.6"}, Major: []string{}},
			Support:             []api.SupportPeriod{{Name: "open-source-rds-standard-support", End: &at}},
			BackupRetentionDays: 7, BackupWindow: "02:00-03:00", LatestRestorableTime: &at, MaintenanceWindow: "sun:04:00-sun:05:00",
			PendingMaintenance: []api.MaintenanceItem{{Action: "system-update", AutoAppliedAfter: &at, Description: "New OS"}},
			Members:            []api.DatabaseInstance{{Identifier: "shop-db-1", Writer: true, Class: "db.r6g.large", Status: "available", CA: "rds-ca-rsa2048-g1", CAValidTill: &at}},
			Snapshots:          []api.DatabaseSnapshot{{Identifier: "rds:shop-db-1", Type: "automated", Created: &at, Status: "available"}},
		}},
		Certificates: []api.Certificate{{Domain: "shop.example.com", Status: "ISSUED", NotAfter: &at, DaysLeft: &days, RenewalEligibility: "ELIGIBLE", InUseBy: []string{}}},
		Functions:    []api.Function{{Name: "shop-resize", Runtime: "nodejs18.x", State: "Active"}},
		Events:       []api.ResourceEvent{{Time: at, Source: "db-cluster/shop-db", Message: "Backup completed"}},
	}}
	want := []string{
		"",
		"cluster shop-db  aurora-postgresql 16.4  available",
		"  version: available",
		"  upgrades: minor=16.6  major=-",
		"  support: open-source-rds-standard-support until 2026-10-26",
		"  backups: retention=7d window=02:00-03:00 latest restorable=2026-10-26T10:00:00Z",
		"  maintenance: window=sun:04:00-sun:05:00 autoMinor=false",
		"  pending system-update  auto after 2026-10-26  New OS",
		"  instance shop-db-1 writer  db.r6g.large  available  ca=rds-ca-rsa2048-g1 until 2026-10-26",
		"  snapshot rds:shop-db-1  automated  2026-10-26T10:00:00Z  available",
		"",
		"certificate shop.example.com  ISSUED  expires 2026-10-26 (20d left)  renewal=ELIGIBLE",
		"  in use by: -",
		"",
		"function shop-resize  nodejs18.x  Active  last modified -",
		"",
		"EVENTS",
		"  2026-10-26T10:00:00Z  db-cluster/shop-db  Backup completed",
	}
	var out bytes.Buffer
	renderResources(&out, resp)
	if got := trimLines(out.String()); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRenderEmptyOverviewSaysWhy(t *testing.T) {
	var out bytes.Buffer
	renderOverview(&out, api.Response[api.Overview]{})
	if !strings.Contains(out.String(), "nothing to summarize") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestRenderObjects(t *testing.T) {
	three := 3
	resp := api.Response[api.WorkloadObjects]{Meta: api.Meta{Service: "engine-api", Environment: "production"}, Data: api.WorkloadObjects{
		Controllers: []api.Controller{{Kind: "Deployment", Name: "engine-api", Replicas: &three, ReadyReplicas: 2, Strategy: "RollingUpdate",
			Containers: []api.ContainerSpec{{Name: "app", Image: "engine:2", Env: []string{"PORT"}, SecretEnv: []string{"DB_PASSWORD"}}}}},
		ConfigMaps:   []api.ConfigMap{{Name: "engine-env", Missing: true}},
		Applications: []api.Application{{Name: "engine", Sync: "Synced", Health: "Healthy", Resources: []api.AppResource{{Object: "Deployment/engine-api", Sync: "Synced", Health: "Healthy"}}}},
	}}
	var out bytes.Buffer
	renderObjects(&out, resp)
	for _, want := range []string{
		"Deployment/engine-api  2/3 ready, RollingUpdate",
		"env PORT",
		"env from secrets DB_PASSWORD",
		"engine-env  MISSING",
		"Deployment/engine-api sync=Synced health=Healthy",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRenderNodes(t *testing.T) {
	resp := api.Response[api.Workloads]{Data: api.Workloads{Nodes: []api.Node{{
		Name: "ip-10-0-1-1", Ready: true, InstanceType: "m6i.large", KubeletVersion: "v1.33.1",
		Allocatable: map[string]string{"cpu": "1930m", "memory": "7Gi"}, Usage: &api.Usage{CPUMillicores: 500, MemoryBytes: 2 << 30},
	}}}}
	var out bytes.Buffer
	renderWorkloads(&out, resp)
	if !strings.Contains(out.String(), "cpu 500m/1930m mem 2048Mi/7Gi") || strings.Contains(out.String(), "PODS") {
		t.Errorf("output:\n%s", out.String())
	}
}
