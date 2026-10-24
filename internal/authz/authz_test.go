package authz

import (
	"context"
	"crypto/sha256"
	"errors"
	"maps"
	"path/filepath"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/store"
)

func testAuthorizer(t *testing.T) *Authorizer {
	t.Helper()
	yaml := `
sources:
  loki: { type: loki, url: "http://loki:3100" }
  prom: { type: prometheus, url: "http://prom:9090" }
services:
  api:
    environments:
      production:
        logs: { source: loki, selector: '{app="api", env="prod"}' }
        metrics: { source: prom, selector: '{job="api"}' }
      staging:
        logs: { source: loki, selector: '{app="api", env="staging"}' }
  billing:
    environments:
      production:
        logs: { source: loki, selector: '{app="billing"}' }
limits:
  max_log_lines: 200
`
	cfg, err := config.Parse([]byte(yaml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "sonda.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	requestsPerMinute := 30
	err = st.Create(context.Background(), identities.Identity{
		Name:        "agent",
		TokenSHA256: sha256.Sum256([]byte("token-a")),
		Grants: []identities.Grant{
			{Service: "api", Environment: "production", Capability: api.CapabilityLogs},
			{Service: "api", Environment: "staging", Capability: api.CapabilityLogs},
			{Service: "api", Environment: "production", Capability: api.CapabilityMetrics},
		},
		Limits:    identities.LimitOverrides{RequestsPerMinute: &requestsPerMinute},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, st)
}

func authenticate(t *testing.T, a *Authorizer) *Identity {
	t.Helper()
	identity, err := a.Authenticate(context.Background(), "token-a")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestAuthenticate(t *testing.T) {
	a := testAuthorizer(t)
	identity := authenticate(t, a)
	if identity.Name != "agent" {
		t.Fatalf("identity = %s", identity.Name)
	}
	if identity.Limits.RequestsPerMinute != 30 || identity.Limits.MaxLogLines != 200 {
		t.Errorf("limits = %+v, want the override and the server limit", identity.Limits)
	}
	for _, token := range []string{"token-b", ""} {
		if _, err := a.Authenticate(context.Background(), token); !hasCode(err, api.CodeUnauthenticated) {
			t.Errorf("token %q: %v", token, err)
		}
	}
}

func TestScopes(t *testing.T) {
	a := testAuthorizer(t)
	identity := authenticate(t, a)

	scope, err := a.LogScope(identity, "api", "staging")
	if err != nil {
		t.Fatal(err)
	}
	if got := lokiScope(t, scope).Selector(); got != `{app="api", env="staging"}` {
		t.Errorf("selector = %s", got)
	}

	// Only one environment has metrics, so it is chosen without an explicit name.
	metrics, err := a.MetricScope(identity, "api", "")
	if err != nil || metrics.Environment() != "production" {
		t.Fatalf("metric scope = %v, %v", metrics.Environment(), err)
	}

	if _, err := a.LogScope(identity, "api", ""); !hasCode(err, api.CodeInvalidRequest) {
		t.Errorf("ambiguous environment: %v", err)
	}
	if _, err := a.MetricScope(identity, "api", "staging"); !hasCode(err, api.CodeNotFound) {
		t.Errorf("ungranted capability in environment: %v", err)
	}
	if _, err := a.LogScope(identity, "billing", "production"); !hasCode(err, api.CodeNotFound) {
		t.Errorf("ungranted service: %v", err)
	}
	if _, err := a.ErrorScope(identity, "api", "production"); !hasCode(err, api.CodeNotFound) {
		t.Errorf("unconfigured capability: %v", err)
	}

	// The same error for unknown and forbidden services hides which services exist.
	_, unknown := a.Service(identity, "nope")
	_, forbidden := a.Service(identity, "billing")
	if unknown.Error() != `not_found: service "nope" not found` || forbidden.Error() != `not_found: service "billing" not found` {
		t.Errorf("errors differ in shape: %v / %v", unknown, forbidden)
	}
}

func TestScopeMatchersAreCopies(t *testing.T) {
	a := testAuthorizer(t)
	identity := authenticate(t, a)
	logs, _ := a.LogScope(identity, "api", "production")
	scope := lokiScope(t, logs)
	scope.Matchers()[0].Value = "billing"
	if got := scope.Matchers()[0].Value; got != "api" {
		t.Fatalf("scope mutated through Matchers(): %s", got)
	}
}

func TestServicesListsOnlyGranted(t *testing.T) {
	a := testAuthorizer(t)
	identity := authenticate(t, a)
	services := a.Services(identity)
	if len(services) != 1 || services[0].Name != "api" {
		t.Fatalf("services = %v", services)
	}
}

func lokiScope(t *testing.T, scope LogScope) SelectorScope {
	t.Helper()
	loki, ok := scope.Loki()
	if !ok {
		t.Fatalf("scope of %s is not a Loki scope", scope.Source().Type)
	}
	return loki
}

func hasCode(err error, code api.ErrorCode) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == code
}

func backendsAuthorizer(t *testing.T) *Authorizer {
	t.Helper()
	yaml := `
sources:
  sentry: { type: sentry, org: acme, auth: { type: bearer, token: t } }
  loki: { type: loki, url: "http://loki" }
  prom: { type: prometheus, url: "http://prom" }
  cf: { type: cloudflare, account_id: acc, auth: { type: bearer, token: t } }
  aws: { type: aws, region: eu-west-1 }
  tempo: { type: tempo, url: "http://tempo" }
  tempo-eu: { type: tempo, url: "http://tempo-eu" }
  content: { type: contember, url: "http://engine", auth: { type: bearer, token: t } }
services:
  worker:
    environments:
      production:
        logs: { source: cf, script: worker }
        metrics: { source: cf, script: worker }
        traces: { source: cf, script: worker }
  db:
    environments:
      production:
        errors: { source: sentry, project: db, environment: production }
        logs: { source: aws, log_groups: [/aws/rds/db] }
        metrics: { source: aws, namespace: AWS/RDS, dimensions: { DBClusterIdentifier: db } }
        traces: { source: tempo, service: db }
        data: { source: content, project: db, entities: [Order], deny_fields: ["*.email", Order.note] }
  api:
    environments:
      production:
        logs: { source: loki, selector: '{app="api"}' }
        metrics: { source: prom, selector: '{job="api"}' }
        traces: { source: tempo, service: api }
  billing:
    environments:
      production:
        traces: { source: tempo, service: billing }
  billing-eu:
    environments:
      production:
        traces: { source: tempo-eu, service: billing }
`
	cfg, err := config.Parse([]byte(yaml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, nil)
}

func grantAll(services ...string) *Identity {
	identity := &Identity{Name: "agent"}
	for _, svc := range services {
		for _, capability := range []api.Capability{api.CapabilityErrors, api.CapabilityLogs, api.CapabilityMetrics, api.CapabilityTraces} {
			identity.Grants = append(identity.Grants, identities.Grant{Service: svc, Environment: "production", Capability: capability})
		}
	}
	return identity
}

func TestLogScopeVariants(t *testing.T) {
	a := backendsAuthorizer(t)
	identity := grantAll("worker", "db", "api")

	worker, err := a.LogScope(identity, "worker", "")
	if err != nil {
		t.Fatal(err)
	}
	cf, ok := worker.Cloudflare()
	if !ok || cf.AccountID() != "acc" || cf.Script() != "worker" || worker.Dialect() != api.DialectCloudflareQuery {
		t.Errorf("cloudflare scope = %+v, %v", cf, ok)
	}
	if _, ok := worker.Loki(); ok {
		t.Error("cloudflare log scope is also a Loki scope")
	}
	if _, ok := worker.CloudWatch(); ok {
		t.Error("cloudflare log scope is also a CloudWatch scope")
	}

	db, err := a.LogScope(identity, "db", "")
	if err != nil {
		t.Fatal(err)
	}
	groups, ok := db.CloudWatch()
	if !ok || db.Dialect() != api.DialectLogsInsights {
		t.Fatalf("db log scope is not a CloudWatch scope")
	}
	groups.LogGroups()[0] = "/aws/rds/billing"
	if got := groups.LogGroups(); len(got) != 1 || got[0] != "/aws/rds/db" {
		t.Errorf("scope mutated through LogGroups(): %v", got)
	}

	apiLogs, err := a.LogScope(identity, "api", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := lokiScope(t, apiLogs).Selector(); got != `{app="api"}` || apiLogs.Dialect() != api.DialectLogQL {
		t.Errorf("loki selector = %s", got)
	}
	if _, ok := apiLogs.Cloudflare(); ok {
		t.Error("loki log scope is also a Cloudflare scope")
	}
}

func TestMetricScopeVariants(t *testing.T) {
	a := backendsAuthorizer(t)
	identity := grantAll("worker", "db", "api")

	worker, err := a.MetricScope(identity, "worker", "")
	if err != nil {
		t.Fatal(err)
	}
	if cf, ok := worker.Cloudflare(); !ok || cf.Script() != "worker" || worker.Dialect() != api.DialectCloudflareMetric {
		t.Errorf("cloudflare metric scope = %+v, %v", cf, ok)
	}

	db, err := a.MetricScope(identity, "db", "")
	if err != nil {
		t.Fatal(err)
	}
	cw, ok := db.CloudWatch()
	if !ok || cw.Namespace() != "AWS/RDS" || db.Dialect() != api.DialectCloudWatchMetric {
		t.Fatalf("cloudwatch metric scope = %+v, %v", cw, ok)
	}
	cw.Dimensions()["DBClusterIdentifier"] = "billing"
	if got := cw.Dimensions()["DBClusterIdentifier"]; got != "db" {
		t.Errorf("scope mutated through Dimensions(): %s", got)
	}
	if _, ok := db.Prometheus(); ok {
		t.Error("cloudwatch metric scope is also a Prometheus scope")
	}

	apiScope, err := a.MetricScope(identity, "api", "")
	if err != nil {
		t.Fatal(err)
	}
	if prom, ok := apiScope.Prometheus(); !ok || prom.Selector() != `{job="api"}` || apiScope.Dialect() != api.DialectPromQL {
		t.Errorf("prometheus scope = %+v, %v", prom, ok)
	}
}

func TestTraceScopeVariants(t *testing.T) {
	a := backendsAuthorizer(t)
	identity := grantAll("worker", "db")

	worker, err := a.TraceScope(identity, "worker", "")
	if err != nil {
		t.Fatal(err)
	}
	if cf, ok := worker.Cloudflare(); !ok || cf.Script() != "worker" || worker.ServiceName() != "worker" || worker.Dialect() != api.DialectCloudflareQuery {
		t.Errorf("cloudflare trace scope = %+v, %v", cf, ok)
	}
	if _, ok := worker.Tempo(); ok {
		t.Error("cloudflare trace scope is also a Tempo scope")
	}

	db, err := a.TraceScope(identity, "db", "")
	if err != nil {
		t.Fatal(err)
	}
	tempo, ok := db.Tempo()
	if !ok || tempo.ServiceName() != "db" || db.ServiceName() != "db" || db.Dialect() != api.DialectTraceQL {
		t.Errorf("tempo trace scope = %+v, %v", tempo, ok)
	}
	if _, err := a.TraceScope(identity, "api", ""); !hasCode(err, api.CodeNotFound) {
		t.Errorf("ungranted traces: %v", err)
	}
}

func TestTraceVisibility(t *testing.T) {
	a := backendsAuthorizer(t)
	identity := grantAll("api", "db", "billing-eu")
	scope, err := a.TraceScope(identity, "api", "")
	if err != nil {
		t.Fatal(err)
	}
	visible := a.TraceVisibility(identity, scope)
	tests := []struct {
		service string
		want    bool
	}{
		{"api", true},
		// Granted, on the same source.
		{"db", true},
		// Granted only on another source, which records a different service under that name.
		{"billing", false},
		{"worker", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		if got := visible(tt.service); got != tt.want {
			t.Errorf("visible(%q) = %v, want %v", tt.service, got, tt.want)
		}
	}

	onlyLogs := &Identity{Name: "agent", Grants: []identities.Grant{
		{Service: "api", Environment: "production", Capability: api.CapabilityTraces},
		{Service: "db", Environment: "production", Capability: api.CapabilityLogs},
	}}
	scope, err = a.TraceScope(onlyLogs, "api", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.TraceVisibility(onlyLogs, scope)("db") {
		t.Error("service without a traces grant is visible")
	}
}

func TestEnvironmentBackends(t *testing.T) {
	a := backendsAuthorizer(t)
	identity := grantAll("db")
	svc, err := a.Service(identity, "db")
	if err != nil {
		t.Fatal(err)
	}
	envs := a.Environments(identity, svc)
	if len(envs) != 1 {
		t.Fatalf("environments = %+v", envs)
	}
	want := map[api.Capability]api.BackendInfo{
		api.CapabilityErrors:  {Source: "sentry"},
		api.CapabilityLogs:    {Source: "aws", Dialect: api.DialectLogsInsights},
		api.CapabilityMetrics: {Source: "aws", Dialect: api.DialectCloudWatchMetric},
		api.CapabilityTraces:  {Source: "tempo", Dialect: api.DialectTraceQL},
	}
	if !maps.Equal(envs[0].Backends, want) {
		t.Errorf("backends = %+v", envs[0].Backends)
	}
}

func TestDataScope(t *testing.T) {
	a := backendsAuthorizer(t)
	identity := grantAll("db")
	if _, err := a.DataScope(identity, "db", ""); !hasCode(err, api.CodeNotFound) {
		t.Fatalf("data without a data grant: %v", err)
	}
	identity.Grants = append(identity.Grants, identities.Grant{Service: "db", Environment: "production", Capability: api.CapabilityData})
	scope, err := a.DataScope(identity, "db", "")
	if err != nil {
		t.Fatal(err)
	}
	cs, ok := scope.Contember()
	if !ok || cs.Project() != "db" || cs.Stage() != "live" || scope.Dialect() != api.DialectContemberGraphQL {
		t.Fatalf("contember scope = %+v, %v", cs, ok)
	}
	if !cs.Denied("Customer", "email") || !cs.Denied("Order", "note") || cs.Denied("Customer", "note") {
		t.Error("deny_fields not applied")
	}
	entities := cs.Entities()
	entities[0] = "Changed"
	if cs.Entities()[0] != "Order" {
		t.Error("Entities is not a copy")
	}
	backends := a.Environments(identity, a.cfg.Services["db"])[0].Backends
	if backends[api.CapabilityData] != (api.BackendInfo{Source: "contember", Dialect: api.DialectContemberGraphQL}) {
		t.Errorf("data backend = %+v", backends[api.CapabilityData])
	}
}
