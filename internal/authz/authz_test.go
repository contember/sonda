package authz

import (
	"context"
	"crypto/sha256"
	"errors"
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
	if got := scope.Selector(); got != `{app="api", env="staging"}` {
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
	scope, _ := a.LogScope(identity, "api", "production")
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

func hasCode(err error, code api.ErrorCode) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == code
}
