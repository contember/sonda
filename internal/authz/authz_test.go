package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	hash := sha256.Sum256([]byte("token-a"))
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
identities:
  agent:
    token_sha256: ` + hex.EncodeToString(hash[:]) + `
    grants:
      - { services: [api], environments: [production, staging], capabilities: [logs] }
      - { services: [api], environments: [production], capabilities: [metrics] }
`
	cfg, err := config.Parse([]byte(yaml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAuthenticate(t *testing.T) {
	a := New(testConfig(t))
	if identity, ok := a.Authenticate("token-a"); !ok || identity.Name != "agent" {
		t.Fatalf("valid token rejected")
	}
	if _, ok := a.Authenticate("token-b"); ok {
		t.Fatalf("invalid token accepted")
	}
	if _, ok := a.Authenticate(""); ok {
		t.Fatalf("empty token accepted")
	}
}

func TestScopes(t *testing.T) {
	a := New(testConfig(t))
	identity, _ := a.Authenticate("token-a")

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
	a := New(testConfig(t))
	identity, _ := a.Authenticate("token-a")
	scope, _ := a.LogScope(identity, "api", "production")
	scope.Matchers()[0].Value = "billing"
	if got := scope.Matchers()[0].Value; got != "api" {
		t.Fatalf("scope mutated through Matchers(): %s", got)
	}
}

func TestServicesListsOnlyGranted(t *testing.T) {
	a := New(testConfig(t))
	identity, _ := a.Authenticate("token-a")
	services := a.Services(identity)
	if len(services) != 1 || services[0].Name != "api" {
		t.Fatalf("services = %v", services)
	}
}

func hasCode(err error, code api.ErrorCode) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == code
}
