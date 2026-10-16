package config

import (
	"strings"
	"testing"
	"time"
)

const validConfig = `
sources:
  sentry:
    type: sentry
    org: acme
    auth: { type: bearer, token: "${SENTRY_TOKEN}" }
  loki:
    type: loki
    url: http://loki:3100
    headers: { X-Scope-OrgID: prod }
  prom:
    type: prometheus
    url: http://prometheus:9090
services:
  api:
    environments:
      production:
        errors: { source: sentry, project: api, environment: production }
        logs: { source: loki, selector: '{app="api"}' }
        metrics: { source: prom, selector: '{job="api"}' }
    signals:
      rps: sum(rate(http_requests_total[5m]))
identities:
  agent:
    token_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    grants:
      - { services: [api], environments: [production], capabilities: [errors, logs] }
    limits: { max_log_lines: 100 }
limits:
  max_range: 3d
`

func env(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), env(map[string]string{"SENTRY_TOKEN": "secret"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Sources["sentry"].Auth.Token; got != "secret" {
		t.Errorf("token = %q, want expanded env value", got)
	}
	if got := cfg.Sources["sentry"].URL; got != "https://sentry.io" {
		t.Errorf("sentry url default = %q", got)
	}
	identity := cfg.Identities["agent"]
	if identity.Limits.MaxLogLines != 100 {
		t.Errorf("identity override not applied: %d", identity.Limits.MaxLogLines)
	}
	if identity.Limits.MaxRange != 3*24*time.Hour {
		t.Errorf("server limit not inherited: %v", identity.Limits.MaxRange)
	}
	if identity.Limits.RequestsPerMinute != DefaultLimits.RequestsPerMinute {
		t.Errorf("default limit not inherited: %d", identity.Limits.RequestsPerMinute)
	}
	if got := len(cfg.Services["api"].Environments["production"].Logs.Matchers); got != 1 {
		t.Errorf("log matchers = %d", got)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"missing env var", [2]string{"", ""}, "SENTRY_TOKEN is not set"},
		{"unknown source", [2]string{"source: loki,", "source: nope,"}, `unknown source "nope"`},
		{"wrong source type", [2]string{"source: loki,", "source: prom,"}, "expected loki"},
		{"selector matching everything", [2]string{`{job="api"}`, `{job!=""}`}, "rejects the empty value"},
		{"invalid selector", [2]string{`{app="api"}`, `{app=}`}, "selector"},
		{"invalid signal", [2]string{"sum(rate(http_requests_total[5m]))", "sum(("}, "invalid PromQL"},
		{"unknown capability", [2]string{"[errors, logs]", "[errors, traces]"}, `unknown capability "traces"`},
		{"unknown grant service", [2]string{"services: [api]", "services: [web]"}, `unknown service "web"`},
		{"unknown grant environment", [2]string{"environments: [production]", "environments: [staging]"}, `"staging" is not an environment`},
		{"bad token hash", [2]string{"token_sha256: 0000", "token_sha256: zz00"}, "64 hex characters"},
		{"unknown field", [2]string{"max_range: 3d", "max_rang: 3d"}, "field max_rang not found"},
		{"bad duration", [2]string{"max_range: 3d", "max_range: soon"}, "invalid duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := map[string]string{"SENTRY_TOKEN": "secret"}
			input := validConfig
			if tt.replace[0] == "" {
				vars = nil
			} else {
				input = strings.Replace(input, tt.replace[0], tt.replace[1], 1)
			}
			_, err := Parse([]byte(input), env(vars))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
