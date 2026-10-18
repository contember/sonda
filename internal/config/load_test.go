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
admin:
  token: "${ADMIN_TOKEN}"
limits:
  max_range: 3d
  max_log_lines: 100
`

func validEnv() map[string]string {
	return map[string]string{"SENTRY_TOKEN": "secret", "ADMIN_TOKEN": strings.Repeat("a", 32)}
}

func env(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Sources["sentry"].Auth.Token; got != "secret" {
		t.Errorf("token = %q, want expanded env value", got)
	}
	if got := cfg.Sources["sentry"].URL; got != "https://sentry.io" {
		t.Errorf("sentry url default = %q", got)
	}
	if cfg.Admin == nil || cfg.Admin.Token != validEnv()["ADMIN_TOKEN"] {
		t.Errorf("admin = %+v", cfg.Admin)
	}
	if cfg.Limits.MaxRange != 3*24*time.Hour || cfg.Limits.MaxLogLines != 100 {
		t.Errorf("limits not applied: %+v", cfg.Limits)
	}
	if cfg.Limits.RequestsPerMinute != DefaultLimits.RequestsPerMinute {
		t.Errorf("default limit not inherited: %d", cfg.Limits.RequestsPerMinute)
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
		{"short admin token", [2]string{`"${ADMIN_TOKEN}"`, "too-short"}, "at least 32 characters"},
		{"unknown field", [2]string{"max_range: 3d", "max_rang: 3d"}, "field max_rang not found"},
		{"bad duration", [2]string{"max_range: 3d", "max_range: soon"}, "invalid duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := validEnv()
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
