package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
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
	if got := len(cfg.Services["api"].Environments["production"].Logs.Selector.Matchers); got != 1 {
		t.Errorf("log matchers = %d", got)
	}
}

func TestSecretFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentry_token")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := validEnv()
	delete(vars, "SENTRY_TOKEN")
	vars["SENTRY_TOKEN_FILE"] = path
	cfg, err := Parse([]byte(validConfig), env(vars))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Sources["sentry"].Auth.Token; got != "from-file" {
		t.Errorf("token = %q", got)
	}

	vars["SENTRY_TOKEN_FILE"] = filepath.Join(t.TempDir(), "missing")
	if _, err := Parse([]byte(validConfig), env(vars)); err == nil || !strings.Contains(err.Error(), "read SENTRY_TOKEN_FILE") {
		t.Errorf("missing file: error = %v", err)
	}
}

func TestSecretFilePrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentry_token")
	if err := os.WriteFile(path, []byte("from-file\r\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		vars map[string]string
		want string
	}{
		{"value wins over file", map[string]string{"SENTRY_TOKEN": "from-env", "SENTRY_TOKEN_FILE": path}, "from-env"},
		{"empty value falls back to file", map[string]string{"SENTRY_TOKEN": "", "SENTRY_TOKEN_FILE": path}, "from-file"},
		{"file only", map[string]string{"SENTRY_TOKEN_FILE": path}, "from-file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := validEnv()
			delete(vars, "SENTRY_TOKEN")
			for k, v := range tt.vars {
				vars[k] = v
			}
			cfg, err := Parse([]byte(validConfig), env(vars))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Sources["sentry"].Auth.Token; got != tt.want {
				t.Errorf("token = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGrafanaURLRefusesCredentials(t *testing.T) {
	input := validConfig + "grafana:\n  url: https://admin:grafpw@grafana.example.com\n"
	_, err := Parse([]byte(input), env(validEnv()))
	if err == nil || !strings.Contains(err.Error(), "grafana.url must not contain a username or password") || strings.Contains(err.Error(), "grafpw") {
		t.Errorf("error = %v", err)
	}
}

func TestSensitiveHeader(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization": true, "Proxy-Authorization": true, "Cookie": true, "X-Api-Key": true,
		"X-Auth-Token": true, "X-Sentry-Auth": true, "X-Scope-OrgID": false, "Monkey": false, "Accept": false,
	} {
		if got := sensitiveHeader(name); got != want {
			t.Errorf("sensitiveHeader(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestURLChecks(t *testing.T) {
	input := strings.Replace(validConfig, "url: http://loki:3100", "url: http://user:pw@loki:3100", 1)
	cfg, err := Parse([]byte(input), env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Warnings, "\n"); !strings.Contains(got, "sources.loki.url contains a password") || strings.Contains(got, "pw") {
		t.Errorf("warnings = %q", got)
	}
	for _, bad := range []string{"http://user:12#34@loki:3100", "http://user:123/abc@loki:3100", "http://user:123?x=1@loki:3100", "http://u:a@bb/c@loki:3100", "http://u:a@bb?c@loki:3100", "http://u:ab/cd@loki:3100"} {
		input = strings.Replace(validConfig, "url: http://loki:3100", `url: "`+bad+`"`, 1)
		_, err = Parse([]byte(input), env(validEnv()))
		if err == nil || !strings.Contains(err.Error(), "sources.loki.url: invalid URL") || !strings.Contains(err.Error(), "percent-encode") ||
			strings.Contains(err.Error(), "123") || strings.Contains(err.Error(), "12#") || strings.Contains(err.Error(), "bb") || strings.Contains(err.Error(), "ab/") {
			t.Errorf("%s: error = %v", bad, err)
		}
	}
	// A literal password next to a host from the environment still warns; a referenced one does not.
	vars := validEnv()
	vars["LOKI_HOST"], vars["LOKI_PASS"] = "loki:3100", "pw"
	for url, warn := range map[string]bool{"https://user:hunter2@${LOKI_HOST}": true, "https://user:${LOKI_PASS}@${LOKI_HOST}": false} {
		input = strings.Replace(validConfig, "url: http://loki:3100", `url: "`+url+`"`, 1)
		cfg, err := Parse([]byte(input), env(vars))
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		if got := strings.Contains(strings.Join(cfg.Warnings, "\n"), "sources.loki.url contains a password"); got != warn {
			t.Errorf("%s: warned = %v, want %v", url, got, warn)
		}
	}
}

func TestWarnsAboutCredentialsInFile(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings for referenced credentials: %v", cfg.Warnings)
	}
	input := strings.Replace(validConfig, `token: "${SENTRY_TOKEN}"`, `token: written-here`, 1)
	input = strings.Replace(input, `X-Scope-OrgID: prod`, `X-Scope-OrgID: prod, X-Api-Key: written-too`, 1)
	cfg, err = Parse([]byte(input), env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"sources.sentry.auth.token is written in the config file", "sources.loki.headers.X-Api-Key is written in the config file"} {
		if !strings.Contains(got, want) {
			t.Errorf("warnings lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "X-Scope-OrgID") || strings.Contains(got, "written-here") {
		t.Errorf("unexpected warning content:\n%s", got)
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

const backendsConfig = `
sources:
  cf:
    type: cloudflare
    account_id: "${CF_ACCOUNT_ID}"
    auth: { type: bearer, token: "${CF_TOKEN}" }
  aws:
    type: aws
    region: eu-west-1
    role_arn: "${ROLE_ARN}"
    external_id: sonda
    max_scan_bytes: 2GB
  tempo:
    type: tempo
    url: http://tempo:3200
services:
  worker:
    environments:
      production:
        logs: { source: cf, script: edge-worker }
        metrics: { source: cf, script: edge-worker }
        traces: { source: cf, script: edge-worker }
    signals:
      requests: { metric: requests, by: [status] }
  db:
    environments:
      production:
        logs: { source: aws, log_groups: [/aws/rds/cluster/engine/postgresql] }
        metrics: { source: aws, namespace: AWS/RDS, dimensions: { DBClusterIdentifier: engine } }
        traces: { source: tempo, service: engine-api }
    signals:
      cpu: { metric: CPUUtilization, stat: p99 }
`

func backendsEnv() map[string]string {
	return map[string]string{"CF_ACCOUNT_ID": "acc", "CF_TOKEN": "cf-secret", "ROLE_ARN": "arn:aws:iam::1:role/sonda"}
}

func TestParseBackends(t *testing.T) {
	cfg, err := Parse([]byte(backendsConfig), env(backendsEnv()))
	if err != nil {
		t.Fatal(err)
	}
	cf := cfg.Sources["cf"]
	if cf.URL != "https://api.cloudflare.com/client/v4" || cf.CloudflareAccountID != "acc" || cf.Auth.Token != "cf-secret" {
		t.Errorf("cloudflare source = %+v", cf)
	}
	aws := cfg.Sources["aws"].AWS
	if aws == nil || aws.Region != "eu-west-1" || aws.RoleARN != "arn:aws:iam::1:role/sonda" || aws.ExternalID != "sonda" || aws.MaxScanBytes != 2_000_000_000 {
		t.Errorf("aws source = %+v", aws)
	}

	worker := cfg.Services["worker"].Environments["production"]
	if got := worker.Capabilities(); len(got) != 3 || got[2] != api.CapabilityTraces {
		t.Errorf("capabilities = %v", got)
	}
	if worker.Logs.Script != "edge-worker" || worker.Logs.Dialect() != api.DialectCloudflareQuery {
		t.Errorf("cloudflare logs = %+v", worker.Logs)
	}
	if worker.Metrics.Dialect() != api.DialectCloudflareMetric || worker.Traces.Dialect() != api.DialectCloudflareQuery {
		t.Errorf("cloudflare dialects = %s, %s", worker.Metrics.Dialect(), worker.Traces.Dialect())
	}
	want := Signal{Dialect: api.DialectCloudflareMetric, Query: `{"metric":"requests","by":["status"]}`}
	if got := cfg.Services["worker"].Signals["requests"]; got != want {
		t.Errorf("cloudflare signal = %+v", got)
	}

	db := cfg.Services["db"].Environments["production"]
	if len(db.Logs.LogGroups) != 1 || db.Logs.Dialect() != api.DialectLogsInsights {
		t.Errorf("aws logs = %+v", db.Logs)
	}
	if db.Metrics.Namespace != "AWS/RDS" || db.Metrics.Dimensions["DBClusterIdentifier"] != "engine" || db.Metrics.Dialect() != api.DialectCloudWatchMetric {
		t.Errorf("aws metrics = %+v", db.Metrics)
	}
	if db.Traces.ServiceName != "engine-api" || db.Traces.Dialect() != api.DialectTraceQL {
		t.Errorf("tempo traces = %+v", db.Traces)
	}
	want = Signal{Dialect: api.DialectCloudWatchMetric, Query: `{"metric":"CPUUtilization","stat":"p99"}`}
	if got := cfg.Services["db"].Signals["cpu"]; got != want {
		t.Errorf("cloudwatch signal = %+v", got)
	}

	cfg, err = Parse([]byte(strings.Replace(backendsConfig, "    max_scan_bytes: 2GB\n", "", 1)), env(backendsEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Sources["aws"].AWS.MaxScanBytes; got != 10_000_000_000 {
		t.Errorf("default max_scan_bytes = %d", got)
	}
}

func TestParseBackendErrors(t *testing.T) {
	manyGroups := make([]string, 51)
	for i := range manyGroups {
		manyGroups[i] = fmt.Sprintf("/g/%d", i)
	}
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"unknown source type", [2]string{"type: tempo", "type: jaeger"}, "type must be sentry, loki, prometheus, tempo, cloudflare or aws"},

		{"cloudflare without account", [2]string{`    account_id: "${CF_ACCOUNT_ID}"` + "\n", ""}, "sources.cf.account_id is required"},
		{"cloudflare basic auth", [2]string{`{ type: bearer, token: "${CF_TOKEN}" }`, "{ type: basic, username: u, password: p }"}, "sources.cf.auth must be bearer"},
		{"cloudflare without auth", [2]string{`    auth: { type: bearer, token: "${CF_TOKEN}" }` + "\n", ""}, "sources.cf.auth must be bearer"},
		{"cloudflare with region", [2]string{"type: cloudflare\n", "type: cloudflare\n    region: eu-west-1\n"}, "sources.cf.region is allowed only for aws sources"},

		{"aws without region", [2]string{"    region: eu-west-1\n", ""}, "sources.aws.region is required"},
		{"aws with url", [2]string{"type: aws\n", "type: aws\n    url: http://aws\n"}, "sources.aws.url is not allowed"},
		{"aws with auth", [2]string{"type: aws\n", "type: aws\n    auth: { type: bearer, token: t }\n"}, "sources.aws.auth is not allowed"},
		{"aws with headers", [2]string{"type: aws\n", "type: aws\n    headers: { X-A: b }\n"}, "sources.aws.headers is not allowed"},
		{"aws with org", [2]string{"type: aws\n", "type: aws\n    org: acme\n"}, "sources.aws.org is allowed only for sentry sources"},
		{"aws with account", [2]string{"type: aws\n", "type: aws\n    account_id: acc\n"}, "sources.aws.account_id is allowed only for cloudflare sources"},
		{"external id without role", [2]string{`    role_arn: "${ROLE_ARN}"` + "\n", ""}, "external_id is allowed only with role_arn"},
		{"invalid scan size", [2]string{"max_scan_bytes: 2GB", "max_scan_bytes: lots"}, "invalid size"},

		{"tempo without url", [2]string{"    url: http://tempo:3200\n", ""}, "sources.tempo.url: invalid URL"},
		{"tempo with role", [2]string{"type: tempo\n", "type: tempo\n    role_arn: arn\n"}, "sources.tempo.role_arn is allowed only for aws sources"},

		{"cloudflare logs without script", [2]string{"logs: { source: cf, script: edge-worker }", "logs: { source: cf }"}, "logs.script is required"},
		{"cloudflare logs with selector", [2]string{"logs: { source: cf, script: edge-worker }", `logs: { source: cf, script: w, selector: '{app="w"}' }`}, "logs.selector is not allowed for cloudflare sources"},
		{"logs on tempo", [2]string{"logs: { source: cf,", "logs: { source: tempo,"}, `source "tempo" has type tempo, expected loki, cloudflare or aws`},
		{"no log groups", [2]string{"[/aws/rds/cluster/engine/postgresql]", "[]"}, "log_groups must have 1 to 50 entries"},
		{"too many log groups", [2]string{"[/aws/rds/cluster/engine/postgresql]", "[" + strings.Join(manyGroups, ", ") + "]"}, "log_groups must have 1 to 50 entries"},
		{"log group pattern", [2]string{"[/aws/rds/cluster/engine/postgresql]", "[/aws/rds/*]"}, "must be an exact name"},
		{"empty log group", [2]string{"[/aws/rds/cluster/engine/postgresql]", `[""]`}, "empty log group name"},
		{"duplicate log group", [2]string{"[/aws/rds/cluster/engine/postgresql]", "[/a, /a]"}, `duplicate log group "/a"`},
		{"aws logs with namespace", [2]string{"logs: { source: aws,", "logs: { source: aws, namespace: AWS/RDS,"}, "logs.namespace is not allowed for aws sources"},

		{"aws metrics without namespace", [2]string{"namespace: AWS/RDS, ", ""}, "metrics.namespace is required"},
		{"aws metrics without dimensions", [2]string{", dimensions: { DBClusterIdentifier: engine }", ""}, "dimensions must have 1 to 10 entries"},
		{"aws metrics with too many dimensions", [2]string{"{ DBClusterIdentifier: engine }", "{ A: a, B: b, C: c, D: d, E: e, F: f, G: g, H: h, I: i, J: j, K: k }"}, "dimensions must have 1 to 10 entries"},
		{"log group ARN", [2]string{"[/aws/rds/cluster/engine/postgresql]", "[\"arn:aws:logs:eu-west-1:1:log-group:/aws/x\"]"}, "must be a log group name, not an ARN"},
		{"aws metrics with empty dimension", [2]string{"{ DBClusterIdentifier: engine }", `{ DBClusterIdentifier: "" }`}, "must not be empty"},
		{"metrics on tempo", [2]string{"metrics: { source: cf,", "metrics: { source: tempo,"}, "expected prometheus, cloudflare or aws"},

		{"tempo traces without service", [2]string{"{ source: tempo, service: engine-api }", "{ source: tempo }"}, "traces.service is required"},
		{"tempo traces with script", [2]string{"{ source: tempo, service: engine-api }", "{ source: tempo, service: a, script: a }"}, "traces.script is not allowed for tempo sources"},
		{"traces on aws", [2]string{"{ source: tempo, service: engine-api }", "{ source: aws, service: a }"}, "expected tempo or cloudflare"},

		{"string signal on cloudflare", [2]string{"{ metric: requests, by: [status] }", "sum(up)"}, "a string signal is PromQL"},
		{"unknown cloudflare metric", [2]string{"metric: requests", "metric: bytes"}, `unknown metric "bytes"`},
		{"unknown signal field", [2]string{"by: [status]", "groupBy: [status]"}, "unknown field"},
		{"invalid cloudwatch stat", [2]string{"stat: p99", "stat: median"}, `unknown stat "median"`},
		{"signal list", [2]string{"{ metric: CPUUtilization, stat: p99 }", "[a]"}, "must be a PromQL string or a mapping"},
		{
			"mixed metrics backends",
			[2]string{"    signals:\n      requests:", "      staging:\n        metrics: { source: aws, namespace: AWS/RDS, dimensions: { A: b } }\n    signals:\n      requests:"},
			"one source type, got aws, cloudflare",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(backendsConfig, tt.replace[0]) {
				t.Fatalf("replacement %q not found", tt.replace[0])
			}
			input := strings.Replace(backendsConfig, tt.replace[0], tt.replace[1], 1)
			_, err := Parse([]byte(input), env(backendsEnv()))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseExistingSourceRules(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"unknown log source and invalid selector", [2]string{`logs: { source: loki, selector: '{app="api"}' }`, `logs: { source: nope, selector: '{app=}' }`}, "logs.selector"},
		{"unknown metric source and invalid selector", [2]string{`metrics: { source: prom, selector: '{job="api"}' }`, `metrics: { source: nope, selector: '{job=}' }`}, "metrics.selector"},
		{"mapping signal on prometheus", [2]string{"rps: sum(rate(http_requests_total[5m]))", "rps: { metric: requests }"}, "a mapping signal needs cloudflare or aws metrics"},
		{"signals without metrics", [2]string{"        metrics: { source: prom, selector: '{job=\"api\"}' }\n", ""}, "signals require an environment with metrics"},
		{"prometheus with account", [2]string{"type: prometheus\n", "type: prometheus\n    account_id: acc\n"}, "sources.prom.account_id is allowed only for cloudflare sources"},
		{"loki with region", [2]string{"type: loki\n", "type: loki\n    region: eu-west-1\n"}, "sources.loki.region is allowed only for aws sources"},
		{"loki logs with script", [2]string{`logs: { source: loki, selector: '{app="api"}' }`, `logs: { source: loki, selector: '{app="api"}', script: w }`}, "logs.script is not allowed for loki sources"},
		{"empty environment", [2]string{"        errors: { source: sentry, project: api, environment: production }\n        logs: { source: loki, selector: '{app=\"api\"}' }\n        metrics: { source: prom, selector: '{job=\"api\"}' }\n", "        {}\n"}, "at least one of errors, logs, metrics or traces is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(validConfig, tt.replace[0]) {
				t.Fatalf("replacement %q not found", tt.replace[0])
			}
			input := strings.Replace(validConfig, tt.replace[0], tt.replace[1], 1)
			_, err := Parse([]byte(input), env(validEnv()))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
