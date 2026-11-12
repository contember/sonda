package config

import (
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/telemetry"
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
projects:
  api:
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
	if err == nil || !strings.Contains(err.Error(), "grafana.url must be scheme://host[:port][/path] without credentials or a query") || strings.Contains(err.Error(), "grafpw") {
		t.Errorf("error = %v", err)
	}
}

func TestGrafanaURLRefusesQuery(t *testing.T) {
	input := validConfig + "grafana:\n  url: https://grafana.example.com/?auth_token=abc\n"
	_, err := Parse([]byte(input), env(validEnv()))
	if err == nil || !strings.Contains(err.Error(), "grafana.url must be") || strings.Contains(err.Error(), "abc") {
		t.Errorf("error = %v", err)
	}
}

func TestPartlyLiteralCredentialsWarn(t *testing.T) {
	vars := validEnv()
	vars["T"], vars["P"] = "t", "p"
	warnings := func(t *testing.T, input string) string {
		t.Helper()
		cfg, err := Parse([]byte(input), env(vars))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(cfg.Warnings, "\n")
	}
	tokens := map[string]string{
		`token: "${SENTRY_TOKEN}"`: "",
		`token: "lit${T}"`:         "sources.sentry.auth.token is partly written",
		`token: "${T} extra"`:      "sources.sentry.auth.token is partly written",
		`token: "Bearer ${T}"`:     "sources.sentry.auth.token starts with an authorization scheme",
	}
	for replacement, want := range tokens {
		got := warnings(t, strings.Replace(validConfig, `token: "${SENTRY_TOKEN}"`, replacement, 1))
		if want == "" && got != "" || want != "" && !strings.Contains(got, want) {
			t.Errorf("%s: warnings %q, want %q", replacement, got, want)
		}
	}
	// The scheme hint is only for auth.token; elsewhere a prefix is just partly literal.
	got := warnings(t, strings.Replace(validConfig, `token: "${ADMIN_TOKEN}"`, `token: "Bearer ${ADMIN_TOKEN}"`, 1))
	if !strings.Contains(got, "admin.token is partly written") || strings.Contains(got, "authorization scheme") {
		t.Errorf("admin.token: warnings %q", got)
	}
	basic := strings.Replace(validConfig, "    url: http://prometheus:9090", "    url: http://prometheus:9090\n    auth: { type: basic, username: \"123\", password: \"Basic ${P}\" }", 1)
	got = warnings(t, basic)
	if !strings.Contains(got, "sources.prom.auth.password is partly written") || strings.Contains(got, "authorization scheme") {
		t.Errorf("auth.password: warnings %q", got)
	}
	// Header values may wrap a reference in any form; only a value without one warns.
	headers := map[string]bool{
		`Cookie: "session=${T}"`:                  false,
		`Authorization: "Token token=${T}"`:       false,
		`X-Sentry-Auth: "Sentry sentry_key=${T}"`: false,
		`X-Api-Key: "${T}:${P}"`:                  false,
		`Authorization: "Bearer written"`:         true,
	}
	for header, warn := range headers {
		got := warnings(t, strings.Replace(validConfig, "X-Scope-OrgID: prod", "X-Scope-OrgID: prod, "+header, 1))
		if warn && !strings.Contains(got, "is written in the config file") || !warn && got != "" {
			t.Errorf("%s: warnings %q, want warning %v", header, got, warn)
		}
	}
	got = warnings(t, strings.Replace(validConfig, "url: http://loki:3100", `url: "http://u:pw${P}@loki:3100"`, 1))
	if !strings.Contains(got, "sources.loki.url contains a password") {
		t.Errorf("partly literal URL password did not warn: %q", got)
	}
	databases := map[string]bool{
		"postgres://sonda:pw@db/sonda":           true,
		"postgres://sonda@db/sonda?password=pw":  true,
		"postgresql://sonda:pw@db/sonda":         true,
		"postgres://sonda@db/sonda":              false,
		"postgres://sonda:@db/sonda":             false,
		"/var/lib/sonda.db":                      false,
		"file:sonda.db?cache=shared&password=no": false,
	}
	for database, warn := range databases {
		got := warnings(t, "server:\n  database: \""+database+"\"\n"+validConfig)
		if strings.Contains(got, "server.database contains a password") != warn || strings.Contains(got, "pw") {
			t.Errorf("%s: warnings %q, want warning %v", database, got, warn)
		}
	}
}

func TestRepositoryRefusesCredentials(t *testing.T) {
	for repository, refused := range map[string]bool{
		"https://bob:ghp_secret@github.com/acme/api":    true,
		"https://ghp_secret@github.com/acme/api":        true,
		"https://bob:ghp_secret@github.com:acme/api":    true,
		"https://github.com/acme/api?token=ghp_secret":  true,
		"ssh://git:ghp_secret@github.com/acme/api.git":  true,
		"https://bob:pa/ghp_secret@github.com/acme/api": true,
		"bob:ghp_secret@github.com/acme/api":            true,
		"github.com/acme/api?token=ghp_secret":          true,
		"git+https://ghp_secret@github.com/acme/api":    true,
		"https://github.com/acme/api#ghp_secret":        true,
		"ssh://git@github.com/acme/api.git":             false,
		"https://github.com/acme/api":                   false,
		"github.com/acme/api":                           false,
		"git@github.com:acme/api.git":                   false,
	} {
		input := strings.Replace(validConfig, "      api:\n", "      api:\n        repository: \""+repository+"\"\n", 1)
		_, err := Parse([]byte(input), env(validEnv()))
		if refused {
			if err == nil || !strings.Contains(err.Error(), "services.api.repository must not contain") || strings.Contains(err.Error(), "ghp_secret") {
				t.Errorf("%s: error = %v", repository, err)
			}
		} else if err != nil {
			t.Errorf("%s: %v", repository, err)
		}
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
projects:
  worker:
    services:
      worker:
        environments:
          production:
            logs: { source: cf, script: edge-worker }
            metrics:
              source: cf
              script: edge-worker
              d1_databases: { main: 6f1c2b9e-3d4a-4e5f-8a7b-0c1d2e3f4a5b }
              queues: { jobs: 0123456789abcdef0123456789abcdef }
            traces: { source: cf, script: edge-worker }
        signals:
          requests: { metric: requests, by: [status] }
          rows: { metric: d1_rows_read }
  db:
    services:
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
	resources := worker.Metrics.CloudflareResources
	if len(resources) != 2 || resources[telemetry.CloudflareD1Databases]["main"] != "6f1c2b9e-3d4a-4e5f-8a7b-0c1d2e3f4a5b" ||
		resources[telemetry.CloudflareQueues]["jobs"] != "0123456789abcdef0123456789abcdef" {
		t.Errorf("cloudflare resources = %v", resources)
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
		{"unknown source type", [2]string{"type: tempo", "type: jaeger"}, "type must be sentry, loki, prometheus, tempo, cloudflare, aws, kubernetes, grafana or vercel"},

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
		{"logs on tempo", [2]string{"logs: { source: cf,", "logs: { source: tempo,"}, `source "tempo" has type tempo, expected loki, cloudflare, aws or vercel`},
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
		{"metrics on tempo", [2]string{"metrics:\n              source: cf", "metrics:\n              source: tempo"}, "expected prometheus, cloudflare or aws"},
		{"d1 database name instead of ID", [2]string{"main: 6f1c2b9e-3d4a-4e5f-8a7b-0c1d2e3f4a5b", "main: main-db"}, `d1_databases.main: "main-db" must be a database UUID`},
		{"queue name instead of ID", [2]string{"jobs: 0123456789abcdef0123456789abcdef", "jobs: jobs-queue"}, "must be a queue ID of 32 hex characters, not the queue name"},
		{"invalid r2 bucket", [2]string{"queues: {", "r2_buckets: { assets: Assets_Bucket }\n              queues: {"}, `r2_buckets.assets: "Assets_Bucket" must be a bucket name`},
		{"invalid durable object namespace", [2]string{"queues: {", "durable_object_namespaces: { rooms: ROOMS }\n              queues: {"}, "must be a namespace ID of 32 hex characters"},
		{"duplicate resource ID", [2]string{"{ jobs: 0123456789abcdef0123456789abcdef }", "{ jobs: 0123456789abcdef0123456789abcdef, retry: 0123456789abcdef0123456789abcdef }"}, "queues: jobs and retry have the same ID"},
		{"empty resources", [2]string{"{ jobs: 0123456789abcdef0123456789abcdef }", "{}"}, "metrics.queues must not be empty"},
		{"resources on cloudflare logs", [2]string{"logs: { source: cf, script: edge-worker }", "logs: { source: cf, script: edge-worker, queues: { a: 0123456789abcdef0123456789abcdef } }"}, "logs.queues is not allowed for cloudflare sources"},
		{"resources on aws metrics", [2]string{"dimensions: { DBClusterIdentifier: engine } }", "dimensions: { DBClusterIdentifier: engine }, r2_buckets: { a: assets } }"}, "metrics.r2_buckets is not allowed for aws sources"},

		{"tempo traces without service", [2]string{"{ source: tempo, service: engine-api }", "{ source: tempo }"}, "traces.service is required"},
		{"tempo traces with script", [2]string{"{ source: tempo, service: engine-api }", "{ source: tempo, service: a, script: a }"}, "traces.script is not allowed for tempo sources"},
		{"traces on aws", [2]string{"{ source: tempo, service: engine-api }", "{ source: aws, service: a }"}, "expected tempo, cloudflare or sentry"},

		{"string signal on cloudflare", [2]string{"{ metric: requests, by: [status] }", "sum(up)"}, "a string signal is PromQL"},
		{"unknown cloudflare metric", [2]string{"metric: requests", "metric: bytes"}, `unknown metric "bytes"`},
		{"dimension of another dataset", [2]string{"metric: d1_rows_read }", "metric: d1_rows_read, by: [status] }"}, `unknown dimension "status" of metric d1_rows_read`},
		{"signal of an unbound resource", [2]string{"metric: d1_rows_read }", "metric: r2_requests }"}, "signals.rows: metric r2_requests needs r2_buckets in the metrics binding of environment production"},
		{"unknown signal field", [2]string{"by: [status]", "groupBy: [status]"}, "unknown field"},
		{"invalid cloudwatch stat", [2]string{"stat: p99", "stat: median"}, `unknown stat "median"`},
		{"signal list", [2]string{"{ metric: CPUUtilization, stat: p99 }", "[a]"}, "must be a PromQL string or a mapping"},
		{
			"mixed metrics backends",
			[2]string{"        signals:\n          requests:", "          staging:\n            metrics: { source: aws, namespace: AWS/RDS, dimensions: { A: b } }\n        signals:\n          requests:"},
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

const vercelConfig = `
sources:
  vercel:
    type: vercel
    team_id: team_abc123
    auth: { type: bearer, token: "${VERCEL_TOKEN}" }
projects:
  web:
    services:
      web:
        environments:
          production:
            logs: { source: vercel, project: prj_abc123, environment: production }
`

func TestParseVercel(t *testing.T) {
	cfg, err := Parse([]byte(vercelConfig), env(map[string]string{"VERCEL_TOKEN": "secret"}))
	if err != nil {
		t.Fatal(err)
	}
	src := cfg.Sources["vercel"]
	if src.URL != "https://api.vercel.com" || src.VercelTeamID != "team_abc123" || src.Auth.Token != "secret" {
		t.Errorf("vercel source = %+v", src)
	}
	logs := cfg.Services["web"].Environments["production"].Logs
	if logs.Project != "prj_abc123" || logs.Environment != "production" || logs.Dialect() != api.DialectVercelKQL {
		t.Errorf("vercel logs = %+v", logs)
	}
}

func TestParseVercelErrors(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"team slug", [2]string{"team_id: team_abc123", "team_id: acme"}, `sources.vercel.team_id must be a Vercel team ID like team_abc123, not the team slug, got "acme"`},
		{"without team", [2]string{"    team_id: team_abc123\n", ""}, "sources.vercel.team_id must be a Vercel team ID"},
		{"basic auth", [2]string{`{ type: bearer, token: "${VERCEL_TOKEN}" }`, "{ type: basic, username: u, password: p }"}, "sources.vercel.auth must be bearer"},
		{"team on another type", [2]string{"type: vercel\n", "type: loki\n    url: http://loki\n"}, "sources.vercel.team_id is allowed only for vercel sources"},
		{"project name", [2]string{"project: prj_abc123", "project: web"}, `logs.project must be a Vercel project ID like prj_abc123, not the project name, got "web"`},
		{"without environment", [2]string{", environment: production", ""}, "logs.environment must be a Vercel environment"},
		{"environment with quote", [2]string{"environment: production", `environment: 'prod"'`}, "logs.environment must be a Vercel environment"},
		{"with script", [2]string{"environment: production }", "environment: production, script: w }"}, "logs.script is not allowed for vercel sources"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(vercelConfig, tt.replace[0]) {
				t.Fatalf("replacement %q not found", tt.replace[0])
			}
			input := strings.Replace(vercelConfig, tt.replace[0], tt.replace[1], 1)
			_, err := Parse([]byte(input), env(map[string]string{"VERCEL_TOKEN": "secret"}))
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
		{"signals without metrics", [2]string{"            metrics: { source: prom, selector: '{job=\"api\"}' }\n", ""}, "signals require an environment with metrics"},
		{"prometheus with account", [2]string{"type: prometheus\n", "type: prometheus\n    account_id: acc\n"}, "sources.prom.account_id is allowed only for cloudflare sources"},
		{"loki with region", [2]string{"type: loki\n", "type: loki\n    region: eu-west-1\n"}, "sources.loki.region is allowed only for aws sources"},
		{"loki logs with script", [2]string{`logs: { source: loki, selector: '{app="api"}' }`, `logs: { source: loki, selector: '{app="api"}', script: w }`}, "logs.script is not allowed for loki sources"},
		{"empty environment", [2]string{"            errors: { source: sentry, project: api, environment: production }\n            logs: { source: loki, selector: '{app=\"api\"}' }\n            metrics: { source: prom, selector: '{job=\"api\"}' }\n", "            {}\n"}, "at least one of errors, logs, metrics, traces, workloads or alerts is required"},
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

func TestParseProjects(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if svc := cfg.Services["api"]; svc.Project != cfg.Projects["api"] || cfg.Projects["api"].Services["api"] != svc {
		t.Errorf("service api is not linked to project api")
	}

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"service name in two projects", `
sources:
  loki: { type: loki, url: http://loki:3100 }
projects:
  a:
    services:
      web: { environments: { production: { logs: { source: loki, selector: '{app="a"}' } } } }
  b:
    services:
      web: { environments: { production: { logs: { source: loki, selector: '{app="b"}' } } } }
`, "projects.b.services.web: service name is already used in project a"},
		{"project without services", `
projects:
  a:
    description: empty
`, "projects.a.services: at least one service is required"},
		{"top-level services", `
services:
  web: {}
`, "field services not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), env(nil))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

const kubernetesConfig = `
sources:
  k8s:
    type: kubernetes
    url: https://k8s.example:6443
    auth: { type: bearer, token: "${K8S_TOKEN}" }
    ca_file: CA_FILE
projects:
  engine:
    services:
      engine:
        environments:
          production:
            workloads: { source: k8s, namespace: engine, labels: { app.kubernetes.io/name: engine-api } }
`

func writeCA(t *testing.T) string {
	t.Helper()
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	file := filepath.Join(t.TempDir(), "ca.crt")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestParseKubernetes(t *testing.T) {
	input := strings.Replace(kubernetesConfig, "CA_FILE", writeCA(t), 1)
	cfg, err := Parse([]byte(input), env(map[string]string{"K8S_TOKEN": "k8s-secret"}))
	if err != nil {
		t.Fatal(err)
	}
	src := cfg.Sources["k8s"]
	if src.Auth.Token != "k8s-secret" || src.RootCAs == nil {
		t.Errorf("kubernetes source = %+v", src)
	}
	env := cfg.Services["engine"].Environments["production"]
	if got := env.Capabilities(); len(got) != 1 || got[0] != api.CapabilityWorkloads {
		t.Errorf("capabilities = %v", got)
	}
	if env.Workloads.Namespace != "engine" || env.Workloads.Labels["app.kubernetes.io/name"] != "engine-api" {
		t.Errorf("workloads = %+v", env.Workloads)
	}
}

func TestParseCAFileOnHTTPSource(t *testing.T) {
	input := fmt.Sprintf(`
sources:
  tempo:
    type: tempo
    url: https://tempo.example
    ca_file: %s
projects:
  api:
    services:
      api:
        environments:
          production:
            traces: { source: tempo, service: api }
`, writeCA(t))
	cfg, err := Parse([]byte(input), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources["tempo"].RootCAs == nil {
		t.Error("tempo source has no RootCAs")
	}
}

func TestParseKubernetesErrors(t *testing.T) {
	ca := writeCA(t)
	notPEM := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		replace [2]string
		env     map[string]string
		want    string
	}{
		{"missing ca file", [2]string{ca, "/nonexistent/ca.crt"}, nil, "sources.k8s.ca_file: open /nonexistent/ca.crt"},
		{"ca file without certificate", [2]string{ca, notPEM}, nil, "contains no PEM certificate"},
		{"basic auth", [2]string{`{ type: bearer, token: "${K8S_TOKEN}" }`, "{ type: basic, username: u, password: p }"}, nil, "auth must be bearer or eks for kubernetes sources with a url"},
		{"in cluster outside a pod", [2]string{"    url: https://k8s.example:6443\n    auth: { type: bearer, token: \"${K8S_TOKEN}\" }\n    ca_file: " + ca + "\n", ""}, nil, "url is required outside a Kubernetes pod"},
		{"in cluster with auth", [2]string{"    url: https://k8s.example:6443\n", ""}, nil, "auth and ca_file require a url"},
		{
			"in cluster without service account", [2]string{"    url: https://k8s.example:6443\n    auth: { type: bearer, token: \"${K8S_TOKEN}\" }\n    ca_file: " + ca + "\n", ""},
			map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1", "KUBERNETES_SERVICE_PORT": "443"},
			"serviceaccount/ca.crt",
		},
		{"ca file on an aws source", [2]string{"type: kubernetes", "type: aws\n    region: eu-west-1"}, nil, "sources.k8s.ca_file is not allowed for aws sources"},
		{"invalid namespace", [2]string{"namespace: engine", "namespace: Engine_Prod"}, nil, `namespace "Engine_Prod" must be a Kubernetes namespace name`},
		{"no labels", [2]string{"labels: { app.kubernetes.io/name: engine-api }", "labels: {}"}, nil, "labels must have at least one label"},
		{"empty label value", [2]string{"engine-api }", `"" }`}, nil, `must be a non-empty label value`},
		{"selector syntax in value", [2]string{"engine-api }", `"a,b!=c" }`}, nil, `must be a non-empty label value`},
		{"invalid label key", [2]string{"app.kubernetes.io/name:", `"app name":`}, nil, `"app name" is not a valid label key`},
		{"workloads on another source", [2]string{"type: kubernetes\n    url: https://k8s.example:6443\n    auth: { type: bearer, token: \"${K8S_TOKEN}\" }\n    ca_file: " + ca, "type: tempo\n    url: https://k8s.example:6443"}, nil, "expected kubernetes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := strings.Replace(kubernetesConfig, "CA_FILE", ca, 1)
			if !strings.Contains(base, tt.replace[0]) {
				t.Fatalf("replacement %q not found", tt.replace[0])
			}
			vars := map[string]string{"K8S_TOKEN": "k8s-secret"}
			maps.Copy(vars, tt.env)
			_, err := Parse([]byte(strings.Replace(base, tt.replace[0], tt.replace[1], 1)), env(vars))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

const identityConfig = `
identity:
  issuer: https://sonda.example.com/
sources:
  aws:
    type: aws
    region: eu-west-1
    credentials: identity
    role_arn: arn:aws:iam::1:role/sonda
  loki:
    type: loki
    url: https://eks.example/api/v1/namespaces/logging/services/http:loki:3100/proxy
    auth: { type: eks, cluster: prod, aws_source: aws }
projects:
  api:
    services:
      api:
        environments:
          production:
            logs: { source: loki, selector: '{app="api"}' }
`

func TestParseIdentityAndEKS(t *testing.T) {
	cfg, err := Parse([]byte(identityConfig), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity == nil || cfg.Identity.Issuer != "https://sonda.example.com" {
		t.Errorf("identity = %+v", cfg.Identity)
	}
	if aws := cfg.Sources["aws"].AWS; aws.Credentials != AWSIdentity || aws.RoleARN != "arn:aws:iam::1:role/sonda" {
		t.Errorf("aws source = %+v", aws)
	}
	auth := cfg.Sources["loki"].Auth
	if auth.Type != AuthEKS || auth.EKS == nil || auth.EKS.Cluster != "prod" || auth.EKS.AWS != cfg.Sources["aws"] {
		t.Errorf("loki auth = %+v", auth)
	}
}

func TestParseIdentityAndEKSErrors(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"http issuer", [2]string{"https://sonda.example.com/", "http://sonda.example.com"}, "identity.issuer must be an https URL"},
		{"issuer with query", [2]string{"https://sonda.example.com/", "https://sonda.example.com/?a=b"}, "identity.issuer must be an https URL"},
		{"identity credentials without identity", [2]string{"identity:\n  issuer: https://sonda.example.com/\n", ""}, "sources.aws.credentials: identity requires the identity section"},
		{"identity credentials without role", [2]string{"    role_arn: arn:aws:iam::1:role/sonda\n", ""}, "sources.aws.role_arn is required with credentials: identity"},
		{"identity credentials with external id", [2]string{"    role_arn:", "    external_id: x\n    role_arn:"}, "external_id is not allowed with credentials: identity"},
		{"unknown credentials", [2]string{"credentials: identity", "credentials: static"}, "credentials must be default or identity"},
		{"credentials on loki", [2]string{"type: loki\n", "type: loki\n    credentials: identity\n"}, "sources.loki.credentials is allowed only for aws sources"},
		{"eks with token", [2]string{"type: eks,", "type: eks, token: t,"}, "eks auth takes no token"},
		{"eks without cluster", [2]string{"cluster: prod, ", ""}, "sources.loki.auth.cluster must be an EKS cluster name"},
		{"eks with invalid cluster", [2]string{"cluster: prod", "cluster: prod/x"}, "must be an EKS cluster name"},
		{"eks without aws source", [2]string{", aws_source: aws", ""}, `sources.loki.auth.aws_source: "" is not an aws source`},
		{"eks with another source type", [2]string{"aws_source: aws", "aws_source: loki"}, `"loki" is not an aws source`},
		{"cluster on bearer auth", [2]string{"type: eks, cluster: prod, aws_source: aws", "type: bearer, token: t, cluster: prod"}, "cluster and aws_source are allowed only for eks auth"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(identityConfig, tt.replace[0]) {
				t.Fatalf("replacement %q not found", tt.replace[0])
			}
			_, err := Parse([]byte(strings.Replace(identityConfig, tt.replace[0], tt.replace[1], 1)), env(nil))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

const alertsConfig = `
sources:
  grafana:
    type: grafana
    url: https://grafana.example
    auth: { type: bearer, token: "${GRAFANA_TOKEN}" }
  prom:
    type: prometheus
    url: http://prometheus:9090
projects:
  api:
    services:
      api:
        environments:
          production:
            alerts: { source: grafana, selector: '{service="api"}' }
          staging:
            alerts: { source: prom, selector: '{job=~"api-.+"}' }
`

func TestParseAlerts(t *testing.T) {
	cfg, err := Parse([]byte(alertsConfig), env(map[string]string{"GRAFANA_TOKEN": "g"}))
	if err != nil {
		t.Fatal(err)
	}
	envs := cfg.Services["api"].Environments
	if b := envs["production"].Alerts; b.Source.Type != SourceGrafana || b.Selector.Text != `{service="api"}` {
		t.Errorf("grafana alerts = %+v", b)
	}
	if b := envs["staging"].Alerts; b.Source.Type != SourcePrometheus || len(b.Selector.Matchers) != 1 {
		t.Errorf("prometheus alerts = %+v", b)
	}
	if caps := envs["production"].Capabilities(); len(caps) != 1 || caps[0] != api.CapabilityAlerts {
		t.Errorf("capabilities = %v", caps)
	}
}

func TestParseAlertErrors(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"unscoped selector", [2]string{`'{service="api"}'`, `'{service!="billing"}'`}, "must contain an = or =~ matcher that rejects the empty value"},
		{"selector that matches empty", [2]string{`'{job=~"api-.+"}'`, `'{job=~".*"}'`}, "must contain an = or =~ matcher"},
		{"missing selector", [2]string{`alerts: { source: grafana, selector: '{service="api"}' }`, `alerts: { source: grafana }`}, "production.alerts.selector"},
		{"extra field", [2]string{`alerts: { source: grafana, selector: '{service="api"}' }`, `alerts: { source: grafana, selector: '{service="api"}', script: w }`}, "alerts.script is not allowed for grafana sources"},
		{"grafana as metrics source", [2]string{`alerts: { source: prom, selector: '{job=~"api-.+"}' }`, `metrics: { source: grafana, selector: '{job="api"}' }`}, "expected prometheus, cloudflare or aws"},
		{"grafana without url", [2]string{"    url: https://grafana.example\n", ""}, "sources.grafana.url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(alertsConfig, tt.replace[0]) {
				t.Fatalf("replacement %q not found", tt.replace[0])
			}
			_, err := Parse([]byte(strings.Replace(alertsConfig, tt.replace[0], tt.replace[1], 1)), env(map[string]string{"GRAFANA_TOKEN": "g"}))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseSentryTraces(t *testing.T) {
	input := strings.Replace(validConfig, "        signals:\n", "            traces: { source: sentry, project: api, environment: production }\n        signals:\n", 1)
	cfg, err := Parse([]byte(input), env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Services["api"].Environments["production"].Traces
	if b.Project != "api" || b.Environment != "production" || b.Dialect() != api.DialectSentrySearch {
		t.Errorf("sentry traces = %+v", b)
	}

	tests := []struct {
		binding string
		want    string
	}{
		{"{ source: sentry, project: api }", "traces.environment is required for sentry sources"},
		{"{ source: sentry, environment: production }", "traces.project is required for sentry sources"},
		{"{ source: sentry, project: api, environment: production, service: api }", "traces.service is not allowed for sentry sources"},
		{"{ source: loki, project: api, environment: production }", "expected tempo, cloudflare or sentry"},
	}
	for _, tt := range tests {
		t.Run(tt.binding, func(t *testing.T) {
			input := strings.Replace(validConfig, "        signals:\n", "            traces: "+tt.binding+"\n        signals:\n", 1)
			_, err := Parse([]byte(input), env(validEnv()))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
