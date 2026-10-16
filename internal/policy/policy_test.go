package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
)

func scopes(t *testing.T) (logs, metrics authz.SelectorScope) {
	t.Helper()
	hash := sha256.Sum256([]byte("t"))
	cfg, err := config.Parse([]byte(`
sources:
  loki: { type: loki, url: "http://loki" }
  prom: { type: prometheus, url: "http://prom" }
services:
  api:
    environments:
      production:
        logs: { source: loki, selector: '{app="api"}' }
        metrics: { source: prom, selector: '{job="api"}' }
identities:
  agent:
    token_sha256: `+hex.EncodeToString(hash[:])+`
    grants: [{ services: [api], environments: [production], capabilities: [logs, metrics] }]
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	a := authz.New(cfg)
	identity, _ := a.Authenticate("t")
	logs, err = a.LogScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	metrics, err = a.MetricScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	return logs, metrics
}

func TestScopePromQL(t *testing.T) {
	_, scope := scopes(t)
	tests := []struct{ in, want string }{
		{`up`, `up{job="api"}`},
		{`{__name__=~".+"}`, `{__name__=~".+",job="api"}`},
		{`up{job="billing"}`, `up{job="api",job="billing"}`},
		{`up{job=~".*"}`, `up{job="api",job=~".*"}`},
		{
			`sum(rate(x{job="api"}[5m])) or on() sum(rate(x{job="billing"}[5m]))`,
			`sum(rate(x{job="api"}[5m])) or on () sum(rate(x{job="api",job="billing"}[5m]))`,
		},
		{`max_over_time(rate(x[5m])[1h:1m])`, `max_over_time(rate(x{job="api"}[5m])[1h:1m])`},
		{`absent(x offset 1h)`, `absent(x{job="api"} offset 1h)`},
		{`label_replace(x, "job", "billing", "job", ".*")`, `label_replace(x{job="api"}, "job", "billing", "job", ".*")`},
		{`vector(1)`, `vector(1)`},
	}
	for _, tt := range tests {
		got, err := ScopePromQL(scope, tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("%s:\n got  %s\n want %s", tt.in, got, tt.want)
		}
	}
}

func TestScopeLogQL(t *testing.T) {
	scope, _ := scopes(t)
	tests := []struct {
		in, want string
		metric   bool
	}{
		{`{level="error"}`, `{level="error", app="api"}`, false},
		{`{app=~".+"} | json | level="error"`, `{app=~".+", app="api"} | json | level="error"`, false},
		{
			`sum(count_over_time({app="api"}[5m])) / sum(count_over_time({app="billing"} |= "password" [5m]))`,
			`(sum(count_over_time({app="api"}[5m])) / sum(count_over_time({app="billing", app="api"} |= "password"[5m])))`,
			true,
		},
		{`sum by (level) (rate({ns="x"} |= "timeout" [1m]))`, `sum by (level)(rate({ns="x", app="api"} |= "timeout"[1m]))`, true},
	}
	for _, tt := range tests {
		got, err := ScopeLogQL(scope, tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if got.String() != tt.want || got.IsMetric() != tt.metric {
			t.Errorf("%s:\n got  %s (metric=%v)\n want %s (metric=%v)", tt.in, got, got.IsMetric(), tt.want, tt.metric)
		}
	}
}

func TestInvalidQueries(t *testing.T) {
	logs, metrics := scopes(t)
	if _, err := ScopePromQL(metrics, `sum(`); !isCode(err, api.CodeInvalidQuery) {
		t.Errorf("PromQL: %v", err)
	}
	if _, err := ScopeLogQL(logs, `{app=}`); !isCode(err, api.CodeInvalidQuery) {
		t.Errorf("LogQL: %v", err)
	}
}

func TestLogSearchQuery(t *testing.T) {
	scope, _ := scopes(t)
	q, err := LogSearchQuery(scope, []string{`timeout "db"`}, `| json | level="error"`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{app="api"} |= "timeout \"db\"" | json | level="error"`; q.String() != want {
		t.Errorf("got %s", q)
	}

	// A pipeline that smuggles in a second selector is still scoped.
	q, err = LogSearchQuery(scope, nil, `[5m])) or count_over_time({app="billing"}[5m]`)
	if err == nil && !strings.Contains(q.String(), `{app="billing", app="api"}`) {
		t.Errorf("smuggled selector not scoped: %s", q)
	}

	count, err := LogCountQuery(scope, mustLogQL(t, scope, `{level="error"}`), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := `sum(count_over_time({level="error", app="api"}[1h]))`; count.String() != want {
		t.Errorf("count query = %s", count)
	}
}

func mustLogQL(t *testing.T, scope authz.SelectorScope, q string) LogQL {
	t.Helper()
	l, err := ScopeLogQL(scope, q)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestRange(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	from := now.Add(-2 * time.Hour)

	r, err := Range(api.Window{Since: "1h"}, now, 24*time.Hour, time.Hour)
	if err != nil || r.From != now.Add(-time.Hour) || r.To != now {
		t.Errorf("since: %v %v", r, err)
	}
	r, err = Range(api.Window{From: &from, To: &future}, now, 24*time.Hour, time.Hour)
	if err != nil || r.To != now {
		t.Errorf("future to not capped: %v %v", r, err)
	}
	if _, err := Range(api.Window{Since: "2d"}, now, 24*time.Hour, time.Hour); !isCode(err, api.CodeLimitExceeded) {
		t.Errorf("max range: %v", err)
	}
	if _, err := Range(api.Window{Since: "soon"}, now, 24*time.Hour, time.Hour); !isCode(err, api.CodeInvalidRequest) {
		t.Errorf("invalid since: %v", err)
	}
}

func TestParseStep(t *testing.T) {
	r := api.TimeRange{From: time.Unix(0, 0), To: time.Unix(0, 0).Add(24 * time.Hour)}
	if step, _ := ParseStep("", r, 100); step != 15*time.Minute {
		t.Errorf("auto step = %v", step)
	}
	if step, _ := ParseStep("1m", r, 100); step != 15*time.Minute {
		t.Errorf("too fine step not raised: %v", step)
	}
	if step, _ := ParseStep("1h", r, 100); step != time.Hour {
		t.Errorf("explicit step = %v", step)
	}
}

func isCode(err error, code api.ErrorCode) bool {
	e, ok := apierr.As(err)
	return ok && e.Code == code
}
