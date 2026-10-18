package logql

// These tests check the lexer against a real Loki, so no Loki code is linked into Sonda.
// They run when SONDA_TEST_LOKI_URL points to a Loki, e.g. the one in dev/docker-compose.yml:
//
//	SONDA_TEST_LOKI_URL=http://localhost:13100 go test ./internal/logql

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
)

var scopeMatchers = []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "app", "api")}

// corpus holds valid LogQL queries that cover every place a brace, quote, comment or
// bracket can appear.
var corpus = []string{
	`{app="api"}`,
	`{app=~".+", namespace!="dev", pod!~"x.*"}`,
	"{app=`api`}",
	`{app="api"} |= "error" != "debug" |~ "time(out)?" !~ "ok"`,
	`{app="api"} |= "a" or "b"`,
	`{app="api"} |> "<_> error <_>" !> "<_> ok"`,
	`{app="api"} |= ip("10.0.0.0/8")`,
	`{app="api"} | json | level="error" and duration > 10s or bytes >= 1KB`,
	`{app="api"} | json first="a.b", second="c[0]"`,
	`{app="api"} | logfmt --strict --keep-empty`,
	`{app="api"} | regexp "(?P<method>\\w+) (?P<path>[^ ]+)"`,
	`{app="api"} | pattern "<ip> - - [<_>] \"<method> <path>\""`,
	`{app="api"} | unpack | line_format "{{.method}} {{ .path | trunc 10 }}"`,
	`{app="api"} | label_format dst="{{.src}}", other=src`,
	`{app="api"} | drop a, b="c" | keep d`,
	`{app="api"} | decolorize`,
	"{app=\"api\"} |= `{\"json\": {\"nested\": true}}`",
	`{app="api"} |= "{app=\"other\"}"`,
	"{app=\"api\"} # {app=\"other\"}",
	"# leading comment {app=\"other\"}\n{app=\"api\"}",
	"{app=\"api\"} // {app=\"other\"}",
	`{app="api"} /* {app="other"} */ |= "x"`,
	`{app="api" /* , x="y" */, ns="prod"}`,
	`rate({app="api"}[5m])`,
	`sum by (level) (count_over_time({app="api"} | json [1h]))`,
	`sum without (pod) (rate({app="api"}[5m] offset 1h))`,
	`topk(5, sum by (path) (rate({app="api"} | json [5m])))`,
	`quantile_over_time(0.99, {app="api"} | json | unwrap duration(latency) [5m]) by (path)`,
	`sum(rate({app="api"}[5m])) / sum(rate({app="billing"} |= "password" [5m]))`,
	`sum(rate({app="api"}[5m])) or on() sum(rate({app="billing"}[5m]))`,
	`sum(rate({app="api"}[5m])) > bool 10`,
	`sum by (a) (rate({app="api"}[5m])) * on (a) group_left (b) sum by (a, b) (rate({app="billing"}[5m]))`,
	`label_replace(rate({app="api"}[5m]), "dst", "$1", "src", "(.*)")`,
	`absent_over_time({app="api"}[1h])`,
	`vector(1)`,
	`(({app="api"} |= "x"))`,
	`sum(rate({app="api"}[5m]))/sum(rate({app="api"}[5m]))`,
	`sum(rate({app="api"}[5m])) - -1`,
	`{app="api"} | json | status_code >= 500 | line_format "{{.msg}}"`,
	`{app="api"} | json | __error__=""`,
}

// lokiOracle formats queries with Loki's /loki/api/v1/format_query. Loki prints the query
// from its own AST, without comments, so the selectors in the output are the selectors
// Loki executes.
type lokiOracle struct {
	url    string
	client *http.Client
}

func newOracle(tb testing.TB) *lokiOracle {
	tb.Helper()
	base := os.Getenv("SONDA_TEST_LOKI_URL")
	if base == "" {
		tb.Skip("SONDA_TEST_LOKI_URL is not set")
	}
	o := &lokiOracle{url: strings.TrimSuffix(base, "/"), client: &http.Client{Timeout: 10 * time.Second}}
	// A fresh Loki needs a few seconds before it accepts pushes.
	deadline := time.Now().Add(90 * time.Second)
	for {
		resp, err := o.client.Get(o.url + "/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return o
			}
		}
		if time.Now().After(deadline) {
			tb.Fatalf("Loki at %s is not ready: %v", o.url, err)
		}
		time.Sleep(time.Second)
	}
}

// format returns Loki's formatting of the query, or false when Loki rejects it.
func (o *lokiOracle) format(tb testing.TB, query string) (string, bool) {
	tb.Helper()
	resp, err := o.client.PostForm(o.url+"/loki/api/v1/format_query", url.Values{"query": {query}})
	if err != nil {
		tb.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
		Data   string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		tb.Fatalf("format_query: %v", err)
	}
	switch {
	case resp.StatusCode == http.StatusOK && body.Status == "success":
		return body.Data, true
	case resp.StatusCode == http.StatusBadRequest:
		return "", false
	}
	tb.Fatalf("format_query returned HTTP %d", resp.StatusCode)
	return "", false
}

// selectors returns the selectors of a query as Loki sees them, sorted, or false when Loki
// rejects the query.
func (o *lokiOracle) selectors(tb testing.TB, query string) ([]string, bool) {
	tb.Helper()
	formatted, ok := o.format(tb, query)
	if !ok {
		return nil, false
	}
	q, err := Parse(formatted)
	if err != nil {
		tb.Fatalf("cannot lex Loki's formatting of %q: %v\n formatted %q", query, err, formatted)
	}
	got := selectorStrings(q)
	slices.Sort(got)
	return got, true
}

func scopedRewrite(q Query) string {
	return q.Rewrite(func(m []*labels.Matcher) []*labels.Matcher {
		return append(slices.Clone(m), scopeMatchers...)
	})
}

func hasScope(selector []*labels.Matcher) bool {
	return slices.ContainsFunc(selector, func(m *labels.Matcher) bool {
		return m.Type == labels.MatchEqual && m.Name == "app" && m.Value == "api"
	})
}

// checkScoped fails when Loki would run the scoped query with a selector that lacks the
// scope. This is the property Sonda's security rests on.
func checkScoped(t *testing.T, o *lokiOracle, input, scoped string) {
	t.Helper()
	formatted, ok := o.format(t, scoped)
	if !ok {
		return // Loki rejects the query, so it cannot leak anything.
	}
	q, err := Parse(formatted)
	if err != nil {
		t.Fatalf("cannot lex Loki's formatting of %q: %v\n formatted %q", scoped, err, formatted)
	}
	for _, selector := range q.Selectors() {
		if !hasScope(selector) {
			t.Errorf("unscoped selector %s\n input  %q\n scoped %q", FormatSelector(selector), input, scoped)
		}
	}
}

func TestAgreesWithLoki(t *testing.T) {
	o := newOracle(t)
	for _, query := range corpus {
		want, ok := o.selectors(t, query)
		if !ok {
			t.Errorf("corpus query is not valid LogQL: %s", query)
			continue
		}
		q, err := Parse(query)
		if err != nil {
			t.Errorf("%s: %v", query, err)
			continue
		}
		got := selectorStrings(q)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got  %q\n loki %q", query, got, want)
		}
		scoped := scopedRewrite(q)
		if _, ok := o.format(t, scoped); !ok {
			t.Errorf("Loki rejects the scoped query %q", scoped)
		}
		checkScoped(t, o, query, scoped)
	}
}

// TestScopedQueriesSeeNoOtherService runs scoped queries that try to reach another service
// against stored logs. It does not depend on Loki's formatter being faithful.
func TestScopedQueriesSeeNoOtherService(t *testing.T) {
	o := newOracle(t)
	now := time.Now()
	push := fmt.Sprintf(`{"streams":[{"stream":{"app":"billing"},"values":[[%q,"billing secret"]]}]}`,
		strconv.FormatInt(now.UnixNano(), 10))
	resp, err := o.client.Post(o.url+"/loki/api/v1/push", "application/json", strings.NewReader(push))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("push returned HTTP %d", resp.StatusCode)
	}

	unscoped := []string{
		`{app="billing"}`,
		`{app=~".+"} |= "secret"`,
		`sum(count_over_time({app="billing"}[1h]))`,
		`sum(count_over_time({app="api"}[1h])) or sum(count_over_time({app="billing"}[1h]))`,
		"{app=\"api\"} # \n or {app=\"billing\"}",
	}
	// The unscoped query must see the stored line, or the test proves nothing. Loki may
	// need a moment to make a pushed line queryable.
	for attempt := 0; !o.hasData(t, unscoped[0], now); attempt++ {
		if attempt == 10 {
			t.Fatal("the stored line is not visible to an unscoped query")
		}
		time.Sleep(time.Second)
	}
	for _, query := range unscoped {
		q, err := Parse(query)
		if err != nil {
			continue // Rejected queries cannot leak.
		}
		if scoped := scopedRewrite(q); o.hasData(t, scoped, now) {
			t.Errorf("scoped query sees another service: %s", scoped)
		}
	}
}

// hasData runs a query over the last hour and reports whether it returned anything.
func (o *lokiOracle) hasData(t *testing.T, query string, now time.Time) bool {
	t.Helper()
	params := url.Values{
		"query": {query},
		"start": {strconv.FormatInt(now.Add(-time.Hour).UnixNano(), 10)},
		"end":   {strconv.FormatInt(now.Add(time.Minute).UnixNano(), 10)},
		"step":  {"60"},
	}
	resp, err := o.client.Get(o.url + "/loki/api/v1/query_range?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusBadRequest {
		return false
	}
	var parsed struct {
		Data struct {
			Result []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &parsed) != nil {
		t.Fatalf("query_range %q returned HTTP %d: %s", query, resp.StatusCode, body)
	}
	return len(parsed.Data.Result) > 0
}

func FuzzScope(f *testing.F) {
	o := newOracle(f)
	for _, query := range corpus {
		f.Add(query)
	}
	f.Fuzz(func(t *testing.T, input string) {
		q, err := Parse(input)
		if err != nil {
			return
		}
		checkScoped(t, o, input, scopedRewrite(q))
		want, ok := o.selectors(t, input)
		if !ok {
			return
		}
		got := selectorStrings(q)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("selectors differ for %q:\n got  %q\n loki %q", input, got, want)
		}
	})
}
