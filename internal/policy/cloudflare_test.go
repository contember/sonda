package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

func cloudflareScope(t *testing.T) authz.CloudflareScope {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  cf: { type: cloudflare, account_id: acc, auth: { type: bearer, token: t } }
services:
  api:
    environments:
      production:
        logs: { source: cf, script: api-worker }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Service: "api", Environment: "production", Capability: api.CapabilityLogs},
	}}
	logScope, err := authz.New(cfg, nil).LogScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	scope, ok := logScope.Cloudflare()
	if !ok {
		t.Fatal("not a cloudflare scope")
	}
	return scope
}

const scopeLeaf = `{"key":"$metadata.service","operation":"eq","type":"string","value":"api-worker"}`

func TestScopeCloudflareQuery(t *testing.T) {
	scope := cloudflareScope(t)
	tests := []struct{ in, want string }{
		{`{}`, `{"view":"events","parameters":{"filterCombination":"and","filters":[` + scopeLeaf + `]}}`},
		{
			`{"filters":[{"key":"$metadata.service","operation":"eq","type":"string","value":"other"}]}`,
			`{"view":"events","parameters":{"filterCombination":"and","filters":[` + scopeLeaf +
				`,{"kind":"group","filterCombination":"and","filters":[{"key":"$metadata.service","operation":"eq","type":"string","value":"other"}]}]}}`,
		},
		{
			`{"filterCombination":"or","filters":[{"key":"$metadata.service","operation":"neq","type":"string","value":"api-worker"},{"kind":"filter","key":"a","operation":"exists","type":"string"}]}`,
			`{"view":"events","parameters":{"filterCombination":"and","filters":[` + scopeLeaf +
				`,{"kind":"group","filterCombination":"or","filters":[{"key":"$metadata.service","operation":"neq","type":"string","value":"api-worker"},{"key":"a","operation":"exists","type":"string"}]}]}}`,
		},
		{
			`{"view":"calculations","limit":5,"needle":{"value":"boom","matchCase":true},"calculations":[{"operator":"count","alias":"n"}],` +
				`"groupBys":[{"type":"number","value":"$metadata.statusCode"}],"havings":[{"key":"n","operation":"gt","value":1}],"orderBy":{"value":"n","order":"desc"}}`,
			`{"view":"calculations","limit":5,"parameters":{"filterCombination":"and","filters":[` + scopeLeaf + `],"needle":{"value":"boom","matchCase":true},` +
				`"calculations":[{"operator":"count","alias":"n"}],"groupBys":[{"type":"number","value":"$metadata.statusCode"}],"havings":[{"key":"n","operation":"gt","value":1}],"orderBy":{"value":"n","order":"desc"}}}`,
		},
		{
			`{"filters":[{"kind":"group","filterCombination":"or","filters":[{"kind":"group","filterCombination":"and","filters":[{"key":"x","operation":"gt","type":"number","value":3}]}]}]}`,
			`{"view":"events","parameters":{"filterCombination":"and","filters":[` + scopeLeaf +
				`,{"kind":"group","filterCombination":"and","filters":[{"kind":"group","filterCombination":"or","filters":[{"kind":"group","filterCombination":"and","filters":[{"key":"x","operation":"gt","type":"number","value":3}]}]}]}]}}`,
		},
	}
	for _, tt := range tests {
		q, err := ScopeCloudflareQuery(scope, tt.in, CloudflareViewEvents, CloudflareViewCalculations, CloudflareViewInvocations)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if q.String() != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.in, q.String(), tt.want)
		}
	}
}

func TestScopeCloudflareQueryRejects(t *testing.T) {
	scope := cloudflareScope(t)
	leaf := `{"key":"a","operation":"eq","type":"string","value":"b"}`
	group := func(inner string) string {
		return `{"kind":"group","filterCombination":"and","filters":[` + inner + `]}`
	}
	tests := []struct{ name, in, wantErr string }{
		{"queryId", `{"queryId":"saved-query"}`, `unknown field "queryId"`},
		{"datasets", `{"datasets":["other"]}`, `unknown field "datasets"`},
		{"parameters", `{"parameters":{"filters":[]}}`, `unknown field "parameters"`},
		{"timeframe", `{"timeframe":{"from":0,"to":1}}`, `unknown field "timeframe"`},
		{"offset", `{"offset":"abc"}`, `unknown field "offset"`},
		{"unknown leaf field", `{"filters":[{"id":"1","key":"a","operation":"eq","type":"string","value":"b"}]}`, `unknown field "id"`},
		{"depth 4", `{"filters":[` + group(group(group(leaf))) + `]}`, "more than 3 levels"},
		{"unknown op", `{"filters":[{"key":"a","operation":"MATCH_REGEX","type":"string","value":"b"}]}`, `operation "MATCH_REGEX"`},
		{"symbol op", `{"filters":[{"key":"a","operation":"=","type":"string","value":"b"}]}`, `operation "="`},
		{"unknown type", `{"filters":[{"key":"a","operation":"eq","type":"object","value":"b"}]}`, "type must be"},
		{"unknown kind", `{"filters":[{"kind":"raw","key":"a","operation":"eq","type":"string"}]}`, "kind must be"},
		{"group with key", `{"filters":[{"kind":"group","key":"a","filterCombination":"and","filters":[` + leaf + `]}]}`, "cannot have key"},
		{"leaf with filters", `{"filters":[{"key":"a","operation":"eq","type":"string","filters":[` + leaf + `]}]}`, "cannot have filterCombination"},
		{"empty group", `{"filters":[{"kind":"group","filterCombination":"and","filters":[]}]}`, "needs filters"},
		{"object value", `{"filters":[{"key":"a","operation":"eq","type":"string","value":{"x":1}}]}`, "string, number or boolean"},
		{"array value", `{"filters":[{"key":"a","operation":"in","type":"string","value":["a"]}]}`, "string, number or boolean"},
		{"no needle value", `{"needle":{"isRegex":true}}`, "needle value is required"},
		{"combination", `{"filterCombination":"xor"}`, "filterCombination"},
		{"limit", `{"limit":5000}`, "limit must be"},
		{"trailing garbage", `{} {"datasets":["x"]}`, "single JSON object"},
		{"trailing text", `{}x`, "single JSON object"},
		{"not an object", `[]`, "invalid Cloudflare query"},
		{"view", `{"view":"traces"}`, `view "traces" is not allowed`},
	}
	for _, tt := range tests {
		_, err := ScopeCloudflareQuery(scope, tt.in, CloudflareViewEvents, CloudflareViewCalculations, CloudflareViewInvocations)
		if err == nil || !isCode(err, api.CodeInvalidQuery) || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: error = %v, want invalid_query containing %q", tt.name, err, tt.wantErr)
		}
	}
}

func TestScopeCloudflareQueryDefaultsToFirstView(t *testing.T) {
	q, err := ScopeCloudflareQuery(cloudflareScope(t), `{}`, CloudflareViewTraces)
	if err != nil {
		t.Fatal(err)
	}
	if q.View() != CloudflareViewTraces {
		t.Errorf("view = %s", q.View())
	}
}

func TestCloudflareQueryWithLimit(t *testing.T) {
	scope := cloudflareScope(t)
	for _, tt := range []struct {
		in        string
		cap, want int
	}{
		{`{}`, 100, 100},
		{`{"limit":10}`, 100, 10},
		{`{"limit":500}`, 100, 100},
	} {
		q, err := ScopeCloudflareQuery(scope, tt.in, CloudflareViewEvents)
		if err != nil {
			t.Fatal(err)
		}
		if got := q.WithLimit(tt.cap).limit; got != tt.want {
			t.Errorf("%s capped at %d: limit = %d, want %d", tt.in, tt.cap, got, tt.want)
		}
	}
}

type sentBody struct {
	QueryID   string `json:"queryId"`
	Timeframe struct {
		From int64 `json:"from"`
		To   int64 `json:"to"`
	} `json:"timeframe"`
	View       string          `json:"view"`
	Limit      int             `json:"limit"`
	Parameters json.RawMessage `json:"parameters"`
}

func TestCloudflareQueryBody(t *testing.T) {
	q, err := ScopeCloudflareQuery(cloudflareScope(t), `{"limit":7}`, CloudflareViewEvents)
	if err != nil {
		t.Fatal(err)
	}
	r := api.TimeRange{From: time.UnixMilli(1000), To: time.UnixMilli(5000)}
	data, err := q.Body(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "datasets") {
		t.Errorf("body sends datasets: %s", data)
	}
	var body sentBody
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.QueryID, "sonda-") || len(body.QueryID) != len("sonda-")+16 {
		t.Errorf("queryId = %q", body.QueryID)
	}
	if body.Timeframe.From != 1000 || body.Timeframe.To != 5000 || body.View != "events" || body.Limit != 7 {
		t.Errorf("body = %s", data)
	}
	if want := `{"filterCombination":"and","filters":[` + scopeLeaf + `]}`; string(body.Parameters) != want {
		t.Errorf("parameters = %s, want %s", body.Parameters, want)
	}
	again, _ := q.Body(r)
	var second sentBody
	if err := json.Unmarshal(again, &second); err != nil || second.QueryID == body.QueryID {
		t.Errorf("queryId is not random: %s", second.QueryID)
	}
}

func TestCloudflareLogSearch(t *testing.T) {
	scope := cloudflareScope(t)
	f := LogFilter{
		Contains: []string{"timeout", `say "hi"`},
		Where:    []Where{{Field: "$metadata.level", Value: "error"}, {Field: "$workers.outcome", Value: "ok", Negate: true}},
	}
	events, count, err := CloudflareLogSearch(scope, f, 50)
	if err != nil {
		t.Fatal(err)
	}
	group := `{"kind":"group","filterCombination":"and","filters":[` +
		`{"key":"$metadata.message","operation":"includes","type":"string","value":"say \"hi\""},` +
		`{"key":"$metadata.level","operation":"eq","type":"string","value":"error"},` +
		`{"key":"$workers.outcome","operation":"neq","type":"string","value":"ok"}]}`
	needle := `"needle":{"value":"timeout","matchCase":true}`
	wantEvents := `{"view":"events","limit":50,"parameters":{"filterCombination":"and","filters":[` + scopeLeaf + `,` + group + `],` + needle + `}}`
	if events.String() != wantEvents {
		t.Errorf("events:\n got %s\nwant %s", events.String(), wantEvents)
	}
	wantCount := `{"view":"calculations","parameters":{"filterCombination":"and","filters":[` + scopeLeaf + `,` + group + `],` + needle + `,"calculations":[{"operator":"count"}]}}`
	if count.String() != wantCount {
		t.Errorf("count:\n got %s\nwant %s", count.String(), wantCount)
	}

	plain, _, err := CloudflareLogSearch(scope, LogFilter{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"view":"events","limit":10,"parameters":{"filterCombination":"and","filters":[` + scopeLeaf + `]}}`; plain.String() != want {
		t.Errorf("plain search = %s", plain.String())
	}
	if _, _, err := CloudflareLogSearch(scope, LogFilter{Pipeline: "| json"}, 10); !isCode(err, api.CodeInvalidRequest) {
		t.Errorf("pipeline: %v", err)
	}
}

func TestCloudflareTraceSearch(t *testing.T) {
	q, err := CloudflareTraceSearch(cloudflareScope(t), TraceFilter{
		MinDuration: 1500 * time.Microsecond,
		MaxDuration: 2 * time.Second,
		Errors:      true,
		Name:        "fetch",
		Where:       []Where{{Field: "$metadata.trigger", Value: "GET /"}},
	}, 21)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"view":"traces","limit":21,"parameters":{"filterCombination":"and","filters":[` + scopeLeaf +
		`,{"kind":"group","filterCombination":"and","filters":[` +
		`{"key":"$metadata.duration","operation":"gte","type":"number","value":1.5},` +
		`{"key":"$metadata.duration","operation":"lte","type":"number","value":2000},` +
		`{"key":"$metadata.error","operation":"exists","type":"string"},` +
		`{"key":"$metadata.spanName","operation":"includes","type":"string","value":"fetch"},` +
		`{"key":"$metadata.trigger","operation":"eq","type":"string","value":"GET /"}]}]}}`
	if q.String() != want {
		t.Errorf("\n got %s\nwant %s", q.String(), want)
	}
}

func TestCloudflareTraceByID(t *testing.T) {
	q := CloudflareTraceByID(cloudflareScope(t), "0123456789abcdef0123456789abcdef")
	want := `{"view":"events","limit":2000,"parameters":{"filterCombination":"and","filters":[{"key":"$metadata.traceId","operation":"eq","type":"string","value":"0123456789abcdef0123456789abcdef"}]}}`
	if q.String() != want {
		t.Errorf("\n got %s\nwant %s", q.String(), want)
	}
}

func TestCloudflareKeys(t *testing.T) {
	data, err := CloudflareKeys(cloudflareScope(t), api.TimeRange{From: time.UnixMilli(1000), To: time.UnixMilli(2000)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"from":1000,"to":2000,"filters":[` + scopeLeaf + `],"limit":1000}`
	if string(data) != want {
		t.Errorf("\n got %s\nwant %s", data, want)
	}
}
