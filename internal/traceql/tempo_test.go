package traceql_test

// These tests check the lexer against a real Tempo, so no Tempo code is linked into Sonda.
// They run when SONDA_TEST_TEMPO_URL points to a Tempo that holds the traces of
// dev/seed-traces.sh:
//
//	docker compose -f dev/docker-compose.yml up -d tempo && dev/seed-traces.sh
//	SONDA_TEST_TEMPO_URL=http://localhost:13200 go test ./internal/traceql
//
// Tempo has no endpoint that prints a parsed query, so the tests check what scoped queries
// return: every span they match belongs to the scoped service.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/internal/policy"
)

const (
	scopedService = "svc-a"
	otherService  = "svc-b"
)

type tempoOracle struct {
	url    string
	client *http.Client
	now    time.Time
	// services caches the service of every span by trace ID and span ID.
	services map[string]map[string]string
}

func newTempoOracle(tb testing.TB) *tempoOracle {
	tb.Helper()
	o := tempoOracleFromEnv(tb)
	if o == nil {
		tb.Skip("SONDA_TEST_TEMPO_URL is not set")
	}
	return o
}

// tempoOracleFromEnv returns nil when SONDA_TEST_TEMPO_URL is not set.
func tempoOracleFromEnv(tb testing.TB) *tempoOracle {
	tb.Helper()
	base := os.Getenv("SONDA_TEST_TEMPO_URL")
	if base == "" {
		return nil
	}
	o := &tempoOracle{
		url:      strings.TrimSuffix(base, "/"),
		client:   &http.Client{Timeout: 30 * time.Second},
		now:      time.Now(),
		services: map[string]map[string]string{},
	}
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
			tb.Fatalf("Tempo at %s is not ready: %v", o.url, err)
		}
		time.Sleep(time.Second)
	}
}

type searchedTrace struct {
	TraceID  string `json:"traceID"`
	SpanSets []struct {
		Spans []struct {
			SpanID string `json:"spanID"`
		} `json:"spans"`
	} `json:"spanSets"`
}

func (o *tempoOracle) get(tb testing.TB, path string) *http.Response {
	tb.Helper()
	resp, err := o.client.Get(o.url + path)
	if err != nil {
		tb.Fatal(err)
	}
	return resp
}

// search runs a query over the last day, or returns false when Tempo rejects it. Tempo also
// reports some evaluation errors, such as !."" on stored blocks, as HTTP 500; an error
// response returns no spans either.
func (o *tempoOracle) search(tb testing.TB, query string) ([]searchedTrace, bool) {
	tb.Helper()
	params := url.Values{
		"q":     {query},
		"start": {strconv.FormatInt(o.now.Add(-24*time.Hour).Unix(), 10)},
		"end":   {strconv.FormatInt(o.now.Add(time.Minute).Unix(), 10)},
		"limit": {"100"},
		"spss":  {"100"},
	}
	resp := o.get(tb, "/api/search?"+params.Encode())
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusInternalServerError {
		return nil, false
	}
	var body struct {
		Traces []searchedTrace `json:"traces"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&body) != nil {
		tb.Fatalf("search %q returned HTTP %d", query, resp.StatusCode)
	}
	return body.Traces, true
}

// matchedServices returns the service of every span the trace matched, from the stored trace.
func (o *tempoOracle) matchedServices(tb testing.TB, trace searchedTrace) []string {
	tb.Helper()
	services := o.spanServices(tb, trace.TraceID)
	var matched []string
	for _, set := range trace.SpanSets {
		for _, span := range set.Spans {
			service, ok := services[padHex(span.SpanID, 16)]
			if !ok {
				tb.Fatalf("span %s of trace %s is not in the stored trace", span.SpanID, trace.TraceID)
			}
			matched = append(matched, service)
		}
	}
	return matched
}

func (o *tempoOracle) spanServices(tb testing.TB, traceID string) map[string]string {
	tb.Helper()
	if services, ok := o.services[traceID]; ok {
		return services
	}
	resp := o.get(tb, "/api/v2/traces/"+padHex(traceID, 32))
	defer resp.Body.Close()
	var body struct {
		Trace struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []struct {
						Key   string `json:"key"`
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []struct {
						SpanID string `json:"spanId"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		} `json:"trace"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&body) != nil {
		tb.Fatalf("trace %s returned HTTP %d", traceID, resp.StatusCode)
	}
	services := map[string]string{}
	for _, rs := range body.Trace.ResourceSpans {
		var service string
		for _, a := range rs.Resource.Attributes {
			if a.Key == "service.name" {
				service = a.Value.StringValue
			}
		}
		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				id, err := base64.StdEncoding.DecodeString(span.SpanID)
				if err != nil {
					tb.Fatalf("span ID %q of trace %s is not base64", span.SpanID, traceID)
				}
				services[hex.EncodeToString(id)] = service
			}
		}
	}
	o.services[traceID] = services
	return services
}

// padHex restores the leading zeros Tempo drops from hex IDs.
func padHex(id string, length int) string {
	return strings.Repeat("0", max(length-len(id), 0)) + id
}

// checkMatchesOnlyTheService fails when a scoped query that Tempo accepts matches a span of
// another service.
func (o *tempoOracle) checkMatchesOnlyTheService(t *testing.T, input, scoped string) {
	t.Helper()
	found, _ := o.search(t, scoped)
	for _, trace := range found {
		for _, service := range o.matchedServices(t, trace) {
			if service != scopedService {
				t.Errorf("scoped query matches a span of %s in trace %s:\n input  %q\n scoped %q", service, trace.TraceID, input, scoped)
			}
		}
	}
}

// TestScopedCorpusMatchesOnlyTheService runs every corpus query unscoped and scoped. Tempo
// must accept both, unless the query is marked invalid, and the scoped query must match only
// spans of the scoped service. This is the property Sonda's security rests on.
func TestScopedCorpusMatchesOnlyTheService(t *testing.T) {
	o := newTempoOracle(t)
	scope := tempoScope(t, scopedService)
	if traces, _ := o.search(t, fmt.Sprintf(`{ resource.service.name = %q }`, otherService)); len(traces) == 0 {
		t.Fatalf("Tempo holds no traces of %s; run dev/seed-traces.sh", otherService)
	}
	var otherUnscoped, scopedMatches int
	for _, e := range readCorpus(t) {
		if e.tag == "reject" {
			continue
		}
		scoped, err := policy.ScopeTraceQL(scope, e.query)
		if err != nil {
			t.Errorf("%s: %v", e.query, err)
			continue
		}
		raw, rawOK := o.search(t, e.query)
		found, scopedOK := o.search(t, scoped.String())
		switch {
		case e.tag == "ok" && (!rawOK || !scopedOK):
			t.Errorf("Tempo rejects a valid corpus query (unscoped accepted: %v):\n input  %s\n scoped %s", rawOK, e.query, scoped)
		case e.tag == "invalid" && (rawOK || scopedOK):
			t.Errorf("Tempo accepts an invalid corpus query (unscoped: %v, scoped: %v): %s", rawOK, scopedOK, e.query)
		}
		for _, trace := range raw {
			for _, service := range o.matchedServices(t, trace) {
				if service != scopedService {
					otherUnscoped++
				}
			}
		}
		for _, trace := range found {
			for _, service := range o.matchedServices(t, trace) {
				scopedMatches++
				if service != scopedService {
					t.Errorf("scoped query matches a span of %s in trace %s:\n input  %s\n scoped %s", service, trace.TraceID, e.query, scoped)
				}
			}
		}
	}
	// Without these, the corpus would pass without reaching the data it must protect.
	if otherUnscoped == 0 || scopedMatches == 0 {
		t.Errorf("corpus matched %d spans of other services unscoped and %d spans scoped; both must be positive", otherUnscoped, scopedMatches)
	}
}

// TestScopedQueriesSeeNoTraceOfAnotherService checks that traces without a span of the
// scoped service never appear in scoped results, whatever the query asks for.
func TestScopedQueriesSeeNoTraceOfAnotherService(t *testing.T) {
	o := newTempoOracle(t)
	scope := tempoScope(t, scopedService)
	otherOnly := o.otherOnlyTraces(t)
	if len(otherOnly) == 0 {
		t.Fatalf("Tempo holds no trace with spans of %s only; run dev/seed-traces.sh", otherService)
	}
	for _, query := range []string{
		`{}`,
		`{ resource.service.name = "svc-b" }`,
		`{ span.secret = "b-only" }`,
		`{ trace:rootService = "svc-b" }`,
		`{ } || { resource.service.name = "svc-b" }`,
		`{ resource.service.name = "svc-a" } || { span.secret =~ ".+" }`,
		`{ } !>> { span.secret != nil }`,
		`({ span.secret != nil } | count() > 0) && ({ })`,
		`{ span.secret != nil } | select(span.secret)`,
		`{ span.secret != nil } | by(resource.service.name)`,
		`{ span.secret != nil } with (most_recent=true)`,
	} {
		unscoped, ok := o.search(t, query)
		if !ok {
			t.Errorf("Tempo rejects %s", query)
			continue
		}
		if !slices.ContainsFunc(unscoped, func(trace searchedTrace) bool { return otherOnly[padHex(trace.TraceID, 32)] }) {
			t.Errorf("unscoped %s does not see a trace of %s only, so the check proves nothing", query, otherService)
		}
		scoped, err := policy.ScopeTraceQL(scope, query)
		if err != nil {
			t.Errorf("%s: %v", query, err)
			continue
		}
		found, ok := o.search(t, scoped.String())
		if !ok {
			t.Errorf("Tempo rejects the scoped query %s", scoped)
			continue
		}
		for _, trace := range found {
			if otherOnly[padHex(trace.TraceID, 32)] {
				t.Errorf("scoped query returns trace %s of %s only: %s", trace.TraceID, otherService, scoped)
			}
		}
	}
}

// otherOnlyTraces returns the IDs of stored traces that have no span of the scoped service.
func (o *tempoOracle) otherOnlyTraces(t *testing.T) map[string]bool {
	t.Helper()
	traces, ok := o.search(t, fmt.Sprintf(`{ resource.service.name = %q }`, otherService))
	if !ok {
		t.Fatal("Tempo rejects the search for the other service")
	}
	otherOnly := map[string]bool{}
	for _, trace := range traces {
		services := o.spanServices(t, trace.TraceID)
		if !slices.Contains(slices.Collect(maps.Values(services)), scopedService) {
			otherOnly[padHex(trace.TraceID, 32)] = true
		}
	}
	return otherOnly
}

// TestTempoSearchQueriesRun checks that Tempo accepts the queries of a structured search and
// that they match only spans of the scoped service.
func TestTempoSearchQueriesRun(t *testing.T) {
	o := newTempoOracle(t)
	scope := tempoScope(t, scopedService)
	for _, filter := range []policy.TraceFilter{
		{},
		{MinDuration: 500 * time.Microsecond, MaxDuration: time.Hour + 90*time.Second},
		{Errors: true, Name: `GET /a.b"}`},
		{Where: []policy.Where{
			{Field: "span.secret", Value: "b-only", Negate: true},
			{Field: "resource.service.name", Value: otherService},
			{Field: ".http.method", Value: "GET"},
			{Field: "name", Value: "render report"},
		}},
	} {
		q, err := policy.TempoSearch(scope, filter)
		if err != nil {
			t.Errorf("%+v: %v", filter, err)
			continue
		}
		found, ok := o.search(t, q.String())
		if !ok {
			t.Errorf("Tempo rejects %s", q)
			continue
		}
		for _, trace := range found {
			for _, service := range o.matchedServices(t, trace) {
				if service != scopedService {
					t.Errorf("%s matches a span of %s in trace %s", q, service, trace.TraceID)
				}
			}
		}
	}
}
