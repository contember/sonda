package query

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/audit"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/tempo"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
)

var tempoRange = api.TimeRange{From: time.Unix(1767225600, 0).UTC(), To: time.Unix(1767229200, 0).UTC()}

// newTestTempoTraces returns a backend for service api, recorded in Tempo as engine-api,
// and the queries the fake Tempo received.
func newTestTempoTraces(t *testing.T, handler http.HandlerFunc) (traceBackend, *[]string) {
	t.Helper()
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Path+" "+r.FormValue("q"))
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
grafana: { url: "https://grafana.example" }
sources:
  tempo: { type: tempo, url: %q, grafana_datasource_uid: tempo-uid }
services:
  api:
    environments:
      production:
        traces: { source: tempo, service: engine-api }
`, server.URL)), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Grants: []identities.Grant{{Service: "api", Environment: "production", Capability: api.CapabilityTraces}}}
	scope, err := authz.New(cfg, nil).TraceScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	tempoScope, _ := scope.Tempo()
	client, err := tempo.New(cfg.Sources["tempo"])
	if err != nil {
		t.Fatal(err)
	}
	return newTempoTraces(tempoScope, client, cfg.Grafana), &queries
}

func TestTempoQueryIsScopedAndRecorded(t *testing.T) {
	backend, queries := newTestTempoTraces(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"traces":[{"traceID":"1","rootServiceName":"billing","startTimeUnixNano":"1767225600000000000",
			"spanSets":[{"spans":[{"spanID":"2","startTimeUnixNano":"1767225600000000000","durationNanos":"5"}]}]}]}`)
	})
	ctx, record := audit.WithRecord(context.Background())
	found, err := backend.query(ctx, tempoRange, `{ resource.service.name = "billing" } >> {}`, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := `{ ( resource.service.name = "billing" ) && resource.service.name = "engine-api" } >> { resource.service.name = "engine-api" }`
	if !slices.Equal(*queries, []string{"/api/search " + want}) {
		t.Errorf("upstream queries %q", *queries)
	}
	if found.query != want || found.source.Kind != "tempo" || found.source.Query != want || !strings.HasPrefix(found.source.URL, "https://grafana.example/explore?") {
		t.Errorf("query %q, source %+v", found.query, found.source)
	}
	if _, _, recorded := record.Snapshot(); !slices.Equal(recorded, []string{want}) {
		t.Errorf("recorded %q", recorded)
	}
	if len(found.traces) != 1 || len(found.traces[0].Matched) != 1 || found.traces[0].Matched[0].Service != "engine-api" {
		t.Errorf("traces %+v", found.traces)
	}
}

func TestTempoSearchBuildsAScopedQuery(t *testing.T) {
	backend, queries := newTestTempoTraces(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"traces":[]}`)
	})
	filter := policy.TraceFilter{Errors: true, Where: []policy.Where{{Field: "span.http.route", Value: "/x"}}}
	found, err := backend.search(context.Background(), tempoRange, filter, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := `{ ( status = error && span.http.route = "/x" ) && resource.service.name = "engine-api" }`
	if found.query != want || !slices.Equal(*queries, []string{"/api/search " + want}) {
		t.Errorf("query %q, upstream %q", found.query, *queries)
	}
}

func TestTempoRejectsBeforeTheUpstream(t *testing.T) {
	backend, queries := newTestTempoTraces(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"traces":[]}`)
	})
	if _, err := backend.query(context.Background(), tempoRange, `select(span.secret)`, 5); !isAPICode(err, api.CodeInvalidQuery) {
		t.Errorf("unscoped pipeline: %v", err)
	}
	filter := policy.TraceFilter{Where: []policy.Where{{Field: "http.route", Value: "/x"}}}
	if _, err := backend.search(context.Background(), tempoRange, filter, 5); !isAPICode(err, api.CodeInvalidRequest) {
		t.Errorf("unscoped where field: %v", err)
	}
	if len(*queries) != 0 {
		t.Errorf("upstream queries %q", *queries)
	}
}

func TestTempoTrace(t *testing.T) {
	backend, queries := newTestTempoTraces(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/traces/00000000000000000000000000000404" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"trace":{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"engine-api"}}]},
			"scopeSpans":[{"spans":[{"traceId":"01","spanId":"02","name":"GET /","startTimeUnixNano":"1","endTimeUnixNano":"2"}]}]}]}}`)
	})
	ctx, record := audit.WithRecord(context.Background())
	id := "00000000000000000000000000000001"
	fetched, err := backend.trace(ctx, tempoRange, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched.spans) != 1 || fetched.spans[0].Service != "engine-api" || fetched.source.Query != id || fetched.source.URL == "" {
		t.Errorf("fetched %+v", fetched)
	}
	if _, _, recorded := record.Snapshot(); !slices.Equal(recorded, []string{"trace " + id}) {
		t.Errorf("recorded %q", recorded)
	}
	if _, err := backend.trace(ctx, tempoRange, "00000000000000000000000000000404"); !isAPICode(err, api.CodeNotFound) {
		t.Errorf("missing trace: %v", err)
	}
	if len(*queries) != 2 {
		t.Errorf("upstream queries %q", *queries)
	}
}

func isAPICode(err error, code api.ErrorCode) bool {
	e, ok := apierr.As(err)
	return ok && e.Code == code
}
