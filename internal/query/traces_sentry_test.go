package query

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/audit"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/sentry"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
)

const (
	sentryTraceA = "0000000000000000000000000000000a"
	sentryTraceB = "0000000000000000000000000000000b"
)

// newTestSentryTraces returns a backend for service api, the Sentry project api in production,
// and the requests the fake Sentry received.
func newTestSentryTraces(t *testing.T, handler func(w http.ResponseWriter, q url.Values)) (traceBackend, *[]url.Values) {
	t.Helper()
	var requests []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/0/organizations/acme/events/" {
			t.Errorf("path %s", r.URL.Path)
		}
		requests = append(requests, r.URL.Query())
		handler(w, r.URL.Query())
	}))
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
sources:
  sentry: { type: sentry, url: %q, org: acme, auth: { type: bearer, token: s } }
projects:
  api:
    services:
      api:
        environments:
          production:
            traces: { source: sentry, project: api, environment: production }
`, server.URL)), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Grants: []identities.Grant{{Project: "api", Environment: "production", Capability: api.CapabilityTraces}}}
	scope, err := authz.New(cfg, nil).TraceScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	sentryScope, _ := scope.Sentry()
	return newSentryTraces(sentryScope, sentry.New(cfg.Sources["sentry"], upstream.HTTPClient(cfg.Sources["sentry"], nil))), &requests
}

func spanRowJSON(trace, id, parent, project, env, transaction string) string {
	return fmt.Sprintf(`{"id":%q,"parent_span":%q,"trace":%q,"project":%q,"environment":%q,"transaction":%q,
		"span.op":"db","span.description":"SELECT 1","span.status":"internal_error","span.duration":12.5,"precise.start_ts":1767225600.25}`,
		id, parent, trace, project, env, transaction)
}

func TestSentrySearchGroupsSpansIntoNamedTraces(t *testing.T) {
	backend, requests := newTestSentryTraces(t, func(w http.ResponseWriter, q url.Values) {
		if strings.HasPrefix(q.Get("query"), "is_transaction:true") {
			fmt.Fprintf(w, `{"data":[%s,%s]}`,
				spanRowJSON(sentryTraceA, "00000000000000a2", "00000000000000a1", "api", "production", "worker job"),
				spanRowJSON(sentryTraceA, "00000000000000a1", "", "web", "production", "GET /checkout"))
			return
		}
		fmt.Fprintf(w, `{"data":[%s,%s,%s]}`,
			spanRowJSON(sentryTraceA, "00000000000000a3", "00000000000000a2", "api", "production", ""),
			spanRowJSON(sentryTraceB, "00000000000000b1", "", "api", "production", ""),
			spanRowJSON(sentryTraceA, "00000000000000a4", "00000000000000a2", "api", "production", ""))
	})
	ctx, record := audit.WithRecord(context.Background())
	found, err := backend.search(ctx, tempoRange, policy.TraceFilter{Errors: true}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 2 {
		t.Fatalf("requests %v", *requests)
	}
	spans, segments := (*requests)[0], (*requests)[1]
	if spans.Get("dataset") != "spans" || spans.Get("projectSlug") != "api" || spans.Get("environment") != "production" ||
		spans.Get("query") != "has:span.status !span.status:ok" || spans.Get("project") != "" || !slices.Contains(spans["field"], "precise.start_ts") {
		t.Errorf("span request %v", spans)
	}
	if segments.Get("project") != "-1" || segments.Get("projectSlug") != "" || segments.Get("query") != "is_transaction:true trace:["+sentryTraceA+"]" {
		t.Errorf("segment request %v", segments)
	}
	// The limit keeps the first trace; its root is the segment without a parent, in project web.
	if len(found.traces) != 1 {
		t.Fatalf("traces %+v", found.traces)
	}
	trace := found.traces[0]
	if trace.TraceID != sentryTraceA || trace.RootService != "web" || trace.RootName != "GET /checkout" || len(trace.Matched) != 2 {
		t.Errorf("trace %+v", trace)
	}
	if m := trace.Matched[0]; m.Service != "api" || m.Status != "error" || m.StatusMessage != "internal_error" || m.Duration.Milliseconds() != 12 {
		t.Errorf("matched span %+v", m)
	}
	if _, _, recorded := record.Snapshot(); len(recorded) != 2 || recorded[0] != "project:api environment:production has:span.status !span.status:ok" {
		t.Errorf("recorded %q", recorded)
	}
}

func TestSentrySpansOutsideTheScopeFail(t *testing.T) {
	for _, row := range []string{
		spanRowJSON(sentryTraceA, "00000000000000a1", "", "billing", "production", ""),
		spanRowJSON(sentryTraceA, "00000000000000a1", "", "api", "staging", ""),
	} {
		backend, _ := newTestSentryTraces(t, func(w http.ResponseWriter, _ url.Values) {
			fmt.Fprintf(w, `{"data":[%s]}`, row)
		})
		if _, err := backend.query(context.Background(), tempoRange, "span.op:db", 5); !isAPICode(err, api.CodeInternal) {
			t.Errorf("row %s: %v", row, err)
		}
	}
}

func TestSentryTraceRequiresASpanOfTheScope(t *testing.T) {
	tests := []struct {
		name string
		rows []string
		code api.ErrorCode
	}{
		{"production span", []string{
			spanRowJSON(sentryTraceA, "00000000000000a1", "", "web", "production", "GET /"),
			spanRowJSON(sentryTraceA, "00000000000000a2", "00000000000000a1", "api", "production", "job"),
		}, ""},
		{"only staging spans of the project", []string{
			spanRowJSON(sentryTraceA, "00000000000000a2", "", "api", "staging", "job"),
		}, api.CodeNotFound},
		{"only other projects", []string{
			spanRowJSON(sentryTraceA, "00000000000000a1", "", "web", "production", "GET /"),
		}, api.CodeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, requests := newTestSentryTraces(t, func(w http.ResponseWriter, _ url.Values) {
				fmt.Fprintf(w, `{"data":[%s]}`, strings.Join(tt.rows, ","))
			})
			fetched, err := backend.trace(context.Background(), tempoRange, sentryTraceA)
			if tt.code != "" {
				if !isAPICode(err, tt.code) {
					t.Errorf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if q := (*requests)[0]; q.Get("project") != "-1" || q.Get("query") != "trace:"+sentryTraceA {
				t.Errorf("request %v", q)
			}
			if len(fetched.spans) != 2 || fetched.spans[0].Service != "web" {
				t.Errorf("spans %+v", fetched.spans)
			}
		})
	}
}
