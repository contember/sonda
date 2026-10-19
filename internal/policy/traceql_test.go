package policy

import (
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

func tempoScope(t *testing.T) authz.TempoScope {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  tempo: { type: tempo, url: "http://tempo" }
services:
  api:
    environments:
      production:
        traces: { source: tempo, service: engine-api }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Service: "api", Environment: "production", Capability: api.CapabilityTraces},
	}}
	scope, err := authz.New(cfg, nil).TraceScope(identity, "api", "production")
	if err != nil {
		t.Fatal(err)
	}
	tempo, _ := scope.Tempo()
	return tempo
}

func TestScopeTraceQL(t *testing.T) {
	scope := tempoScope(t)
	tests := []struct{ in, want string }{
		{`{}`, `{ resource.service.name = "engine-api" }`},
		{`{  }`, `{ resource.service.name = "engine-api" }`},
		{`{ .a = 1 || true }`, `{ ( .a = 1 || true ) && resource.service.name = "engine-api" }`},
		{
			`{ resource.service.name = "billing" }`,
			`{ ( resource.service.name = "billing" ) && resource.service.name = "engine-api" }`,
		},
		{
			`{ name = "}" } >> {} | select(span.a)`,
			`{ ( name = "}" ) && resource.service.name = "engine-api" } >> { resource.service.name = "engine-api" } | select(span.a)`,
		},
		{
			`({} | count() > 1) && ({ status = error })`,
			`({ resource.service.name = "engine-api" } | count() > 1) && ({ ( status = error ) && resource.service.name = "engine-api" })`,
		},
	}
	for _, tt := range tests {
		got, err := ScopeTraceQL(scope, tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("%s:\n got  %s\n want %s", tt.in, got, tt.want)
		}
	}

	for _, in := range []string{``, `select(span.a)`, `by(resource.service.name)`, `{ } /* } */`, "{ (.a` = 1) } || { true } || { (.b`) = 1 }"} {
		if _, err := ScopeTraceQL(scope, in); !isCode(err, api.CodeInvalidQuery) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestIsScopedFilter(t *testing.T) {
	condition := `resource.service.name = "a"`
	tests := []struct {
		filter string
		scoped bool
	}{
		{` resource.service.name = "a" `, true},
		{` (.x = 1) && resource.service.name = "a" `, true},
		{` (.x = 1) || (true) && resource.service.name = "a" `, false},
		{` (.x = 1)) || ((true) && resource.service.name = "a" `, false},
		{` true || resource.service.name = "a" `, false},
		{`resource.service.name = "a"`, false},
	}
	for _, tt := range tests {
		if got := isScopedFilter(tt.filter, condition); got != tt.scoped {
			t.Errorf("%q: scoped = %v", tt.filter, got)
		}
	}
}

func TestTempoSearch(t *testing.T) {
	scope := tempoScope(t)
	tests := []struct {
		filter TraceFilter
		want   string
	}{
		{TraceFilter{}, `{ resource.service.name = "engine-api" }`},
		{
			TraceFilter{MinDuration: 500 * time.Millisecond, MaxDuration: 90 * time.Second, Errors: true},
			`{ ( duration >= 500ms && duration <= 1m30s && status = error ) && resource.service.name = "engine-api" }`,
		},
		{
			TraceFilter{Name: `GET /a.b"}`},
			`{ ( name =~ ".*GET /a\\.b\"\\}.*" ) && resource.service.name = "engine-api" }`,
		},
		{
			TraceFilter{Where: []Where{
				{Field: "span.http.route", Value: "/x"},
				{Field: ".k8s.pod-name", Value: `a"}`, Negate: true},
				{Field: "resource.service.name", Value: "billing"},
				{Field: "statusMessage", Value: ""},
			}},
			`{ ( span.http.route = "/x" && .k8s.pod-name != "a\"}" && resource.service.name = "billing" && statusMessage = "" ) && resource.service.name = "engine-api" }`,
		},
	}
	for _, tt := range tests {
		got, err := TempoSearch(scope, tt.filter)
		if err != nil {
			t.Errorf("%+v: %v", tt.filter, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("%+v:\n got  %s\n want %s", tt.filter, got, tt.want)
		}
	}

	for _, field := range []string{"http.route", "duration", "status", "span.", "event.name", "span.a$b", "@message", "rootName"} {
		_, err := TempoSearch(scope, TraceFilter{Where: []Where{{Field: field, Value: "x"}}})
		if !isCode(err, api.CodeInvalidRequest) {
			t.Errorf("where field %q: %v", field, err)
		}
	}
	// The lexer rejects these attribute names, because they contain forbidden identifiers.
	for _, field := range []string{".rootName", "span.parent.id"} {
		_, err := TempoSearch(scope, TraceFilter{Where: []Where{{Field: field, Value: "x"}}})
		if !isCode(err, api.CodeInvalidQuery) {
			t.Errorf("where field %q: %v", field, err)
		}
	}
}
