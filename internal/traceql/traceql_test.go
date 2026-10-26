package traceql_test

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/traceql"
)

type corpusEntry struct {
	tag, query string
}

// readCorpus reads testdata/corpus.txt; its header describes the format.
func readCorpus(tb testing.TB) []corpusEntry {
	tb.Helper()
	file, err := os.Open("testdata/corpus.txt")
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()
	var entries []corpusEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tag, query, _ := strings.Cut(line, " ")
		if tag != "ok" && tag != "invalid" && tag != "reject" {
			tb.Fatalf("corpus line %q has an unknown tag", line)
		}
		entries = append(entries, corpusEntry{tag: tag, query: query})
	}
	if err := scanner.Err(); err != nil {
		tb.Fatal(err)
	}
	return entries
}

func corpusQueries(tb testing.TB, tags ...string) []string {
	var queries []string
	for _, e := range readCorpus(tb) {
		if slices.Contains(tags, e.tag) {
			queries = append(queries, e.query)
		}
	}
	return queries
}

// tempoScope returns the scope of a service whose spans Tempo records as serviceName.
func tempoScope(tb testing.TB, serviceName string) authz.TempoScope {
	tb.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  tempo: { type: tempo, url: "http://tempo" }
projects:
  api:
    services:
      api:
        environments:
          production:
            traces: { source: tempo, service: `+serviceName+` }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		tb.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "api", Environment: "production", Capability: api.CapabilityTraces},
	}}
	scope, err := authz.New(cfg, nil).TraceScope(identity, "api", "production")
	if err != nil {
		tb.Fatal(err)
	}
	tempo, ok := scope.Tempo()
	if !ok {
		tb.Fatal("not a Tempo scope")
	}
	return tempo
}

func TestParseFindsFilters(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`{}`, []string{``}},
		{` { } `, []string{` `}},
		{`{ .a = "b" }`, []string{` .a = "b" `}},
		{`{ name = "}" } || { name = "{" }`, []string{` name = "}" `, ` name = "{" `}},
		{"{ name = `}{` }", []string{" name = `}{` "}},
		{`{ span."a}b" = 1 }`, []string{` span."a}b" = 1 `}},
		{`{ .a"}" = 1 }`, []string{` .a"}" = 1 `}},
		{`{ name = "\"}" }`, []string{` name = "\"}" `}},
		{`{ (.a = 1) && ((.b = 2)) }`, []string{` (.a = 1) && ((.b = 2)) `}},
		{`{.a=1}>>{.b=2}&&{.c=3}`, []string{`.a=1`, `.b=2`, `.c=3`}},
		{`({ }) || (({ } | count() > 1))`, []string{` `, ` `}},
		{`{ } | by(resource.service.name) | select(.a, name) | avg(duration) > 1s`, []string{` `}},
		{`{ } | rate() by (resource.service.name)`, []string{` `}},
		{`{ } | compare({ status = error }, 10)`, []string{` `, ` status = error `}},
		{`{ } with (most_recent=true)`, []string{` `}},
		{"{ .a = 1 }\n||\t{ }", []string{` .a = 1 `, ` `}},
		{"{ name = `multi\nline` }", []string{" name = `multi\nline` "}},
	}
	for _, tt := range tests {
		q, err := traceql.Parse(tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if got := q.Filters(); !slices.Equal(got, tt.want) {
			t.Errorf("%s:\n got  %q\n want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	rejected := append(corpusQueries(t, "reject"),
		"{ name = \"a\nb\" }",
		"{ name = \"a\\\nb\" }",
		"{ name = \"\xff\" }",
		"{ name = \"\x00\" }",
		"\uFEFF{ }",
		"{ }\u00a0|| { }",
		"{ name = `x }",
		"{ } | select(.a\"x\")`",
	)
	for _, in := range rejected {
		if q, err := traceql.Parse(in); err == nil {
			t.Errorf("%q: accepted with filters %q", in, q.Filters())
		}
	}
}

func TestParseExplainsRejections(t *testing.T) {
	tests := []struct{ in, want string }{
		{`{ } | (count()) > 1`, "wrap aggregates without extra parentheses"},
		{`{ } || (count() > 1)`, "expected a spanset filter"},
		{`{ trace:rootName = "x" }`, "rootName is not supported"},
		{`{ } | select(parent.span.a)`, "parent is not supported"},
	}
	for _, tt := range tests {
		_, err := traceql.Parse(tt.in)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error %v, want containing %q", tt.in, err, tt.want)
		}
	}
}

func TestParseAcceptsCorpus(t *testing.T) {
	for _, in := range corpusQueries(t, "ok", "invalid") {
		if _, err := traceql.Parse(in); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestRewriteKeepsTheRest(t *testing.T) {
	q, err := traceql.Parse("({a}|count()>1) && {} | select(name)")
	if err != nil {
		t.Fatal(err)
	}
	got := q.Rewrite(func(inner string) string { return "<" + inner + ">" })
	if want := "({<a>}|count()>1) && {<>} | select(name)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := q.Rewrite(func(inner string) string { return inner }); got != "({a}|count()>1) && {} | select(name)" {
		t.Errorf("identity rewrite changed the query: %q", got)
	}
}

// FuzzScope checks that every query the lexer accepts is scoped: the scoped query lexes,
// has the same filters, and every filter carries the scope condition at its top level. With
// SONDA_TEST_TEMPO_URL set, it also runs each scoped query against Tempo (tempo_test.go).
func FuzzScope(f *testing.F) {
	scope := tempoScope(f, scopedService)
	condition := `resource.service.name = "svc-a"`
	oracle := tempoOracleFromEnv(f)
	for _, e := range readCorpus(f) {
		f.Add(e.query)
	}
	f.Fuzz(func(t *testing.T, input string) {
		q, err := traceql.Parse(input)
		if err != nil {
			return
		}
		scoped, err := policy.ScopeTraceQL(scope, input)
		if err != nil {
			t.Fatalf("lexed %q but cannot scope it: %v", input, err)
		}
		reparsed, err := traceql.Parse(scoped.String())
		if err != nil {
			t.Fatalf("scoped %q does not lex: %v", scoped, err)
		}
		original, filters := q.Filters(), reparsed.Filters()
		if len(filters) != len(original) {
			t.Fatalf("scoped %q has %d filters, input %q has %d", scoped, len(filters), input, len(original))
		}
		for i, filter := range filters {
			want := " (" + original[i] + ") && " + condition + " "
			if strings.TrimSpace(original[i]) == "" {
				want = " " + condition + " "
			}
			if filter != want {
				t.Errorf("filter %d of %q is %q, want %q", i, scoped, filter, want)
			}
		}
		if oracle != nil {
			oracle.checkMatchesOnlyTheService(t, input, scoped.String())
		}
	})
}
