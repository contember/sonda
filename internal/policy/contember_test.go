package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/gqlguard"
)

func TestScopeContemberGraphQLLimitsNormalizedSize(t *testing.T) {
	cfg, err := config.Parse([]byte(`
sources:
  content: { type: contember, url: "http://engine", auth: { type: bearer, token: t } }
services:
  blog:
    environments:
      production:
        data: { source: content, project: blog }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	scope := authz.New(cfg, nil).ContemberScopes()[0]
	data, err := os.ReadFile("../gqlguard/testdata/contember_reader.json")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := gqlguard.LoadIntrospection(data)
	if err != nil {
		t.Fatal(err)
	}
	// One 2 KB variable used in 20 fields: small input, large normalized query.
	var fields strings.Builder
	for i := range 20 {
		fields.WriteString("a")
		fields.WriteString(strings.Repeat("x", i+1))
		fields.WriteString(`: listTag(limit: 1, filter: {name: {eq: $s}}) { id } `)
	}
	query := `query($s: String) { ` + fields.String() + `}`
	vars := []byte(`{"s": "` + strings.Repeat("v", 2000) + `"}`)
	limits := config.DefaultLimits
	_, err = ScopeContemberGraphQL(scope, schema, query, vars, limits)
	if e, ok := apierr.As(err); !ok || e.Code != api.CodeLimitExceeded || !strings.Contains(e.Message, "after variables and fragments are inlined") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ScopeContemberGraphQL(scope, schema, `{ listTag(limit: 1) { id } }`, nil, limits); err != nil {
		t.Fatalf("small query: %v", err)
	}
}
