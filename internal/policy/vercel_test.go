package policy

import (
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

func vercelScope(t *testing.T) authz.VercelScope {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  vercel: { type: vercel, team_id: team_1, auth: { type: bearer, token: t } }
projects:
  web:
    services:
      web:
        environments:
          production:
            logs: { source: vercel, project: prj_1, environment: production }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "web", Environment: "production", Capability: api.CapabilityLogs},
	}}
	logScope, err := authz.New(cfg, nil).LogScope(identity, "web", "production")
	if err != nil {
		t.Fatal(err)
	}
	scope, ok := logScope.Vercel()
	if !ok {
		t.Fatal("not a vercel scope")
	}
	return scope
}

func TestScopeVercelQuery(t *testing.T) {
	scope := vercelScope(t)
	tests := []struct{ in, want string }{
		{"", `environment:"production"`},
		{"  level:error  ", `environment:"production" AND (level:error)`},
		{"level:error OR environment:preview", `environment:"production" AND (level:error OR environment:preview)`},
		{`requestPath:"/a)" AND (x OR y)`, `environment:"production" AND (requestPath:"/a)" AND (x OR y))`},
		{`undefined\ \(reading`, `environment:"production" AND (undefined\ \(reading)`},
		{`requestPath:"a\"(b"`, `environment:"production" AND (requestPath:"a\"(b")`},
		{`message:'(' AND x:')'`, `environment:"production" AND (message:'(' AND x:')')`},
	}
	for _, tt := range tests {
		q, err := ScopeVercelQuery(scope, tt.in)
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		if q.String() != tt.want {
			t.Errorf("%q:\n got %s\nwant %s", tt.in, q, tt.want)
		}
	}
}

// Each rejected query would close the group around the agent filter, or leave Vercel to parse
// it differently than Sonda.
func TestScopeVercelQueryRejectsEscapes(t *testing.T) {
	scope := vercelScope(t)
	for _, in := range []string{
		`level:error) OR (environment:preview`,
		`x) OR environment:preview OR (y`,
		`(level:error`,
		`requestPath:"/a`,
		`level:error\`,
		`\) OR (level:*`,
	} {
		if _, err := ScopeVercelQuery(scope, in); err == nil {
			t.Errorf("%q: accepted", in)
		}
	}
}

func TestVercelLogSearch(t *testing.T) {
	scope := vercelScope(t)
	tests := []struct {
		name string
		f    LogFilter
		want string
	}{
		{"empty", LogFilter{}, `environment:"production"`},
		{"word", LogFilter{Contains: []string{"TypeError"}}, `environment:"production" AND TypeError`},
		{"phrase", LogFilter{Contains: []string{"undefined (reading 'url')"}}, `environment:"production" AND undefined\ \(reading\ \'url\'\)`},
		{"keyword", LogFilter{Contains: []string{"OR"}}, `environment:"production" AND \OR`},
		{"exclamation", LogFilter{Contains: []string{"failed!"}}, `environment:"production" AND failed\!`},
		{"unicode", LogFilter{Contains: []string{"chyba při"}}, `environment:"production" AND chyba\ při`},
		{
			"where",
			LogFilter{Contains: []string{"a", "b"}, Where: []Where{{Field: "level", Value: "error"}, {Field: "requestPath", Value: `/x"y\`, Negate: true}}},
			`environment:"production" AND a AND b AND level:"error" AND NOT requestPath:"/x\"y\\"`,
		},
	}
	for _, tt := range tests {
		q, err := VercelLogSearch(scope, tt.f)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if q.String() != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, q, tt.want)
		}
	}
	for _, f := range []LogFilter{{Pipeline: "| json"}, {Contains: []string{"  "}}} {
		if _, err := VercelLogSearch(scope, f); err == nil {
			t.Errorf("%+v: accepted", f)
		}
	}
}
