package query

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

// These tests run against the dev Contember engine (dev/docker-compose.yml, seeded by
// dev/seed-contember.sh) when SONDA_TEST_CONTEMBER_URL is set.
func contemberEnv(t *testing.T) (url, project, reader, writer string) {
	t.Helper()
	url = os.Getenv("SONDA_TEST_CONTEMBER_URL")
	if url == "" {
		t.Skip("SONDA_TEST_CONTEMBER_URL is not set")
	}
	return url, os.Getenv("SONDA_TEST_CONTEMBER_PROJECT"), os.Getenv("SONDA_TEST_CONTEMBER_READER_TOKEN"), os.Getenv("SONDA_TEST_CONTEMBER_WRITER_TOKEN")
}

func contemberService(t *testing.T, url, project, token, denyFields string) (*Service, *authz.Identity) {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
sources:
  content: { type: contember, url: %q, auth: { type: bearer, token: %q } }
services:
  blog:
    environments:
      production:
        data: { source: content, project: %q, deny_fields: %s }
`, url, token, project, denyFields)), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	connectors, err := NewConnectors(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, authz.New(cfg, nil), connectors, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{
		Name:   "agent",
		Grants: []identities.Grant{{Service: "blog", Environment: "production", Capability: api.CapabilityData}},
		Limits: cfg.Limits,
	}
	return s, identity
}

func TestContemberReader(t *testing.T) {
	url, project, reader, _ := contemberEnv(t)
	s, identity := contemberService(t, url, project, reader, `["*.email", Article.secretNote]`)
	ctx := context.Background()

	schema, err := s.DataSchema(ctx, identity, "blog", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(schema.Data.Entities) != 3 {
		t.Fatalf("entities = %+v", schema.Data.Entities)
	}
	for _, e := range schema.Data.Entities {
		for _, f := range e.Fields {
			if f.Name == "email" || f.Name == "secretNote" {
				t.Errorf("%s.%s is visible", e.Name, f.Name)
			}
		}
	}

	// The role's predicate hides unpublished articles: Contember is the primary boundary.
	resp, err := s.QueryData(ctx, identity, "blog", api.DataQueryRequest{
		Query:     `query($n: Int!) { listArticle(limit: $n, orderBy: [{title: asc}]) { title published author { name } } paginateArticle(first: 1) { pageInfo { totalCount } } }`,
		Variables: []byte(`{"n": 50}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	data := string(resp.Data.Data)
	if strings.Contains(data, `"published":false`) || !strings.Contains(data, `"totalCount":5`) {
		t.Errorf("data = %s", data)
	}
	if resp.Data.Query != `query { listArticle(limit: 50, orderBy: [{title: asc}]) { title published author { name } } paginateArticle(first: 1) { pageInfo { totalCount } } }` {
		t.Errorf("query = %s", resp.Data.Query)
	}

	for _, q := range []string{
		`{ listAuthor(limit: 1) { email } }`,
		`{ listAuthor(limit: 1, filter: {email: {contains: "@"}}) { name } }`,
		`{ listArticle(limit: 1) { id } }  mutation { createArticle(data: {}) { ok } }`,
		`{ listArticle { id } }`,
	} {
		_, err := s.QueryData(ctx, identity, "blog", api.DataQueryRequest{Query: q})
		if e, ok := apierr.As(err); !ok || e.Code != api.CodeInvalidQuery {
			t.Errorf("%s: err = %v", q, err)
		}
	}

	checks := s.CheckData(ctx)
	if len(checks) != 1 || len(checks[0].Errors) != 0 || checks[0].WriteAccess {
		t.Errorf("check = %+v", checks)
	}
}

func TestContemberCheckFindings(t *testing.T) {
	url, project, reader, _ := contemberEnv(t)
	s, _ := contemberService(t, url, project, reader, `[Author.mail]`)
	checks := s.CheckData(context.Background())
	if len(checks) != 1 {
		t.Fatalf("checks = %+v", checks)
	}
	got := strings.Join(checks[0].Errors, "\n") + "\n" + strings.Join(checks[0].Warnings, "\n")
	if !strings.Contains(got, "deny_fields: Author.mail does not exist") || !strings.Contains(got, "Author.email is readable") {
		t.Errorf("findings = %s", got)
	}
}

func TestContemberRefusesWriter(t *testing.T) {
	url, project, _, writer := contemberEnv(t)
	s, identity := contemberService(t, url, project, writer, `[]`)
	_, err := s.QueryData(context.Background(), identity, "blog", api.DataQueryRequest{Query: `{ listArticle(limit: 1) { id } }`})
	if e, ok := apierr.As(err); !ok || e.Code != api.CodeUpstreamError || !strings.Contains(e.Message, "can write") {
		t.Fatalf("err = %v", err)
	}
	checks := s.CheckData(context.Background())
	if len(checks) != 1 || !checks[0].WriteAccess {
		t.Errorf("checks = %+v", checks)
	}
}
