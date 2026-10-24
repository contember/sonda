package query

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/gqlguard"
	"github.com/contember/sonda/internal/identities"
)

func TestSchemaCacheRefreshFailsClosed(t *testing.T) {
	now := time.Unix(0, 0)
	cache := newSchemaCache(func() time.Time { return now })
	first := &gqlguard.Schema{}
	loads := 0
	load := func(schema *gqlguard.Schema, err error) func() (*gqlguard.Schema, error) {
		return func() (*gqlguard.Schema, error) { loads++; return schema, err }
	}
	if got, err := cache.get("k", load(first, nil)); err != nil || got != first {
		t.Fatalf("first load: %v, %v", got, err)
	}
	now = now.Add(schemaTTL - time.Second)
	if got, _ := cache.get("k", load(nil, errors.New("not called"))); got != first || loads != 1 {
		t.Fatalf("cached schema not reused: loads=%d", loads)
	}
	// After the TTL the load runs again; a failure (e.g. the key gained write access) must not
	// fall back to the old schema, now or on the next request.
	now = now.Add(2 * time.Second)
	writeErr := errors.New("can write")
	if got, err := cache.get("k", load(nil, writeErr)); !errors.Is(err, writeErr) || got != nil {
		t.Fatalf("refresh: %v, %v", got, err)
	}
	if _, err := cache.get("k", load(nil, writeErr)); !errors.Is(err, writeErr) || loads != 3 {
		t.Fatalf("failed load was cached: loads=%d, err=%v", loads, err)
	}
}

// fakeEngine serves the reader fixtures; failSchema makes the schema queries fail with a
// GraphQL error.
func fakeEngine(t *testing.T, failSchema bool) *httptest.Server {
	t.Helper()
	read := func(name string) []byte {
		data, err := os.ReadFile("../gqlguard/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	introspection, relations := read("contember_reader.json"), read("contember_reader_relations.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		switch {
		case failSchema:
			fmt.Fprint(w, `{"errors":[{"message":"introspection is disabled"}]}`)
		case strings.Contains(body, "__schema"):
			_, _ = w.Write(introspection)
		case strings.Contains(body, "_Relation"):
			_, _ = w.Write(relations)
		default:
			fmt.Fprint(w, `{"data":{}}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func fakeDataService(t *testing.T, url string, maxResponseBytes int) (*Service, *authz.Identity) {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
sources:
  content: { type: contember, url: %q, auth: { type: bearer, token: t } }
services:
  blog:
    environments:
      production:
        data: { source: content, project: blog }
`, url)), func(string) (string, bool) { return "", false })
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
	limits := cfg.Limits
	limits.MaxResponseBytes = maxResponseBytes
	identity := &authz.Identity{
		Name:   "agent",
		Grants: []identities.Grant{{Service: "blog", Environment: "production", Capability: api.CapabilityData}},
		Limits: limits,
	}
	return s, identity
}

func TestDataSchemaTooLargeListsEntityNames(t *testing.T) {
	s, identity := fakeDataService(t, fakeEngine(t, false).URL, 400)
	ctx := context.Background()
	resp, err := s.DataSchema(ctx, identity, "blog", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Meta.Truncated || len(resp.Data.Entities) != 3 || resp.Data.Entities[0].Fields != nil {
		t.Fatalf("schema = %+v, meta = %+v", resp.Data, resp.Meta)
	}
	one, err := s.DataSchema(ctx, identity, "blog", "", []string{"Article"})
	if err != nil {
		t.Fatal(err)
	}
	if one.Meta.Truncated || len(one.Data.Entities) != 1 || len(one.Data.Entities[0].Fields) == 0 || one.Data.Enums["ArticleStatus"] == nil {
		t.Fatalf("one entity = %+v", one.Data)
	}
	if _, err := s.DataSchema(ctx, identity, "blog", "", []string{"Nope"}); !isCode(err, api.CodeNotFound) {
		t.Fatalf("unknown entity: %v", err)
	}
}

func TestDataSchemaQueryErrorsAreUpstreamErrors(t *testing.T) {
	s, identity := fakeDataService(t, fakeEngine(t, true).URL, 65536)
	_, err := s.DataSchema(context.Background(), identity, "blog", "", nil)
	if !isCode(err, api.CodeUpstreamError) || !strings.Contains(err.Error(), "introspection is disabled") {
		t.Fatalf("err = %v", err)
	}
}

func isCode(err error, code api.ErrorCode) bool {
	e, ok := apierr.As(err)
	return ok && e.Code == code
}
