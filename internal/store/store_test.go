package store

// The Postgres variants run when SONDA_TEST_POSTGRES_URL points to a Postgres, e.g. the one
// in dev/docker-compose.yml:
//
//	SONDA_TEST_POSTGRES_URL=postgres://sonda:sonda@localhost:15432/sonda go test ./internal/store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
)

func forEachDatabase(t *testing.T, test func(t *testing.T, st *Store)) {
	t.Run("sqlite", func(t *testing.T) {
		test(t, openTestStore(t, filepath.Join(t.TempDir(), "sonda.db")))
	})
	t.Run("postgres", func(t *testing.T) {
		test(t, openPostgresTestStore(t))
	})
}

func openTestStore(t *testing.T, database string) *Store {
	t.Helper()
	st, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// openPostgresTestStore opens a store in a new schema, so tests do not see each other's rows.
func openPostgresTestStore(t *testing.T) *Store {
	t.Helper()
	base := os.Getenv("SONDA_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("SONDA_TEST_POSTGRES_URL is not set")
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	schema := "sonda_test_" + strings.ToLower(rand.Text())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	return openTestStore(t, u.String())
}

func TestResults(t *testing.T) {
	forEachDatabase(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		now := time.Unix(1_700_000_000, 0)
		st.now = func() time.Time { return now }

		id, err := st.SaveResult(ctx, "agent", "logs", []byte("payload"), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		kind, payload, err := st.LoadResult(ctx, "agent", id)
		if err != nil {
			t.Fatal(err)
		}
		if kind != "logs" || string(payload) != "payload" {
			t.Errorf("loaded %q %q", kind, payload)
		}

		if _, _, err := st.LoadResult(ctx, "other", id); !isNotFound(err) {
			t.Errorf("other identity: %v", err)
		}
		now = now.Add(2 * time.Minute)
		if _, _, err := st.LoadResult(ctx, "agent", id); !isNotFound(err) {
			t.Errorf("expired: %v", err)
		}
	})
}

func isNotFound(err error) bool {
	e, ok := apierr.As(err)
	return ok && e.Code == api.CodeNotFound
}

func TestAudit(t *testing.T) {
	forEachDatabase(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		entries := []AuditEntry{
			{Time: time.UnixMilli(1_700_000_000_001), Identity: "agent", Method: "GET", Path: "/v1/logs",
				Service: "api", Environment: "production", Queries: `{app="api"}`, Status: 200,
				Duration: 120 * time.Millisecond, ResponseBytes: 3_000_000_000},
			{Time: time.UnixMilli(1_700_000_000_002), Identity: "other", Method: "GET", Path: "/v1/errors", Status: 403, ErrorCode: "forbidden"},
			{Time: time.UnixMilli(1_700_000_000_003), Identity: "agent", Method: "GET", Path: "/v1/metrics", Status: 200},
		}
		for _, e := range entries {
			if err := st.WriteAudit(ctx, e); err != nil {
				t.Fatal(err)
			}
		}

		records, err := st.ListAudit(ctx, AuditFilter{Identity: "agent", Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		var got []AuditEntry
		for _, r := range records {
			got = append(got, r.AuditEntry)
		}
		if want := []AuditEntry{entries[2], entries[0]}; !reflect.DeepEqual(got, want) {
			t.Fatalf("records %+v\nwant    %+v", got, want)
		}

		older, err := st.ListAudit(ctx, AuditFilter{BeforeID: records[0].ID, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(older) != 1 || older[0].Identity != "other" {
			t.Errorf("page before %d: %+v", records[0].ID, older)
		}
	})
}
