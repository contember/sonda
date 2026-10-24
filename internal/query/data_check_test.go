package query

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
)

// A hanging engine must not hide a write key on another binding.
func TestCheckDataBindingsHaveOwnTimeouts(t *testing.T) {
	writer, err := os.ReadFile("../gqlguard/testdata/contember_writer.json")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hanging.Close()
	defer close(release)
	writable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(writer)
	}))
	defer writable.Close()

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
sources:
  a-hanging: { type: contember, url: %q, auth: { type: bearer, token: a } }
  b-writable: { type: contember, url: %q, auth: { type: bearer, token: b } }
services:
  a:
    environments:
      production:
        data: { source: a-hanging, project: a }
  b:
    environments:
      production:
        data: { source: b-writable, project: b }
`, hanging.URL, writable.URL)), func(string) (string, bool) { return "", false })
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	checks := s.CheckData(ctx)
	if len(checks) != 2 || checks[0].Service != "a" || checks[1].Service != "b" {
		t.Fatalf("checks = %+v", checks)
	}
	if !checks[1].WriteAccess || !strings.Contains(strings.Join(checks[1].Errors, " "), "can write") {
		t.Errorf("write key not detected: %+v", checks[1])
	}
	if checks[0].WriteAccess || len(checks[0].Errors) == 0 {
		t.Errorf("hanging engine: %+v", checks[0])
	}
	if time.Since(start) > 3500*time.Millisecond {
		t.Errorf("check took %s", time.Since(start))
	}
}
