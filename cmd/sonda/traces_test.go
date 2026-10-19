package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

type recordedRequest struct {
	method string
	path   string
	query  string
	body   []byte
}

// runCommand runs one command against a fake Sonda server and returns the request it sent.
func runCommand(t *testing.T, build func(*app) *cobra.Command, args ...string) recordedRequest {
	t.Helper()
	var got recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = recordedRequest{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery, body: body}
		_, _ = w.Write([]byte(`{"data":{},"meta":{}}`))
	}))
	defer server.Close()
	t.Setenv("SONDA_TOKEN", "test-token")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cmd := build(&app{url: server.URL, format: "json"})
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestTracesSearchRequest(t *testing.T) {
	got := runCommand(t, (*app).tracesSearchCmd, "engine-api", "-e", "production",
		"--errors", "--min-duration", "500ms", "--max-duration", "2s", "--name", "graphql",
		"--where", "span.http.route=/graphql", "--where", "span.http.method!=GET", "--limit", "5")

	if got.method != http.MethodPost || got.path != "/v1/services/engine-api/traces/search" {
		t.Fatalf("request = %s %s", got.method, got.path)
	}
	var req api.TraceSearchRequest
	if err := json.Unmarshal(got.body, &req); err != nil {
		t.Fatal(err)
	}
	want := api.TraceSearchRequest{
		Window:      api.Window{Environment: "production"},
		MinDuration: "500ms",
		MaxDuration: "2s",
		Errors:      true,
		Name:        "graphql",
		Where:       []string{"span.http.route=/graphql", "span.http.method!=GET"},
		Limit:       5,
	}
	if !reflect.DeepEqual(req, want) {
		t.Errorf("body = %+v, want %+v", req, want)
	}
}

func TestTraceEscapesPath(t *testing.T) {
	got := runCommand(t, (*app).traceCmd, "svc/a", "../x?y", "--since", "6h")

	if got.method != http.MethodGet || got.path != "/v1/services/svc%2Fa/traces/..%2Fx%3Fy" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.query != "since=6h" {
		t.Errorf("query = %q, want since=6h", got.query)
	}
}
