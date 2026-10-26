package kubernetes

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/identities"
)

type request struct {
	path  string
	query url.Values
	auth  string
}

// fakeAPI serves the pages of each path in order and records the requests.
type fakeAPI struct {
	pages    map[string][]string
	status   int
	requests []request
}

func (f *fakeAPI) handler(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, request{path: r.URL.Path, query: r.URL.Query(), auth: r.Header.Get("Authorization")})
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, `{"kind":"Status","message":"forbidden: cannot list pods"}`)
		return
	}
	pages := f.pages[r.URL.Path]
	if len(pages) == 0 {
		_, _ = io.WriteString(w, `{"items":[]}`)
		return
	}
	_, _ = io.WriteString(w, pages[0])
	f.pages[r.URL.Path] = pages[1:]
}

// setup serves f over TLS and returns a client that trusts only the server's certificate.
func setup(t *testing.T, f *fakeAPI) (*Client, authz.WorkloadScope) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`
sources:
  k8s: { type: kubernetes, url: "`+server.URL+`", auth: { type: bearer, token: secret }, ca_file: "`+ca+`" }
projects:
  engine:
    services:
      engine:
        environments:
          production:
            workloads: { source: k8s, namespace: engine, labels: { app: engine-api, tier: web } }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "engine", Environment: "production", Capability: api.CapabilityWorkloads},
	}}
	scope, err := authz.New(cfg, nil).WorkloadScope(identity, "engine", "production")
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg.Sources["k8s"], upstream.HTTPClient(cfg.Sources["k8s"], nil)), scope
}

const scopedMeta = `"namespace":"engine","labels":{"app":"engine-api","tier":"web","pod-template-hash":"7d9f"}`

func TestPodsFollowContinueTokens(t *testing.T) {
	f := &fakeAPI{pages: map[string][]string{"/api/v1/namespaces/engine/pods": {
		`{"items":[{"metadata":{"name":"a",` + scopedMeta + `}}],"metadata":{"continue":"next-1"}}`,
		`{"items":[{"metadata":{"name":"b",` + scopedMeta + `},"status":{"phase":"Running","containerStatuses":[{"name":"app","restartCount":3,"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137,"finishedAt":"2026-10-26T10:00:00Z"}}}]}}]}`,
	}}}
	client, scope := setup(t, f)
	pods, truncated, err := client.Pods(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(pods) != 2 || pods[1].Status.ContainerStatuses[0].LastState.Terminated.Reason != "OOMKilled" {
		t.Errorf("pods = %+v, truncated %t", pods, truncated)
	}
	if len(f.requests) != 2 {
		t.Fatalf("requests = %+v", f.requests)
	}
	first, second := f.requests[0], f.requests[1]
	if first.auth != "Bearer secret" || first.query.Get("labelSelector") != "app=engine-api,tier=web" || first.query.Get("continue") != "" {
		t.Errorf("first request = %+v", first)
	}
	if second.query.Get("continue") != "next-1" || second.query.Get("labelSelector") != "app=engine-api,tier=web" {
		t.Errorf("second request = %+v", second)
	}
}

func TestListTruncates(t *testing.T) {
	items := make([]string, pageSize)
	for i := range items {
		items[i] = `{"metadata":{"name":"rs",` + scopedMeta + `}}`
	}
	page := `{"items":[` + strings.Join(items, ",") + `],"metadata":{"continue":"more"}}`
	f := &fakeAPI{pages: map[string][]string{"/apis/apps/v1/namespaces/engine/replicasets": {page, page}}}
	client, scope := setup(t, f)
	sets, truncated, err := client.ReplicaSets(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(sets) != maxReplicaSets || len(f.requests) != 1 {
		t.Errorf("%d sets, truncated %t, %d requests", len(sets), truncated, len(f.requests))
	}
}

func TestPostCheck(t *testing.T) {
	tests := []struct {
		name string
		path string
		item string
		list func(*Client, authz.WorkloadScope) error
	}{
		{"pod without a scope label", "/api/v1/namespaces/engine/pods", `{"metadata":{"name":"x","namespace":"engine","labels":{"app":"engine-api"}}}`,
			func(c *Client, s authz.WorkloadScope) error { _, _, err := c.Pods(context.Background(), s); return err }},
		{"pod of another namespace", "/api/v1/namespaces/engine/pods", `{"metadata":{"name":"x","namespace":"other","labels":{"app":"engine-api","tier":"web"}}}`,
			func(c *Client, s authz.WorkloadScope) error { _, _, err := c.Pods(context.Background(), s); return err }},
		{"replica set with another value", "/apis/apps/v1/namespaces/engine/replicasets", `{"metadata":{"name":"x","namespace":"engine","labels":{"app":"engine-api","tier":"worker"}}}`,
			func(c *Client, s authz.WorkloadScope) error {
				_, _, err := c.ReplicaSets(context.Background(), s)
				return err
			}},
		{"event of another namespace", "/api/v1/namespaces/engine/events", `{"metadata":{"name":"e","namespace":"other"}}`,
			func(c *Client, s authz.WorkloadScope) error {
				_, _, err := c.Events(context.Background(), s)
				return err
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeAPI{pages: map[string][]string{tt.path: {`{"items":[` + tt.item + `]}`}}}
			client, scope := setup(t, f)
			if err := tt.list(client, scope); !isCode(err, api.CodeInternal) {
				t.Errorf("error = %v", err)
			}
		})
	}
}

func TestEventsAreNotFilteredUpstream(t *testing.T) {
	f := &fakeAPI{pages: map[string][]string{"/api/v1/namespaces/engine/events": {
		`{"items":[{"metadata":{"name":"e","namespace":"engine"},"involvedObject":{"kind":"Pod","name":"a"},"reason":"BackOff","count":4,"lastTimestamp":"2026-10-26T10:00:00Z"}]}`,
	}}}
	client, scope := setup(t, f)
	events, _, err := client.Events(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Occurrences() != 4 || events[0].LastSeen().IsZero() {
		t.Errorf("events = %+v", events)
	}
	if f.requests[0].query.Has("labelSelector") {
		t.Errorf("events request has a label selector: %v", f.requests[0].query)
	}
}

func TestUpstreamError(t *testing.T) {
	client, scope := setup(t, &fakeAPI{status: http.StatusForbidden})
	_, _, err := client.Pods(context.Background(), scope)
	if !isCode(err, api.CodeUpstreamError) || !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %v", err)
	}
}

func TestTokenFileIsReadPerRequest(t *testing.T) {
	f := &fakeAPI{}
	server := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(server.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	src := &config.Source{Name: "k8s", Type: config.SourceKubernetes, URL: server.URL, Auth: config.Auth{Type: config.AuthBearer, TokenFile: tokenFile}}
	client := New(src, upstream.HTTPClient(src, nil))
	_, scope := setup(t, &fakeAPI{})
	for _, token := range []string{"first", "rotated"} {
		if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := client.Pods(context.Background(), scope); err != nil {
			t.Fatal(err)
		}
	}
	if f.requests[0].auth != "Bearer first" || f.requests[1].auth != "Bearer rotated" {
		t.Errorf("requests = %+v", f.requests)
	}
}

func isCode(err error, code api.ErrorCode) bool {
	e, ok := apierr.As(err)
	return ok && e.Code == code
}
