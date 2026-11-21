package query

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

// fakeCluster serves an empty list for every list and a ConfigMap for every ConfigMap read,
// unless a path has its own answer.
// A path mapped to a number answers with that status.
type fakeCluster struct {
	mu      sync.Mutex
	answers map[string]any
	paths   []string
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	answer, ok := f.answers[r.URL.Path]
	f.mu.Unlock()
	switch a := answer.(type) {
	case int:
		w.WriteHeader(a)
		_, _ = io.WriteString(w, `{"kind":"Status","message":"fake"}`)
	case string:
		_, _ = io.WriteString(w, a)
	default:
		if ok {
			panic(fmt.Sprintf("bad answer %T", answer))
		}
		if name, found := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/engine/configmaps/"); found {
			_, _ = fmt.Fprintf(w, `{"metadata":{"name":%q,"namespace":"engine"},"data":{"KEY":"value"}}`, name)
			return
		}
		_, _ = io.WriteString(w, `{"items":[],"metadata":{}}`)
	}
}

func fakeObjectsService(t *testing.T, answers map[string]any) (*Service, *authz.Identity, *fakeCluster) {
	t.Helper()
	cluster := &fakeCluster{answers: answers}
	server := httptest.NewServer(cluster)
	t.Cleanup(server.Close)
	cfg, err := config.Parse([]byte(`
sources:
  k8s:
    type: kubernetes
    url: "`+server.URL+`"
    auth: { type: bearer, token: t }
    argocd_namespace: argocd
projects:
  engine:
    services:
      engine:
        environments:
          production:
            workloads: { source: k8s, namespace: engine, labels: { app: engine-api } }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	connectors, err := NewConnectors(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, authz.New(cfg, nil), connectors, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Limits: cfg.Limits, Grants: []identities.Grant{
		{Project: "engine", Environment: "production", Capability: api.CapabilityWorkloads},
	}}
	return s, identity, cluster
}

const fakeDeployment = `{"items":[{"metadata":{"name":"engine-api","namespace":"engine"},
	"spec":{"replicas":1,"selector":{"matchLabels":{"app":"engine-api"}},"template":{"metadata":{"labels":{"app":"engine-api"}},
	"spec":{"containers":[{"name":"api","image":"engine:1","envFrom":[{"configMapRef":{"name":"engine-config"}}]}]}}},"status":{}}],"metadata":{}}`

func TestObjectsReadsConfigMapsAndReportsMissing(t *testing.T) {
	s, identity, _ := fakeObjectsService(t, map[string]any{
		"/apis/apps/v1/namespaces/engine/deployments":        fakeDeployment,
		"/api/v1/namespaces/engine/configmaps/engine-config": http.StatusNotFound,
	})
	resp, err := s.Objects(context.Background(), identity, "engine", "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Controllers) != 1 || len(resp.Data.ConfigMaps) != 1 || !resp.Data.ConfigMaps[0].Missing {
		t.Errorf("data = %+v", resp.Data)
	}
}

func TestObjectsFailsWhenOneListFails(t *testing.T) {
	s, identity, _ := fakeObjectsService(t, map[string]any{
		"/apis/apps/v1/namespaces/engine/deployments":            fakeDeployment,
		"/apis/networking.k8s.io/v1/namespaces/engine/ingresses": http.StatusForbidden,
	})
	_, err := s.Objects(context.Background(), identity, "engine", "production")
	if !isCode(err, api.CodeUpstreamError) {
		t.Errorf("err = %v, want upstream_error", err)
	}
}

func TestObjectsCapsConfigMaps(t *testing.T) {
	var refs []string
	for i := range maxConfigMaps + 2 {
		refs = append(refs, fmt.Sprintf(`{"configMapRef":{"name":"cm-%02d"}}`, i))
	}
	deployment := strings.Replace(fakeDeployment, `[{"configMapRef":{"name":"engine-config"}}]`, "["+strings.Join(refs, ",")+"]", 1)
	s, identity, cluster := fakeObjectsService(t, map[string]any{
		"/apis/apps/v1/namespaces/engine/deployments": deployment,
	})
	resp, err := s.Objects(context.Background(), identity, "engine", "production")
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	for _, p := range cluster.paths {
		if strings.Contains(p, "/configmaps/") {
			reads++
		}
	}
	if len(resp.Data.ConfigMaps) != maxConfigMaps || reads != maxConfigMaps || !resp.Meta.Truncated {
		t.Errorf("configMaps = %d, reads = %d, truncated = %v", len(resp.Data.ConfigMaps), reads, resp.Meta.Truncated)
	}
}

func TestObjectsRejectsAConfigMapOfAnotherNamespace(t *testing.T) {
	s, identity, _ := fakeObjectsService(t, map[string]any{
		"/apis/apps/v1/namespaces/engine/deployments":        fakeDeployment,
		"/api/v1/namespaces/engine/configmaps/engine-config": `{"metadata":{"name":"engine-config","namespace":"other"},"data":{"KEY":"secret"}}`,
	})
	_, err := s.Objects(context.Background(), identity, "engine", "production")
	if !isCode(err, api.CodeInternal) {
		t.Errorf("err = %v, want internal", err)
	}
}

func TestObjectsRejectsAnApplicationOfAnotherNamespace(t *testing.T) {
	s, identity, _ := fakeObjectsService(t, map[string]any{
		"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications": `{"items":[{"metadata":{"name":"engine","namespace":"default"}}],"metadata":{}}`,
	})
	_, err := s.Objects(context.Background(), identity, "engine", "production")
	if !isCode(err, api.CodeInternal) {
		t.Errorf("err = %v, want internal", err)
	}
}

func TestWorkloadsWithoutMetricsAPI(t *testing.T) {
	s, identity, _ := fakeObjectsService(t, map[string]any{
		"/api/v1/namespaces/engine/pods": `{"items":[{"metadata":{"name":"engine-api-1","namespace":"engine","labels":{"app":"engine-api"}},
			"spec":{"containers":[{"name":"api","image":"engine:1"}]},"status":{"phase":"Running","containerStatuses":[{"name":"api","image":"engine:1","ready":true,"state":{"running":{}}}]}}],"metadata":{}}`,
		"/apis/metrics.k8s.io/v1beta1/namespaces/engine/pods": http.StatusForbidden,
	})
	resp, err := s.Workloads(context.Background(), identity, "engine", api.Window{Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Pods) != 1 || len(resp.Data.Pods[0].Containers) != 1 || resp.Data.Pods[0].Containers[0].Usage != nil {
		t.Errorf("pods = %+v", resp.Data.Pods)
	}
}
