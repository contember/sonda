package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

func TestLabelSelectorMatches(t *testing.T) {
	labels := map[string]string{"app": "engine-api", "tier": "web"}
	tests := []struct {
		selector string
		want     bool
	}{
		{`{}`, true},
		{`{"matchLabels":{"app":"engine-api"}}`, true},
		{`{"matchLabels":{"app":"worker"}}`, false},
		{`{"matchExpressions":[{"key":"tier","operator":"In","values":["web","api"]}]}`, true},
		{`{"matchExpressions":[{"key":"tier","operator":"NotIn","values":["web"]}]}`, false},
		{`{"matchExpressions":[{"key":"canary","operator":"DoesNotExist"}]}`, true},
		{`{"matchExpressions":[{"key":"canary","operator":"Exists"}]}`, false},
		{`{"matchExpressions":[{"key":"tier","operator":"Gt","values":["1"]}]}`, false},
	}
	for _, tt := range tests {
		var s LabelSelector
		if err := json.Unmarshal([]byte(tt.selector), &s); err != nil {
			t.Fatal(err)
		}
		if got := s.Matches(labels); got != tt.want {
			t.Errorf("%s matches = %v, want %v", tt.selector, got, tt.want)
		}
	}
	var none *LabelSelector
	if none.Matches(labels) {
		t.Error("a nil selector matches")
	}
}

func TestQuantities(t *testing.T) {
	for q, want := range map[string]int64{"250m": 250, "2": 2000, "123456789n": 123, "1500u": 1, "0.5": 500} {
		if got, ok := ParseCPU(q); !ok || got != want {
			t.Errorf("ParseCPU(%q) = %d, %v; want %d", q, got, ok, want)
		}
	}
	for q, want := range map[string]int64{"512Mi": 512 << 20, "1Gi": 1 << 30, "2048Ki": 2 << 20, "1G": 1e9, "1000": 1000} {
		if got, ok := ParseMemory(q); !ok || got != want {
			t.Errorf("ParseMemory(%q) = %d, %v; want %d", q, got, ok, want)
		}
	}
	if _, ok := ParseCPU("lots"); ok {
		t.Error("ParseCPU accepted lots")
	}
}

// Values of environment variables and ConfigMaps are not decoded into any field.
func TestValuesAreNotDecoded(t *testing.T) {
	var d Deployment
	if err := json.Unmarshal([]byte(`{"spec":{"template":{"spec":{"containers":[{"name":"app","env":[
		{"name":"API_KEY","value":"env-s3cr3t"},
		{"name":"DB_PASSWORD","valueFrom":{"secretKeyRef":{"name":"db","key":"password"}}}
	],"livenessProbe":{"exec":{"command":["check","--token=probe-s3cr3t"]}}}]}}}}`), &d); err != nil {
		t.Fatal(err)
	}
	var cm ConfigMap
	if err := json.Unmarshal([]byte(`{"metadata":{"name":"engine"},"data":{"b":"cm-s3cr3t","a":"x"},"binaryData":{"c":"Ymlu"}}`), &cm); err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v %+v", d, cm)
	if strings.Contains(dump, "s3cr3t") {
		t.Errorf("a value was decoded: %s", dump)
	}
	if fmt.Sprint(cm.Data, cm.BinaryData) != "[a b] [c]" {
		t.Errorf("keys = %v %v", cm.Data, cm.BinaryData)
	}
}

func TestNamespaceListsAreCheckedAndUnfiltered(t *testing.T) {
	f := &fakeAPI{pages: map[string][]string{"/apis/apps/v1/namespaces/engine/deployments": {
		`{"items":[{"metadata":{"name":"engine-api","namespace":"engine"}}]}`,
	}}}
	client, scope := setup(t, f)
	deployments, _, err := client.Deployments(context.Background(), scope)
	if err != nil || len(deployments) != 1 {
		t.Fatalf("deployments = %+v, err = %v", deployments, err)
	}
	if f.requests[0].query.Has("labelSelector") {
		t.Errorf("request has a label selector: %v", f.requests[0].query)
	}

	f = &fakeAPI{pages: map[string][]string{"/api/v1/namespaces/engine/services": {
		`{"items":[{"metadata":{"name":"engine-api","namespace":"other"}}]}`,
	}}}
	client, scope = setup(t, f)
	if _, _, err := client.Services(context.Background(), scope); !isCode(err, api.CodeInternal) {
		t.Errorf("service of another namespace: error = %v", err)
	}
}

func TestConfigMapByName(t *testing.T) {
	f := &fakeAPI{pages: map[string][]string{"/api/v1/namespaces/engine/configmaps/engine-config": {
		`{"metadata":{"name":"engine-config","namespace":"engine"},"data":{"LOG_LEVEL":"debug"}}`,
	}}}
	client, scope := setup(t, f)
	cm, found, err := client.ConfigMap(context.Background(), scope, "engine-config")
	if err != nil || !found || fmt.Sprint(cm.Data) != "[LOG_LEVEL]" {
		t.Errorf("config map = %+v, found %v, err = %v", cm, found, err)
	}
}

func TestApplicationsNeedANamespace(t *testing.T) {
	f := &fakeAPI{pages: map[string][]string{"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications": {
		`{"items":[{"metadata":{"name":"engine","namespace":"argocd"},"spec":{"source":{"helm":{"values":"password: helm-s3cr3t"}}},"status":{"sync":{"status":"Synced"}}}]}`,
	}}}
	client, _ := setup(t, f)
	apps, _, err := client.Applications(context.Background())
	if err != nil || apps != nil || len(f.requests) != 0 {
		t.Fatalf("without a namespace: apps = %+v, %d requests, err = %v", apps, len(f.requests), err)
	}
	client.source.ArgoCDNamespace = "argocd"
	apps, _, err = client.Applications(context.Background())
	if err != nil || len(apps) != 1 || apps[0].Status.Sync.Status != "Synced" {
		t.Fatalf("apps = %+v, err = %v", apps, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", apps), "s3cr3t") {
		t.Errorf("helm values were decoded: %+v", apps)
	}
}

func TestMetricsAreOptional(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusServiceUnavailable} {
		client, scope := setup(t, &fakeAPI{status: status})
		metrics, ok, err := client.PodMetrics(context.Background(), scope)
		if err != nil || ok || metrics != nil {
			t.Errorf("HTTP %d: metrics = %v, ok = %v, err = %v", status, metrics, ok, err)
		}
	}
	client, scope := setup(t, &fakeAPI{status: http.StatusInternalServerError})
	if _, _, err := client.PodMetrics(context.Background(), scope); !isCode(err, api.CodeUpstreamError) {
		t.Errorf("HTTP 500: error = %v", err)
	}

	f := &fakeAPI{pages: map[string][]string{"/apis/metrics.k8s.io/v1beta1/namespaces/engine/pods": {
		`{"items":[{"metadata":{"name":"engine-api-1","namespace":"engine"},"containers":[{"name":"app","usage":{"cpu":"250m","memory":"512Mi"}}]}]}`,
	}}}
	client, scope = setup(t, f)
	metrics, ok, err := client.PodMetrics(context.Background(), scope)
	if err != nil || !ok || len(metrics) != 1 || f.requests[0].query.Get("labelSelector") != "app=engine-api,tier=web" {
		t.Errorf("metrics = %+v, ok = %v, err = %v, requests = %+v", metrics, ok, err, f.requests)
	}
}

func TestNodeEventsAreFilteredByKind(t *testing.T) {
	f := &fakeAPI{pages: map[string][]string{"/api/v1/namespaces/default/events": {
		`{"items":[{"metadata":{"name":"e","namespace":"default"},"involvedObject":{"kind":"Pod","name":"x"}}]}`,
	}}}
	client, _ := setup(t, f)
	if _, _, err := client.NodeEvents(context.Background(), nodeScope(t)); !isCode(err, api.CodeInternal) {
		t.Errorf("event of a pod: error = %v", err)
	}
	if f.requests[0].query.Get("fieldSelector") != "involvedObject.kind=Node" {
		t.Errorf("request = %+v", f.requests[0])
	}
}

func nodeScope(t *testing.T) authz.NodeScope {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  k8s: { type: kubernetes, url: "https://k8s.example.com", auth: { type: bearer, token: secret } }
projects:
  platform:
    services:
      cluster:
        environments:
          production:
            workloads: { source: k8s, nodes: true }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "platform", Environment: "production", Capability: api.CapabilityWorkloads},
	}}
	workloads, err := authz.New(cfg, nil).WorkloadScope(identity, "cluster", "production")
	if err != nil {
		t.Fatal(err)
	}
	scope, ok := workloads.Nodes()
	if !ok {
		t.Fatal("not a nodes scope")
	}
	return scope
}
