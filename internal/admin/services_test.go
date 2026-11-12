package admin

import (
	"slices"
	"testing"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/telemetry"
)

func TestBindingsCoverEveryVariant(t *testing.T) {
	src := func(name string, typ config.SourceType) *config.Source {
		return &config.Source{Name: name, Type: typ}
	}
	cf, aws, vercel, sentry := src("cf", config.SourceCloudflare), src("aws", config.SourceAWS), src("vercel", config.SourceVercel), src("sentry", config.SourceSentry)
	env := &config.Environment{
		Errors:    &config.ErrorBinding{Source: sentry, Project: "api", Environment: "production", Query: "server_name:api-*"},
		Logs:      &config.LogBinding{Source: vercel, Project: "prj_1", Environment: "production"},
		Metrics:   &config.MetricBinding{Source: cf, Script: "edge", CloudflareResources: map[telemetry.CloudflareResource]map[string]string{telemetry.CloudflareD1Databases: {"main": "uuid-1"}}},
		Traces:    &config.TraceBinding{Source: sentry, Project: "api", Environment: "production"},
		Workloads: &config.WorkloadBinding{Source: src("k8s", config.SourceKubernetes), Namespace: "api", Labels: map[string]string{"app": "api"}},
		Alerts:    &config.AlertBinding{Source: src("prom", config.SourcePrometheus), Selector: &config.Selector{Text: `{service="api"}`}},
	}
	var got []string
	for _, b := range bindings(env) {
		got = append(got, b.Capability+": "+b.Scope)
	}
	want := []string{
		"errors: project api, environment production, search server_name:api-*",
		"logs: project prj_1, environment production",
		"metrics: script edge, d1_databases main",
		"traces: project api, environment production",
		"workloads: namespace api, app=api",
		`alerts: {service="api"}`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("bindings:\n got %q\nwant %q", got, want)
	}
	logs := bindings(&config.Environment{Logs: &config.LogBinding{Source: aws, LogGroups: []string{"/aws/lambda/api"}}})
	if len(logs) != 1 || logs[0].Scope != "log groups /aws/lambda/api" {
		t.Errorf("aws logs = %+v", logs)
	}
}

func TestSourceAuthAndHost(t *testing.T) {
	awsSrc := &config.Source{Name: "aws", Type: config.SourceAWS, AWS: &config.AWSSource{Region: "eu-west-1", Credentials: config.AWSIdentity, RoleARN: "arn:aws:iam::123456789012:role/sonda"}}
	for _, tc := range []struct {
		src        *config.Source
		auth, host string
	}{
		{awsSrc, "Sonda identity, assume role", "AWS eu-west-1"},
		{&config.Source{AWS: &config.AWSSource{Region: "us-east-1", Credentials: config.AWSDefaultChain}}, "credential chain", "AWS us-east-1"},
		{&config.Source{URL: "https://eks.example/api/v1/namespaces/x/services/y/proxy", Auth: config.Auth{Type: config.AuthEKS, EKS: &config.EKSAuth{Cluster: "prod", AWS: awsSrc}}}, "eks via aws", "https://eks.example"},
		{&config.Source{URL: "https://10.0.0.1:443", Auth: config.Auth{Type: config.AuthBearer, TokenFile: "/var/run/token"}}, "service account", "https://10.0.0.1:443"},
		{&config.Source{URL: "https://user:pw@loki.example/tenant?x=1", Auth: config.Auth{Type: config.AuthBasic}}, "basic", "https://loki.example"},
	} {
		if got := sourceAuth(tc.src); got != tc.auth {
			t.Errorf("auth = %q, want %q", got, tc.auth)
		}
		if got := sourceHost(tc.src); got != tc.host {
			t.Errorf("host = %q, want %q", got, tc.host)
		}
	}
}
