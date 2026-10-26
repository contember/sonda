package alerting

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
)

func TestAlertsPathBySourceType(t *testing.T) {
	tests := []struct {
		typ  config.SourceType
		path string
	}{
		{config.SourcePrometheus, "/prom/api/v1/alerts"},
		{config.SourceGrafana, "/prom/api/prometheus/grafana/api/v1/alerts"},
	}
	for _, tt := range tests {
		t.Run(string(tt.typ), func(t *testing.T) {
			var path, auth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path, auth = r.URL.Path, r.Header.Get("Authorization")
				_, _ = io.WriteString(w, `{"status":"success","data":{"alerts":[{"labels":{"alertname":"Down"},"state":"firing","activeAt":"2026-10-26T10:00:00Z","value":"1e+00"}]}}`)
			}))
			defer server.Close()
			src := &config.Source{Name: "rules", Type: tt.typ, URL: server.URL + "/prom/", Auth: config.Auth{Type: config.AuthBearer, Token: "secret"}}
			alerts, err := New(src, upstream.HTTPClient(src, nil)).Alerts(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if path != tt.path || auth != "Bearer secret" {
				t.Errorf("request path %q, auth %q", path, auth)
			}
			if len(alerts) != 1 || alerts[0].Labels["alertname"] != "Down" || alerts[0].ActiveAt == nil {
				t.Errorf("alerts = %+v", alerts)
			}
		})
	}
}

func TestAlertsErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"HTTP status", http.StatusForbidden, `{"message":"permission denied"}`, "HTTP 403"},
		{"error status", http.StatusOK, `{"status":"error","error":"ruler unavailable"}`, "ruler unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			src := &config.Source{Name: "rules", Type: config.SourceGrafana, URL: server.URL}
			_, err := New(src, upstream.HTTPClient(src, nil)).Alerts(context.Background())
			e, ok := apierr.As(err)
			if !ok || e.Code != api.CodeUpstreamError || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v", err)
			}
		})
	}
}
