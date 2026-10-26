// Package alerting reads active alerts from a Prometheus-compatible alerts API: Prometheus,
// Mimir, Thanos Ruler, or Grafana-managed alerting.
package alerting

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
)

type Client struct {
	source *config.Source
	http   *http.Client
}

func New(src *config.Source, client *http.Client) *Client {
	return &Client{source: src, http: client}
}

// Alert is one alert instance. Prometheus reports state firing or pending; Grafana reports
// Alerting, Pending, Recovering, NoData, Error or Normal, optionally followed by " (Reason)".
type Alert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	State       string            `json:"state"`
	ActiveAt    *time.Time        `json:"activeAt"`
	Value       string            `json:"value"`
}

type response struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		Alerts []Alert `json:"alerts"`
	} `json:"data"`
}

// Alerts returns every alert of the ruler. The API has no label filter, so the caller scopes
// the result.
func (c *Client) Alerts(ctx context.Context) ([]Alert, error) {
	path := "/api/v1/alerts"
	if c.source.Type == config.SourceGrafana {
		path = "/api/prometheus/grafana/api/v1/alerts"
	}
	var resp response
	if err := upstream.GetJSON(ctx, c.http, c.source.Name, strings.TrimRight(c.source.URL, "/")+path, &resp); err != nil {
		return nil, upstream.Wrap(c.source.Name, err)
	}
	if resp.Status != "success" {
		return nil, apierr.Upstream("source %s returned status %q: %s", c.source.Name, resp.Status, resp.Error)
	}
	return resp.Data.Alerts, nil
}
