package query

import (
	"fmt"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/alerting"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/connector/kubernetes"
	"github.com/contember/sonda/internal/connector/loki"
	"github.com/contember/sonda/internal/connector/prometheus"
	"github.com/contember/sonda/internal/connector/sentry"
	"github.com/contember/sonda/internal/connector/tempo"
)

// Connectors holds one client per configured source, keyed by source name.
type Connectors struct {
	Prometheus map[string]*prometheus.Client
	Loki       map[string]*loki.Client
	Sentry     map[string]*sentry.Client
	Cloudflare map[string]*cloudflare.Client
	AWS        map[string]*aws.Client
	Tempo      map[string]*tempo.Client
	Kubernetes map[string]*kubernetes.Client
	// Alerting holds a client for every Prometheus and Grafana source.
	Alerting map[string]*alerting.Client
}

func NewConnectors(cfg *config.Config) (Connectors, error) {
	c := Connectors{
		Prometheus: map[string]*prometheus.Client{},
		Loki:       map[string]*loki.Client{},
		Sentry:     map[string]*sentry.Client{},
		Cloudflare: map[string]*cloudflare.Client{},
		AWS:        map[string]*aws.Client{},
		Tempo:      map[string]*tempo.Client{},
		Kubernetes: map[string]*kubernetes.Client{},
		Alerting:   map[string]*alerting.Client{},
	}
	for name, src := range cfg.Sources {
		switch src.Type {
		case config.SourcePrometheus:
			client, err := prometheus.New(src)
			if err != nil {
				return Connectors{}, err
			}
			c.Prometheus[name] = client
			c.Alerting[name] = alerting.New(src)
		case config.SourceLoki:
			c.Loki[name] = loki.New(src)
		case config.SourceSentry:
			c.Sentry[name] = sentry.New(src)
		case config.SourceCloudflare:
			client, err := cloudflare.New(src)
			if err != nil {
				return Connectors{}, err
			}
			c.Cloudflare[name] = client
		case config.SourceAWS:
			client, err := aws.New(src)
			if err != nil {
				return Connectors{}, err
			}
			c.AWS[name] = client
		case config.SourceTempo:
			client, err := tempo.New(src)
			if err != nil {
				return Connectors{}, err
			}
			c.Tempo[name] = client
		case config.SourceKubernetes:
			c.Kubernetes[name] = kubernetes.New(src)
		case config.SourceGrafana:
			c.Alerting[name] = alerting.New(src)
		default:
			return Connectors{}, fmt.Errorf("source %s: unsupported type %s", name, src.Type)
		}
	}
	return c, nil
}
