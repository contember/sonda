package query

import (
	"fmt"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/connector/cloudflare"
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
}

func NewConnectors(cfg *config.Config) (Connectors, error) {
	c := Connectors{
		Prometheus: map[string]*prometheus.Client{},
		Loki:       map[string]*loki.Client{},
		Sentry:     map[string]*sentry.Client{},
		Cloudflare: map[string]*cloudflare.Client{},
		AWS:        map[string]*aws.Client{},
		Tempo:      map[string]*tempo.Client{},
	}
	for name, src := range cfg.Sources {
		switch src.Type {
		case config.SourcePrometheus:
			client, err := prometheus.New(src)
			if err != nil {
				return Connectors{}, err
			}
			c.Prometheus[name] = client
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
		default:
			return Connectors{}, fmt.Errorf("source %s: unsupported type %s", name, src.Type)
		}
	}
	return c, nil
}
