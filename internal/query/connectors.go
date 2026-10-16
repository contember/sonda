package query

import (
	"fmt"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/prometheus"
)

// Connectors holds one client per configured source, keyed by source name.
type Connectors struct {
	Prometheus map[string]*prometheus.Client
}

func NewConnectors(cfg *config.Config) (Connectors, error) {
	c := Connectors{
		Prometheus: map[string]*prometheus.Client{},
	}
	for name, src := range cfg.Sources {
		switch src.Type {
		case config.SourcePrometheus:
			client, err := prometheus.New(src)
			if err != nil {
				return Connectors{}, err
			}
			c.Prometheus[name] = client
		case config.SourceLoki, config.SourceSentry:
		default:
			return Connectors{}, fmt.Errorf("source %s: unsupported type %s", name, src.Type)
		}
	}
	return c, nil
}
