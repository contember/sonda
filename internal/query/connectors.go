package query

import (
	"context"
	"fmt"
	"net/http"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/alerting"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/connector/awsauth"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/connector/kubernetes"
	"github.com/contember/sonda/internal/connector/loki"
	"github.com/contember/sonda/internal/connector/prometheus"
	"github.com/contember/sonda/internal/connector/sentry"
	"github.com/contember/sonda/internal/connector/tempo"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/connector/vercel"
	"github.com/contember/sonda/internal/issuer"
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
	Vercel     map[string]*vercel.Client
	// Alerting holds a client for every Prometheus and Grafana source.
	Alerting map[string]*alerting.Client
}

// NewConnectors builds the clients. identity is Sonda's own identity, nil without the identity
// section; aws sources with credentials: identity need it.
func NewConnectors(cfg *config.Config, identity *issuer.Issuer) (Connectors, error) {
	c := Connectors{
		Prometheus: map[string]*prometheus.Client{},
		Loki:       map[string]*loki.Client{},
		Sentry:     map[string]*sentry.Client{},
		Cloudflare: map[string]*cloudflare.Client{},
		AWS:        map[string]*aws.Client{},
		Tempo:      map[string]*tempo.Client{},
		Kubernetes: map[string]*kubernetes.Client{},
		Vercel:     map[string]*vercel.Client{},
		Alerting:   map[string]*alerting.Client{},
	}
	// One AWS configuration per aws source, shared by its CloudWatch client and by the sources
	// that authenticate to EKS with it, so they share one credential cache.
	awsConfigs := map[string]sdkaws.Config{}
	for name, src := range cfg.Sources {
		if src.Type != config.SourceAWS {
			continue
		}
		awsConfig, err := awsauth.Config(context.Background(), src.AWS, identity)
		if err != nil {
			return Connectors{}, fmt.Errorf("source %s: load AWS configuration: %w", name, err)
		}
		awsConfigs[name] = awsConfig
		c.AWS[name] = aws.New(src, awsConfig)
	}
	for name, src := range cfg.Sources {
		if src.Type == config.SourceAWS {
			continue
		}
		var tokens upstream.TokenSource
		if src.Auth.EKS != nil {
			tokens = awsauth.NewEKSTokens(awsConfigs[src.Auth.EKS.AWS.Name], src.Auth.EKS.Cluster)
		}
		client := upstream.HTTPClient(src, tokens)
		if err := c.add(name, src, client); err != nil {
			return Connectors{}, err
		}
	}
	return c, nil
}

func (c Connectors) add(name string, src *config.Source, client *http.Client) error {
	switch src.Type {
	case config.SourcePrometheus:
		prom, err := prometheus.New(src, client)
		if err != nil {
			return err
		}
		c.Prometheus[name] = prom
		c.Alerting[name] = alerting.New(src, client)
	case config.SourceLoki:
		c.Loki[name] = loki.New(src, client)
	case config.SourceSentry:
		c.Sentry[name] = sentry.New(src, client)
	case config.SourceCloudflare:
		c.Cloudflare[name] = cloudflare.New(src, client)
	case config.SourceTempo:
		c.Tempo[name] = tempo.New(src, client)
	case config.SourceKubernetes:
		c.Kubernetes[name] = kubernetes.New(src, client)
	case config.SourceGrafana:
		c.Alerting[name] = alerting.New(src, client)
	case config.SourceVercel:
		c.Vercel[name] = vercel.New(src, client)
	default:
		return fmt.Errorf("source %s: unsupported type %s", name, src.Type)
	}
	return nil
}
