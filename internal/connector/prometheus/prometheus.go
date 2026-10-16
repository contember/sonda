// Package prometheus queries the Prometheus HTTP API (also Mimir, Thanos, VictoriaMetrics).
package prometheus

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	promapi "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/policy"
)

const metadataTTL = 10 * time.Minute

type Client struct {
	source *config.Source
	api    v1.API

	mu         sync.Mutex
	metadata   map[string][]v1.Metadata
	metadataAt time.Time
}

func New(src *config.Source) (*Client, error) {
	c, err := promapi.NewClient(promapi.Config{Address: src.URL, Client: upstream.HTTPClient(src)})
	if err != nil {
		return nil, fmt.Errorf("prometheus source %s: %w", src.Name, err)
	}
	return &Client{source: src, api: v1.NewAPI(c)}, nil
}

func (c *Client) QueryRange(ctx context.Context, q policy.PromQL, r api.TimeRange, step time.Duration) (model.Matrix, error) {
	value, _, err := c.api.QueryRange(ctx, q.String(), v1.Range{Start: r.From, End: r.To, Step: step})
	if err != nil {
		return nil, c.wrap(err)
	}
	matrix, ok := value.(model.Matrix)
	if !ok {
		return nil, apierr.Upstream("source %s returned %s instead of a matrix", c.source.Name, value.Type())
	}
	return matrix, nil
}

// MetricNames returns the metric names that exist within the scope.
func (c *Client) MetricNames(ctx context.Context, scope authz.SelectorScope, r api.TimeRange) ([]string, error) {
	values, _, err := c.api.LabelValues(ctx, model.MetricNameLabel, []string{scope.Selector()}, r.From, r.To)
	if err != nil {
		return nil, c.wrap(err)
	}
	names := make([]string, len(values))
	for i, v := range values {
		names[i] = string(v)
	}
	return names, nil
}

// Metadata returns type and help of all metrics, cached. Callers must look up only names
// they obtained through a scoped call.
func (c *Client) Metadata(ctx context.Context) (map[string][]v1.Metadata, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.metadata != nil && time.Since(c.metadataAt) < metadataTTL {
		return c.metadata, nil
	}
	metadata, err := c.api.Metadata(ctx, "", "")
	if err != nil {
		return nil, c.wrap(err)
	}
	c.metadata, c.metadataAt = metadata, time.Now()
	return metadata, nil
}

func (c *Client) wrap(err error) error {
	var promErr *v1.Error
	if errors.As(err, &promErr) {
		switch promErr.Type {
		case v1.ErrBadData:
			return apierr.InvalidQuery("source %s rejected the query: %s", c.source.Name, promErr.Msg)
		case v1.ErrTimeout, v1.ErrCanceled:
			return context.DeadlineExceeded
		default:
			return apierr.Upstream("source %s: %s", c.source.Name, promErr.Error())
		}
	}
	return upstream.Wrap(c.source.Name, err)
}
