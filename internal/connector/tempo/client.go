// Package tempo queries the Grafana Tempo HTTP API.
package tempo

import (
	"net/http"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
)

type Client struct {
	source *config.Source
	http   *http.Client
}

func New(src *config.Source) (*Client, error) {
	return &Client{source: src, http: upstream.HTTPClient(src)}, nil
}
