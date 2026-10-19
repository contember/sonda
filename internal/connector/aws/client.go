// Package aws queries CloudWatch Logs Insights and CloudWatch Metrics.
package aws

import (
	"github.com/contember/sonda/internal/config"
)

type Client struct {
	source *config.Source
}

func New(src *config.Source) (*Client, error) {
	return &Client{source: src}, nil
}
