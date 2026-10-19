package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/policy"
)

type cloudflareTraces struct {
	scope  authz.CloudflareScope
	client *cloudflare.Client
}

func newCloudflareTraces(scope authz.CloudflareScope, client *cloudflare.Client) traceBackend {
	return &cloudflareTraces{scope: scope, client: client}
}

func (b *cloudflareTraces) dialect() api.Dialect { return api.DialectCloudflareQuery }

func (b *cloudflareTraces) search(ctx context.Context, r api.TimeRange, f policy.TraceFilter, limit int) (traceSearch, error) {
	return traceSearch{}, notImplemented(b.dialect())
}

func (b *cloudflareTraces) query(ctx context.Context, r api.TimeRange, text string, limit int) (traceSearch, error) {
	return traceSearch{}, notImplemented(b.dialect())
}

func (b *cloudflareTraces) trace(ctx context.Context, r api.TimeRange, id string) (traceFetch, error) {
	return traceFetch{}, notImplemented(b.dialect())
}
