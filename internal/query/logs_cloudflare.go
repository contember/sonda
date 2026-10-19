package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/policy"
)

type cloudflareLogs struct {
	scope  authz.CloudflareScope
	client *cloudflare.Client
}

func newCloudflareLogs(scope authz.CloudflareScope, client *cloudflare.Client) logBackend {
	return &cloudflareLogs{scope: scope, client: client}
}

func (b *cloudflareLogs) dialect() api.Dialect { return api.DialectCloudflareQuery }

func (b *cloudflareLogs) search(ctx context.Context, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error) {
	return logSearch{}, notImplemented(b.dialect())
}

func (b *cloudflareLogs) query(ctx context.Context, r api.TimeRange, text string, limit int, step string) (logQuery, error) {
	return logQuery{}, notImplemented(b.dialect())
}

func (b *cloudflareLogs) fields(ctx context.Context, r api.TimeRange) (api.LogFields, error) {
	return api.LogFields{}, notImplemented(b.dialect())
}
