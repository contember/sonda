package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/policy"
)

type cloudWatchLogs struct {
	scope  authz.LogGroupScope
	client *aws.Client
}

func newCloudWatchLogs(scope authz.LogGroupScope, client *aws.Client) logBackend {
	return &cloudWatchLogs{scope: scope, client: client}
}

func (b *cloudWatchLogs) dialect() api.Dialect { return api.DialectLogsInsights }

func (b *cloudWatchLogs) search(ctx context.Context, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error) {
	return logSearch{}, notImplemented(b.dialect())
}

func (b *cloudWatchLogs) query(ctx context.Context, r api.TimeRange, text string, limit int, step string) (logQuery, error) {
	return logQuery{}, notImplemented(b.dialect())
}

func (b *cloudWatchLogs) fields(ctx context.Context, r api.TimeRange) (api.LogFields, error) {
	return api.LogFields{}, notImplemented(b.dialect())
}
