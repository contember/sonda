package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/insights"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

type cloudWatchLogs struct {
	scope  authz.LogGroupScope
	client *aws.Client
}

func newCloudWatchLogs(scope authz.LogGroupScope, client *aws.Client) logBackend {
	return &cloudWatchLogs{scope: scope, client: client}
}

func (b *cloudWatchLogs) dialect() api.Dialect { return api.DialectLogsInsights }

// search runs one query; its statistics give the exact number of matching events.
func (b *cloudWatchLogs) search(ctx context.Context, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error) {
	q, err := policy.InsightsSearch(b.scope, f, limit)
	if err != nil {
		return logSearch{}, err
	}
	recordQuery(ctx, b.scope.Target, q.String())
	result, err := b.client.Insights(ctx, b.scope, q, r, limit)
	if err != nil {
		return logSearch{}, err
	}
	return logSearch{query: q.String(), total: result.Total, streams: result.Streams, source: b.sourceRef(q, r)}, nil
}

// query runs Logs Insights QL. Queries with a stats stage return series, others lines. The
// step is unused, because bin() in the query sets the bucket size.
func (b *cloudWatchLogs) query(ctx context.Context, r api.TimeRange, text string, limit int, step string) (logQuery, error) {
	q, err := policy.ScopeInsights(b.scope, text)
	if err != nil {
		return logQuery{}, err
	}
	// The line limit must not cut statistics rows, so they get as many rows as AWS returns.
	rows := limit
	if q.Aggregates() {
		rows = insights.MaxRows
	}
	recordQuery(ctx, b.scope.Target, q.String())
	result, err := b.client.Insights(ctx, b.scope, q, r, rows)
	if err != nil {
		return logQuery{}, err
	}
	return logQuery{query: q.String(), streams: result.Streams, series: result.Series, source: b.sourceRef(q, r)}, nil
}

func (b *cloudWatchLogs) fields(ctx context.Context, r api.TimeRange) (api.LogFields, error) {
	fields, err := b.client.LogFields(ctx, b.scope, r)
	if err != nil {
		return api.LogFields{}, err
	}
	result := api.LogFields{Fields: make([]api.LogField, 0, len(fields))}
	for _, f := range fields {
		result.Fields = append(result.Fields, api.LogField{Name: f.Name})
	}
	return result, nil
}

func (b *cloudWatchLogs) sourceRef(q policy.InsightsQuery, r api.TimeRange) api.SourceRef {
	return shape.CloudWatchLogsSourceRef(b.scope.Source(), b.scope.LogGroups(), q.String(), r)
}
