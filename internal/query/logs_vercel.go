package query

import (
	"context"
	"slices"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/vercel"
	"github.com/contember/sonda/internal/policy"
)

// vercelMaxCount bounds the paging that counts search matches, ten pages of logs.
const vercelMaxCount = 10_000

type vercelLogs struct {
	scope  authz.VercelScope
	client *vercel.Client
}

func newVercelLogs(scope authz.VercelScope, client *vercel.Client) logBackend {
	return &vercelLogs{scope: scope, client: client}
}

func (b *vercelLogs) dialect() api.Dialect { return api.DialectVercelKQL }

// search fetches the newest matching logs. Vercel reports no total, so when more logs match,
// they are counted by paging, up to vercelMaxCount.
func (b *vercelLogs) search(ctx context.Context, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error) {
	q, err := policy.VercelLogSearch(b.scope, f)
	if err != nil {
		return logSearch{}, err
	}
	recordQuery(ctx, b.scope.Target, q.String())
	streams, more, err := b.client.Lines(ctx, b.scope, q, r, limit)
	if err != nil {
		return logSearch{}, err
	}
	result := logSearch{query: q.String(), streams: streams, source: b.sourceRef(q)}
	for _, s := range streams {
		result.total += int64(len(s.Entries))
	}
	if more {
		total, complete, err := b.client.Count(ctx, b.scope, q, r, vercelMaxCount)
		if err != nil {
			return logSearch{}, err
		}
		result.total, result.totalLowerBound = total, !complete
	}
	return result, nil
}

// query runs KQL over runtime logs. Vercel has no aggregations, so a query returns lines and
// step is not used.
func (b *vercelLogs) query(ctx context.Context, r api.TimeRange, text string, limit int, _ string) (logQuery, error) {
	q, err := policy.ScopeVercelQuery(b.scope, text)
	if err != nil {
		return logQuery{}, err
	}
	recordQuery(ctx, b.scope.Target, q.String())
	streams, _, err := b.client.Lines(ctx, b.scope, q, r, limit)
	if err != nil {
		return logQuery{}, err
	}
	return logQuery{query: q.String(), streams: streams, source: b.sourceRef(q)}, nil
}

// fields lists the fields Vercel filters on; it has no endpoint for the fields seen in a range.
func (b *vercelLogs) fields(context.Context, api.TimeRange) (api.LogFields, error) {
	return api.LogFields{Labels: []api.LogLabel{}, Fields: slices.Clone(vercel.RuntimeFields)}, nil
}

// sourceRef has no URL: the dashboard addresses teams and projects by slug, not by ID.
func (b *vercelLogs) sourceRef(q policy.VercelQuery) api.SourceRef {
	return api.SourceRef{Kind: string(b.scope.Source().Type), Query: q.String()}
}
