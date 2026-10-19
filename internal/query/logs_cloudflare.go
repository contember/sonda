package query

import (
	"context"
	"sort"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

var cloudflareLogViews = []string{policy.CloudflareViewEvents, policy.CloudflareViewCalculations, policy.CloudflareViewInvocations}

type cloudflareLogs struct {
	scope  authz.CloudflareScope
	client *cloudflare.Client
}

func newCloudflareLogs(scope authz.CloudflareScope, client *cloudflare.Client) logBackend {
	return &cloudflareLogs{scope: scope, client: client}
}

func (b *cloudflareLogs) dialect() api.Dialect { return api.DialectCloudflareQuery }

// search counts the matching events with a calculations query, then fetches the newest events.
func (b *cloudflareLogs) search(ctx context.Context, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error) {
	events, count, err := policy.CloudflareLogSearch(b.scope, f, limit)
	if err != nil {
		return logSearch{}, err
	}
	recordQuery(ctx, b.scope.Target, count.String())
	total, err := b.client.Count(ctx, b.scope, count, r)
	if err != nil {
		return logSearch{}, err
	}
	recordQuery(ctx, b.scope.Target, events.String())
	streams, err := b.client.Lines(ctx, b.scope, events, r)
	if err != nil {
		return logSearch{}, err
	}
	return logSearch{query: events.String(), total: total, streams: streams, source: b.sourceRef(events, r)}, nil
}

// query runs a telemetry query. Calculations return series; events and invocations return
// lines. Cloudflare picks the time buckets of calculations, so step is not used.
func (b *cloudflareLogs) query(ctx context.Context, r api.TimeRange, text string, limit int, _ string) (logQuery, error) {
	q, err := policy.ScopeCloudflareQuery(b.scope, text, cloudflareLogViews...)
	if err != nil {
		return logQuery{}, err
	}
	q = q.WithLimit(limit)
	recordQuery(ctx, b.scope.Target, q.String())
	result := logQuery{query: q.String(), source: b.sourceRef(q, r)}
	if q.View() == policy.CloudflareViewCalculations {
		series, err := b.client.Calculations(ctx, b.scope, q, r)
		if err != nil {
			return logQuery{}, err
		}
		result.series = series
		return result, nil
	}
	result.streams, err = b.client.Lines(ctx, b.scope, q, r)
	if err != nil {
		return logQuery{}, err
	}
	return result, nil
}

func (b *cloudflareLogs) fields(ctx context.Context, r api.TimeRange) (api.LogFields, error) {
	keys, err := b.client.Keys(ctx, b.scope, r)
	if err != nil {
		return api.LogFields{}, err
	}
	result := api.LogFields{Labels: []api.LogLabel{}, Fields: make([]api.LogField, 0, len(keys))}
	for _, key := range keys {
		result.Fields = append(result.Fields, api.LogField{Name: key.Key, Type: key.Type})
	}
	sort.Slice(result.Fields, func(i, j int) bool { return result.Fields[i].Name < result.Fields[j].Name })
	return result, nil
}

func (b *cloudflareLogs) sourceRef(q policy.CloudflareQuery, r api.TimeRange) api.SourceRef {
	return shape.CloudflareSourceRef(b.scope.Source(), q.String(), r)
}
