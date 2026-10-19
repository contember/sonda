package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/cloudflare"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
	"github.com/contember/sonda/internal/telemetry"
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
	q, err := policy.CloudflareTraceSearch(b.scope, f, limit)
	if err != nil {
		return traceSearch{}, err
	}
	return b.run(ctx, r, q, limit)
}

func (b *cloudflareTraces) query(ctx context.Context, r api.TimeRange, text string, limit int) (traceSearch, error) {
	q, err := policy.ScopeCloudflareQuery(b.scope, text, policy.CloudflareViewTraces)
	if err != nil {
		return traceSearch{}, err
	}
	return b.run(ctx, r, q.WithLimit(limit), limit)
}

func (b *cloudflareTraces) run(ctx context.Context, r api.TimeRange, q policy.CloudflareQuery, limit int) (traceSearch, error) {
	recordQuery(ctx, b.scope.Target, q.String())
	traces, err := b.client.Traces(ctx, b.scope, q, r)
	if err != nil {
		return traceSearch{}, err
	}
	return traceSearch{query: q.String(), traces: firstTraces(traces, limit), source: b.sourceRef(q, r)}, nil
}

func (b *cloudflareTraces) trace(ctx context.Context, r api.TimeRange, id string) (traceFetch, error) {
	q := policy.CloudflareTraceByID(b.scope, id)
	recordQuery(ctx, b.scope.Target, q.String())
	spans, err := b.client.Trace(ctx, q, r)
	if err != nil {
		return traceFetch{}, err
	}
	return traceFetch{spans: spans, source: b.sourceRef(q, r)}, nil
}

func (b *cloudflareTraces) sourceRef(q policy.CloudflareQuery, r api.TimeRange) api.SourceRef {
	return shape.CloudflareSourceRef(b.scope.Source(), q.String(), r)
}

func firstTraces(traces []telemetry.TraceSummary, limit int) []telemetry.TraceSummary {
	if len(traces) > limit {
		return traces[:limit]
	}
	return traces
}
