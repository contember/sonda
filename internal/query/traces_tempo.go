package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/tempo"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

type tempoTraces struct {
	scope  authz.TempoScope
	client *tempo.Client
}

func newTempoTraces(scope authz.TempoScope, client *tempo.Client) traceBackend {
	return &tempoTraces{scope: scope, client: client}
}

func (b *tempoTraces) dialect() api.Dialect { return api.DialectTraceQL }

func (b *tempoTraces) search(ctx context.Context, r api.TimeRange, f policy.TraceFilter, limit int) (traceSearch, error) {
	q, err := policy.TempoSearch(b.scope, f)
	if err != nil {
		return traceSearch{}, err
	}
	return b.run(ctx, r, q, limit)
}

func (b *tempoTraces) query(ctx context.Context, r api.TimeRange, text string, limit int) (traceSearch, error) {
	q, err := policy.ScopeTraceQL(b.scope, text)
	if err != nil {
		return traceSearch{}, err
	}
	return b.run(ctx, r, q, limit)
}

func (b *tempoTraces) run(ctx context.Context, r api.TimeRange, q policy.TraceQL, limit int) (traceSearch, error) {
	recordQuery(ctx, b.scope.Target, q.String())
	traces, err := b.client.Search(ctx, q, r, limit)
	if err != nil {
		return traceSearch{}, err
	}
	// Every filter of the query is scoped, so every matched span is of the scoped service.
	for i := range traces {
		for j := range traces[i].Matched {
			traces[i].Matched[j].Service = b.scope.ServiceName()
		}
	}
	return traceSearch{query: q.String(), traces: traces, source: b.sourceRef(q.String(), r)}, nil
}

func (b *tempoTraces) trace(ctx context.Context, r api.TimeRange, id string) (traceFetch, error) {
	recordQuery(ctx, b.scope.Target, "trace "+id)
	spans, err := b.client.Trace(ctx, id, r)
	if err != nil {
		return traceFetch{}, err
	}
	return traceFetch{spans: spans, source: b.sourceRef(id, r)}, nil
}

// sourceRef builds no Grafana link: newTempoTraces does not receive the Grafana config.
func (b *tempoTraces) sourceRef(query string, r api.TimeRange) api.SourceRef {
	return shape.TempoSourceRef(nil, b.scope.Source(), query, r)
}
