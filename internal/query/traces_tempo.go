package query

import (
	"context"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/tempo"
	"github.com/contember/sonda/internal/policy"
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
	return traceSearch{}, notImplemented(b.dialect())
}

func (b *tempoTraces) query(ctx context.Context, r api.TimeRange, text string, limit int) (traceSearch, error) {
	return traceSearch{}, notImplemented(b.dialect())
}

func (b *tempoTraces) trace(ctx context.Context, r api.TimeRange, id string) (traceFetch, error) {
	return traceFetch{}, notImplemented(b.dialect())
}
