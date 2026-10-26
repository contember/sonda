package query

import (
	"cmp"
	"context"
	"slices"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/sentry"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

const (
	// sentrySearchSpans is how many matching spans a search reads to find its traces.
	sentrySearchSpans = 500
	// sentryMatchedSpans caps the matched spans shown per trace.
	sentryMatchedSpans = 3
	// sentryTraceSpans is the most spans a trace fetch reads; a larger trace fails.
	sentryTraceSpans = 2000
	// sentrySegments is the most transaction segments read to name the found traces.
	sentrySegments = 1000
)

type sentryTraces struct {
	scope  authz.SentrySpanScope
	client *sentry.Client
}

func newSentryTraces(scope authz.SentrySpanScope, client *sentry.Client) traceBackend {
	return &sentryTraces{scope: scope, client: client}
}

func (b *sentryTraces) dialect() api.Dialect { return api.DialectSentrySearch }

func (b *sentryTraces) search(ctx context.Context, r api.TimeRange, f policy.TraceFilter, limit int) (traceSearch, error) {
	q, err := policy.SentrySpanSearch(f)
	if err != nil {
		return traceSearch{}, err
	}
	return b.run(ctx, r, q, limit)
}

func (b *sentryTraces) query(ctx context.Context, r api.TimeRange, text string, limit int) (traceSearch, error) {
	return b.run(ctx, r, policy.SentrySpans(text), limit)
}

// run finds the newest matching spans of the scope, groups them into traces and names each
// trace by its root transaction.
func (b *sentryTraces) run(ctx context.Context, r api.TimeRange, q policy.SentrySpanQuery, limit int) (traceSearch, error) {
	recordQuery(ctx, b.scope.Target, b.describe(q))
	spans, err := b.client.Spans(ctx, b.scope, q, r, sentrySearchSpans)
	if err != nil {
		return traceSearch{}, err
	}
	var traces []telemetry.TraceSummary
	index := map[string]int{}
	for _, span := range spans {
		i, ok := index[span.TraceID]
		if !ok {
			if len(traces) == limit {
				continue
			}
			i = len(traces)
			index[span.TraceID] = i
			traces = append(traces, telemetry.TraceSummary{TraceID: span.TraceID, Start: span.Start, Duration: span.Duration})
		}
		if len(traces[i].Matched) < sentryMatchedSpans {
			traces[i].Matched = append(traces[i].Matched, span)
		}
	}
	if len(traces) > 0 {
		if err := b.nameTraces(ctx, r, traces); err != nil {
			return traceSearch{}, err
		}
	}
	return traceSearch{query: q.String(), traces: traces, source: b.sourceRef(q)}, nil
}

// nameTraces sets each trace's root from its segment without a parent, or its earliest
// segment when the root is missing. A trace without segments keeps its matched span's timing.
func (b *sentryTraces) nameTraces(ctx context.Context, r api.TimeRange, traces []telemetry.TraceSummary) error {
	ids := make([]string, len(traces))
	for i, t := range traces {
		ids[i] = t.TraceID
	}
	q := policy.SentryTraceSegments(ids)
	recordQuery(ctx, b.scope.Target, q.String())
	segments, err := b.client.TraceSpans(ctx, q, r, sentrySegments)
	if err != nil {
		return err
	}
	roots := map[string]telemetry.Span{}
	for _, s := range segments {
		root, ok := roots[s.TraceID]
		if !ok || (root.ParentID != "" && (s.ParentID == "" || s.Start.Before(root.Start))) {
			roots[s.TraceID] = s
		}
	}
	for i := range traces {
		if root, ok := roots[traces[i].TraceID]; ok {
			traces[i].RootService, traces[i].RootName = root.Service, cmp.Or(root.Attributes["transaction"], root.Name)
			traces[i].Start, traces[i].Duration = root.Start, root.Duration
		}
	}
	return nil
}

func (b *sentryTraces) trace(ctx context.Context, r api.TimeRange, id string) (traceFetch, error) {
	q, err := policy.SentryTraceByID(id)
	if err != nil {
		return traceFetch{}, err
	}
	recordQuery(ctx, b.scope.Target, "trace "+id)
	spans, err := b.client.TraceSpans(ctx, q, r, sentryTraceSpans)
	if err != nil {
		return traceFetch{}, err
	}
	if len(spans) >= sentryTraceSpans {
		return traceFetch{}, apierr.New(api.CodeLimitExceeded, "trace has at least %d spans, more than one fetch returns", sentryTraceSpans)
	}
	// The caller checks the project; the environment of the binding must match as well.
	inScope := func(s telemetry.Span) bool {
		return s.Service == b.scope.Project() && s.Attributes["environment"] == b.scope.SentryEnvironment()
	}
	if !slices.ContainsFunc(spans, inScope) {
		return traceFetch{}, apierr.NotFound("trace %s not found", id)
	}
	return traceFetch{spans: spans, source: b.sourceRef(q)}, nil
}

func (b *sentryTraces) describe(q policy.SentrySpanQuery) string {
	return "project:" + b.scope.Project() + " environment:" + b.scope.SentryEnvironment() + " " + q.String()
}

func (b *sentryTraces) sourceRef(q policy.SentrySpanQuery) api.SourceRef {
	return api.SourceRef{Kind: "sentry", Query: q.String()}
}
