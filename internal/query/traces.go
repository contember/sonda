package query

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
	"github.com/contember/sonda/internal/telemetry"
)

const (
	defaultTraces = 20
	maxTraces     = 50
	maxTraceSpans = 300
)

var (
	traceIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{16}|[0-9a-f]{32})$`)

	traceSearchUntrusted = []string{
		"data.traces[].rootService",
		"data.traces[].rootName",
		"data.traces[].matched[].name",
		"data.traces[].matched[].statusMessage",
		"data.traces[].matched[].attributes",
		"data.traces[].matched[].events",
	}
	traceUntrusted = []string{
		"data.services[]",
		"data.spans[].service",
		"data.spans[].name",
		"data.spans[].statusMessage",
		"data.spans[].attributes",
		"data.spans[].events",
	}
)

func (s *Service) traceScope(identity *authz.Identity, service, env string) (authz.TraceScope, traceBackend, error) {
	scope, err := s.authz.TraceScope(identity, service, env)
	if err != nil {
		return authz.TraceScope{}, nil, err
	}
	backend, err := s.traceBackend(scope)
	if err != nil {
		return authz.TraceScope{}, nil, err
	}
	return scope, backend, nil
}

// SearchTraces finds traces with spans of the service that match a backend-neutral filter.
func (s *Service) SearchTraces(ctx context.Context, identity *authz.Identity, service string, req api.TraceSearchRequest) (api.Response[api.TraceSearchResult], error) {
	scope, backend, err := s.traceScope(identity, service, req.Environment)
	if err != nil {
		return api.Response[api.TraceSearchResult]{}, err
	}
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return api.Response[api.TraceSearchResult]{}, err
	}
	filter, err := policy.ParseTraceFilter(req)
	if err != nil {
		return api.Response[api.TraceSearchResult]{}, err
	}
	limit := capLimit(req.Limit, defaultTraces, maxTraces)
	found, err := backend.search(ctx, r, filter, limit+1)
	if err != nil {
		return api.Response[api.TraceSearchResult]{}, err
	}
	return s.traceSearchResponse(identity, scope, r, found, limit), nil
}

// QueryTraces runs a native query in the dialect of the service's trace source.
func (s *Service) QueryTraces(ctx context.Context, identity *authz.Identity, service string, req api.TraceQueryRequest) (api.Response[api.TraceSearchResult], error) {
	scope, backend, err := s.traceScope(identity, service, req.Environment)
	if err != nil {
		return api.Response[api.TraceSearchResult]{}, err
	}
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return api.Response[api.TraceSearchResult]{}, err
	}
	limit := capLimit(req.Limit, defaultTraces, maxTraces)
	found, err := backend.query(ctx, r, req.Query, limit+1)
	if err != nil {
		return api.Response[api.TraceSearchResult]{}, err
	}
	return s.traceSearchResponse(identity, scope, r, found, limit), nil
}

// traceSearchResponse expects up to limit+1 traces; the extra one only marks the result as truncated.
func (s *Service) traceSearchResponse(identity *authz.Identity, scope authz.TraceScope, r api.TimeRange, found traceSearch, limit int) api.Response[api.TraceSearchResult] {
	traces := shape.TraceSummaries(found.traces, s.authz.TraceVisibility(identity, scope), s.redactor)
	meta := metaFor(scope.Target, r)
	if len(traces) > limit {
		traces, meta.Truncated = traces[:limit], true
	}
	meta.Sources = []api.SourceRef{found.source}
	meta.Untrusted = traceSearchUntrusted
	return api.Response[api.TraceSearchResult]{Data: api.TraceSearchResult{Query: found.query, Traces: traces}, Meta: meta}
}

// GetTrace returns a whole trace that contains a span of the service. Spans of services the
// identity has no traces grant for are reduced to stubs.
func (s *Service) GetTrace(ctx context.Context, identity *authz.Identity, service, id string, w api.Window) (api.Response[api.Trace], error) {
	scope, backend, err := s.traceScope(identity, service, w.Environment)
	if err != nil {
		return api.Response[api.Trace]{}, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return api.Response[api.Trace]{}, err
	}
	normalized := strings.ToLower(id)
	if !traceIDPattern.MatchString(normalized) {
		return api.Response[api.Trace]{}, apierr.InvalidRequest("invalid trace ID %q, expected 16 or 32 hex characters", id)
	}
	notFound := apierr.NotFound("trace %q not found for service %q", normalized, service)
	fetched, err := backend.trace(ctx, r, normalized)
	if e, ok := apierr.As(err); ok && e.Code == api.CodeNotFound {
		return api.Response[api.Trace]{}, notFound
	}
	if err != nil {
		return api.Response[api.Trace]{}, err
	}
	// The fetch by ID is not scoped upstream, so the trace must prove it belongs to the service.
	serviceName := scope.ServiceName()
	if !slices.ContainsFunc(fetched.spans, func(span telemetry.Span) bool { return span.Service == serviceName }) {
		return api.Response[api.Trace]{}, notFound
	}
	trace, truncated := shape.Trace(normalized, fetched.spans, s.authz.TraceVisibility(identity, scope), s.redactor, maxTraceSpans)
	meta := metaFor(scope.Target, r)
	meta.Truncated = truncated
	meta.Sources = []api.SourceRef{fetched.source}
	meta.Untrusted = traceUntrusted
	return api.Response[api.Trace]{Data: trace, Meta: meta}, nil
}
