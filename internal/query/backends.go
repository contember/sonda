package query

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

// logBackend runs log use cases for one scope. Implementations bind the scope and the client
// and record their upstream queries with recordQuery.
type logBackend interface {
	dialect() api.Dialect
	// search returns the exact number of matching lines in the range and the newest matching lines.
	search(ctx context.Context, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error)
	// query runs native query text. A query returns either streams or series.
	query(ctx context.Context, r api.TimeRange, text string, limit int, step string) (logQuery, error)
	fields(ctx context.Context, r api.TimeRange) (api.LogFields, error)
}

type logSearch struct {
	query string
	total int64
	// totalLowerBound is true when the backend stopped counting before the last match.
	totalLowerBound bool
	streams         []telemetry.LogStream
	source          api.SourceRef
}

// logQuery holds the result of a native log query. series is non-nil exactly when the query
// returns series, also when there are none.
type logQuery struct {
	query   string
	streams []telemetry.LogStream
	series  model.Matrix
	source  api.SourceRef
}

// metricBackend runs metric use cases for one scope.
type metricBackend interface {
	dialect() api.Dialect
	names(ctx context.Context, r api.TimeRange) ([]api.MetricInfo, error)
	query(ctx context.Context, r api.TimeRange, text string, step time.Duration) (metricQuery, error)
}

type metricQuery struct {
	query  string
	series model.Matrix
	source api.SourceRef
	// step is the resolution the backend actually used; 0 means the requested step.
	step time.Duration
}

// traceBackend runs trace use cases for one scope. search and query return at most limit
// traces; the caller asks for one more than it returns to detect truncation.
type traceBackend interface {
	dialect() api.Dialect
	search(ctx context.Context, r api.TimeRange, f policy.TraceFilter, limit int) (traceSearch, error)
	query(ctx context.Context, r api.TimeRange, text string, limit int) (traceSearch, error)
	// trace fetches a trace by ID. The fetch cannot be scoped upstream; the caller checks that the
	// trace contains a span of the scoped service before returning anything. A missing trace is a
	// not_found error or no spans; the caller replaces both with one message that names the
	// scoped service, so the error does not reveal traces of other services.
	trace(ctx context.Context, r api.TimeRange, id string) (traceFetch, error)
}

type traceSearch struct {
	query  string
	traces []telemetry.TraceSummary
	source api.SourceRef
}

type traceFetch struct {
	spans  []telemetry.Span
	source api.SourceRef
}

func (s *Service) logBackend(scope authz.LogScope) (logBackend, error) {
	if loki, ok := scope.Loki(); ok {
		return newLokiLogs(loki, s.connectors.Loki[loki.Source().Name], s.cfg.Grafana), nil
	}
	if cf, ok := scope.Cloudflare(); ok {
		return newCloudflareLogs(cf, s.connectors.Cloudflare[cf.Source().Name]), nil
	}
	if groups, ok := scope.CloudWatch(); ok {
		return newCloudWatchLogs(groups, s.connectors.AWS[groups.Source().Name]), nil
	}
	if v, ok := scope.Vercel(); ok {
		return newVercelLogs(v, s.connectors.Vercel[v.Source().Name]), nil
	}
	return nil, unsupported("log", scope.Source())
}

func (s *Service) metricBackend(scope authz.MetricScope) (metricBackend, error) {
	if prom, ok := scope.Prometheus(); ok {
		return newPrometheusMetrics(prom, s.connectors.Prometheus[prom.Source().Name], s.cfg.Grafana), nil
	}
	if cf, ok := scope.Cloudflare(); ok {
		return newCloudflareMetrics(cf, s.connectors.Cloudflare[cf.Source().Name]), nil
	}
	if cw, ok := scope.CloudWatch(); ok {
		return newCloudWatchMetrics(cw, s.connectors.AWS[cw.Source().Name]), nil
	}
	return nil, unsupported("metrics", scope.Source())
}

func (s *Service) traceBackend(scope authz.TraceScope) (traceBackend, error) {
	if tempo, ok := scope.Tempo(); ok {
		return newTempoTraces(tempo, s.connectors.Tempo[tempo.Source().Name], s.cfg.Grafana), nil
	}
	if cf, ok := scope.Cloudflare(); ok {
		return newCloudflareTraces(cf, s.connectors.Cloudflare[cf.Source().Name]), nil
	}
	if sentry, ok := scope.Sentry(); ok {
		return newSentryTraces(sentry, s.connectors.Sentry[sentry.Source().Name]), nil
	}
	return nil, unsupported("trace", scope.Source())
}

func unsupported(capability string, src *config.Source) error {
	return fmt.Errorf("%s source %s has unsupported type %s", capability, src.Name, src.Type)
}

func notImplemented(dialect api.Dialect) error {
	return apierr.New(api.CodeInternal, "%s queries are not implemented yet", dialect)
}
