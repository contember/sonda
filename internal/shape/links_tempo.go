package shape

import (
	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

// TempoSourceRef describes where a TraceQL query or a trace lookup ran. The query may be a
// trace ID, which Grafana's TraceQL editor opens as a trace. It links to Grafana Explore
// when Grafana and the source's datasource UID are configured.
func TempoSourceRef(grafana *config.Grafana, src *config.Source, query string, r api.TimeRange) api.SourceRef {
	return exploreRef(grafana, src, query, r, exploreQuery{Query: query, QueryType: "traceql"})
}
