package shape

import (
	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/telemetry"
)

// TraceSummaries converts search results. Matched spans are of the scoped service; RootName is cleared
// when visible(RootService) is false. Attribute values are redacted.
func TraceSummaries(traces []telemetry.TraceSummary, visible func(string) bool, redactor *Redactor) []api.TraceSummary {
	panic("not implemented")
}

// Trace orders spans depth-first from the roots and replaces spans of invisible services by stubs.
// It keeps at most maxSpans spans and reports whether it cut any.
func Trace(id string, spans []telemetry.Span, visible func(string) bool, redactor *Redactor, maxSpans int) (api.Trace, bool) {
	panic("not implemented")
}
