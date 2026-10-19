package shape

import (
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/telemetry"
)

const maxAttributeLength = 500

// TraceSummaries converts search results. Matched spans of invisible services become stubs; RootName
// is cleared when visible(RootService) is false. Names and attribute values are redacted.
func TraceSummaries(traces []telemetry.TraceSummary, visible func(string) bool, redactor *Redactor) []api.TraceSummary {
	summaries := make([]api.TraceSummary, len(traces))
	for i, t := range traces {
		summary := api.TraceSummary{
			TraceID:     t.TraceID,
			RootService: t.RootService,
			Start:       t.Start,
			DurationMs:  milliseconds(t.Duration),
			SpanCount:   t.SpanCount,
			ErrorCount:  t.ErrorCount,
		}
		if visible(t.RootService) {
			summary.RootName = redactor.Redact(t.RootName)
		}
		for _, span := range t.Matched {
			summary.Matched = append(summary.Matched, shapeSpan(span, 0, visible, redactor))
		}
		summaries[i] = summary
	}
	return summaries
}

// Trace orders spans depth-first from the roots and replaces spans of invisible services by stubs.
// It keeps at most maxSpans spans and reports whether it cut any.
func Trace(id string, spans []telemetry.Span, visible func(string) bool, redactor *Redactor, maxSpans int) (api.Trace, bool) {
	unique := uniqueSpans(spans)
	ordered := depthFirst(unique)
	truncated := len(ordered) > maxSpans
	if truncated {
		ordered = ordered[:max(maxSpans, 0)]
	}
	trace := api.Trace{TraceID: id, Services: services(unique), Spans: make([]api.Span, len(ordered))}
	for i, node := range ordered {
		trace.Spans[i] = shapeSpan(node.span, node.depth, visible, redactor)
	}
	return trace, truncated
}

type orderedSpan struct {
	span  telemetry.Span
	depth int
}

func uniqueSpans(spans []telemetry.Span) []telemetry.Span {
	seen := map[string]bool{}
	var unique []telemetry.Span
	for _, span := range spans {
		if seen[span.SpanID] {
			continue
		}
		seen[span.SpanID] = true
		unique = append(unique, span)
	}
	return unique
}

// depthFirst walks from spans whose parent is missing. Spans caught in a parent cycle are
// unreachable from those roots, so the walk then starts from each still unvisited span.
func depthFirst(spans []telemetry.Span) []orderedSpan {
	byStart := slices.Clone(spans)
	slices.SortStableFunc(byStart, compareSpans)
	present := map[string]bool{}
	for _, span := range byStart {
		present[span.SpanID] = true
	}
	children := map[string][]telemetry.Span{}
	var roots []telemetry.Span
	for _, span := range byStart {
		if span.ParentID == "" || !present[span.ParentID] {
			roots = append(roots, span)
			continue
		}
		children[span.ParentID] = append(children[span.ParentID], span)
	}

	visited := map[string]bool{}
	ordered := make([]orderedSpan, 0, len(spans))
	var walk func(span telemetry.Span, depth int)
	walk = func(span telemetry.Span, depth int) {
		if visited[span.SpanID] {
			return
		}
		visited[span.SpanID] = true
		ordered = append(ordered, orderedSpan{span: span, depth: depth})
		for _, child := range children[span.SpanID] {
			walk(child, depth+1)
		}
	}
	for _, root := range roots {
		walk(root, 0)
	}
	for _, span := range byStart {
		walk(span, 0)
	}
	return ordered
}

func compareSpans(a, b telemetry.Span) int {
	if c := a.Start.Compare(b.Start); c != 0 {
		return c
	}
	return strings.Compare(a.SpanID, b.SpanID)
}

func services(spans []telemetry.Span) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Service)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func shapeSpan(span telemetry.Span, depth int, visible func(string) bool, redactor *Redactor) api.Span {
	if visible(span.Service) {
		return grantedSpan(span, depth, redactor)
	}
	return stubSpan(span, depth)
}

func grantedSpan(span telemetry.Span, depth int, redactor *Redactor) api.Span {
	result := stubSpan(span, depth)
	result.Granted = true
	result.Name = redactor.Redact(span.Name)
	result.Kind = span.Kind
	result.StatusMessage = cutAttribute(redactor.Redact(span.StatusMessage))
	result.Attributes = redactAttributes(span.Attributes, redactor)
	for _, event := range span.Events {
		result.Events = append(result.Events, api.SpanEvent{
			Time:       event.Time,
			Name:       redactor.Redact(event.Name),
			Attributes: redactAttributes(event.Attributes, redactor),
		})
	}
	return result
}

// stubSpan keeps only what may be shown for a span of a service the identity cannot see.
func stubSpan(span telemetry.Span, depth int) api.Span {
	return api.Span{
		SpanID:     span.SpanID,
		ParentID:   span.ParentID,
		Depth:      depth,
		Service:    span.Service,
		Start:      span.Start,
		DurationMs: milliseconds(span.Duration),
		Status:     status(span.Status),
	}
}

func status(s telemetry.SpanStatus) string {
	switch s {
	case telemetry.StatusOK, telemetry.StatusError:
		return string(s)
	}
	return ""
}

func redactAttributes(attributes map[string]string, redactor *Redactor) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	redacted := make(map[string]string, len(attributes))
	for key, value := range attributes {
		redacted[key] = cutAttribute(redactor.Redact(value))
	}
	return redacted
}

func cutAttribute(value string) string {
	if len(value) <= maxAttributeLength {
		return value
	}
	end := maxAttributeLength
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + "…"
}

func milliseconds(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
