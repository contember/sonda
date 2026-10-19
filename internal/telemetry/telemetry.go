// Package telemetry holds backend-neutral telemetry records returned by connectors.
package telemetry

import "time"

type LogEntry struct {
	Time time.Time
	Line string
}

type LogStream struct {
	Labels  map[string]string
	Entries []LogEntry
}

type SpanStatus string

const (
	StatusUnset SpanStatus = "unset"
	StatusOK    SpanStatus = "ok"
	StatusError SpanStatus = "error"
)

type Span struct {
	TraceID       string
	SpanID        string
	ParentID      string
	Service       string // OTel service.name, or the Cloudflare script name
	Name          string
	Kind          string
	Start         time.Time
	Duration      time.Duration
	Status        SpanStatus
	StatusMessage string
	Attributes    map[string]string
	Events        []SpanEvent
}

type SpanEvent struct {
	Time       time.Time
	Name       string
	Attributes map[string]string
}

type TraceSummary struct {
	TraceID     string
	RootService string
	RootName    string
	Start       time.Time
	Duration    time.Duration
	SpanCount   int // 0 when the backend does not report it
	ErrorCount  int
	Matched     []Span // spans that matched the search, scoped service only
}
