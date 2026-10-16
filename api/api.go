// Package api defines the HTTP API contract shared by sonda-server and the sonda CLI.
// It must stay free of server dependencies, so the CLI stays small.
package api

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

type Response[T any] struct {
	Data T    `json:"data"`
	Meta Meta `json:"meta"`
}

type Meta struct {
	Service     string      `json:"service,omitempty"`
	Environment string      `json:"environment,omitempty"`
	Range       *TimeRange  `json:"range,omitempty"`
	Sources     []SourceRef `json:"sources,omitempty"`
	Truncated   bool        `json:"truncated,omitempty"`
	Sampled     bool        `json:"sampled,omitempty"`
	ResultID    string      `json:"resultId,omitempty"`
	// Untrusted lists JSON paths of fields that carry raw telemetry.
	Untrusted []string `json:"untrusted,omitempty"`
}

type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// SourceRef points a human to the upstream data. URL is empty when no link can be built.
type SourceRef struct {
	Kind  string `json:"kind"`
	URL   string `json:"url,omitempty"`
	Query string `json:"query,omitempty"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

type ErrorCode string

const (
	CodeUnauthenticated ErrorCode = "unauthenticated"
	CodeNotFound        ErrorCode = "not_found"
	CodeInvalidRequest  ErrorCode = "invalid_request"
	CodeInvalidQuery    ErrorCode = "invalid_query"
	CodeLimitExceeded   ErrorCode = "limit_exceeded"
	CodeRateLimited     ErrorCode = "rate_limited"
	CodeUpstreamError   ErrorCode = "upstream_error"
	CodeTimeout         ErrorCode = "timeout"
	CodeInternal        ErrorCode = "internal"
)

type Capability string

const (
	CapabilityErrors  Capability = "errors"
	CapabilityLogs    Capability = "logs"
	CapabilityMetrics Capability = "metrics"
)

func ParseCapability(s string) (Capability, error) {
	switch c := Capability(s); c {
	case CapabilityErrors, CapabilityLogs, CapabilityMetrics:
		return c, nil
	}
	return "", fmt.Errorf("unknown capability %q (expected errors, logs or metrics)", s)
}

// Window selects an environment and a time range. Since is a duration like "1h" or "7d"
// relative to To (or now). From/To take precedence over Since.
type Window struct {
	Environment string     `json:"env,omitempty"`
	From        *time.Time `json:"from,omitempty"`
	To          *time.Time `json:"to,omitempty"`
	Since       string     `json:"since,omitempty"`
}

type ServiceSummary struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Environments []string `json:"environments"`
}

type ServiceDetail struct {
	Name         string              `json:"name"`
	Description  string              `json:"description,omitempty"`
	Repository   string              `json:"repository,omitempty"`
	Environments []EnvironmentDetail `json:"environments"`
	Signals      []string            `json:"signals,omitempty"`
}

type EnvironmentDetail struct {
	Name         string       `json:"name"`
	Capabilities []Capability `json:"capabilities"`
}

type Issue struct {
	ID      string `json:"id"`
	ShortID string `json:"shortId"`
	Title   string `json:"title"`
	Culprit string `json:"culprit,omitempty"`
	Level   string `json:"level,omitempty"`
	// Count and Users cover the requested range.
	Count     int64     `json:"count"`
	Users     int64     `json:"users"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// New is true when the issue was first seen inside the requested range.
	New  bool   `json:"new"`
	Link string `json:"link,omitempty"`
}

type IssueDetail struct {
	Issue       Issue  `json:"issue"`
	LatestEvent *Event `json:"latestEvent,omitempty"`
}

type Event struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Message    string            `json:"message,omitempty"`
	Release    string            `json:"release,omitempty"`
	TraceID    string            `json:"traceId,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Exceptions []Exception       `json:"exceptions,omitempty"`
}

type Exception struct {
	Type   string  `json:"type"`
	Value  string  `json:"value,omitempty"`
	Frames []Frame `json:"frames,omitempty"`
}

type Frame struct {
	File     string `json:"file,omitempty"`
	Function string `json:"function,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	InApp    bool   `json:"inApp"`
}

type Release struct {
	Version    string    `json:"version"`
	Created    time.Time `json:"created"`
	LastDeploy *Deploy   `json:"lastDeploy,omitempty"`
}

type Deploy struct {
	Environment string    `json:"environment"`
	Finished    time.Time `json:"finished"`
}

type LogSearchRequest struct {
	Window
	// Contains adds case-sensitive line filters (|= "...").
	Contains []string `json:"contains,omitempty"`
	// Pipeline is a LogQL pipeline appended after the service selector, e.g. `| json | level="error"`.
	Pipeline string `json:"pipeline,omitempty"`
	// Limit caps the number of sampled lines used for grouping.
	Limit int `json:"limit,omitempty"`
}

type LogSearchResult struct {
	Query string `json:"query"`
	// Total is the exact number of matching lines in the range.
	Total      int64 `json:"total"`
	SampleSize int   `json:"sampleSize"`
	// SampleRange is the time span of the sampled lines, which are the newest matches.
	SampleRange *TimeRange `json:"sampleRange,omitempty"`
	Groups      []LogGroup `json:"groups"`
	// Ungrouped counts sampled lines too short or too long to cluster.
	Ungrouped int `json:"ungrouped"`
}

type LogGroup struct {
	Index   int    `json:"index"`
	Pattern string `json:"pattern"`
	// SampleCount is the number of sampled lines in the group.
	SampleCount int `json:"sampleCount"`
	// EstimatedCount extrapolates SampleCount to Total.
	EstimatedCount int64     `json:"estimatedCount"`
	Example        string    `json:"example"`
	FirstSeen      time.Time `json:"firstSeen"`
	LastSeen       time.Time `json:"lastSeen"`
}

type LogQueryRequest struct {
	Window
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
	// Step applies to metric LogQL queries, e.g. "1m".
	Step string `json:"step,omitempty"`
}

type LogQueryResult struct {
	Query string `json:"query"`
	// Streams holds the label sets; each line refers to one by index.
	Streams []map[string]string `json:"streams,omitempty"`
	Lines   []LogLine           `json:"lines,omitempty"`
	Series  []Series            `json:"series,omitempty"`
}

type LogLine struct {
	Time   time.Time `json:"time"`
	Stream int       `json:"stream"`
	Line   string    `json:"line"`
}

type LogFields struct {
	Labels []LogLabel `json:"labels"`
	Fields []LogField `json:"fields,omitempty"`
}

type LogLabel struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
	// MoreValues is true when Values was cut.
	MoreValues bool `json:"moreValues,omitempty"`
}

type LogField struct {
	Name        string   `json:"name"`
	Type        string   `json:"type,omitempty"`
	Cardinality int      `json:"cardinality,omitempty"`
	Parsers     []string `json:"parsers,omitempty"`
}

type MetricQueryRequest struct {
	Window
	Query string `json:"query"`
	Step  string `json:"step,omitempty"`
}

type MetricResult struct {
	Query  string   `json:"query"`
	Step   string   `json:"step"`
	Series []Series `json:"series"`
}

type Series struct {
	Labels  map[string]string `json:"labels"`
	Summary SeriesSummary     `json:"summary"`
	Points  []Point           `json:"points,omitempty"`
}

// SeriesSummary is computed over finite values only. Pointer fields are nil when the
// series has no finite value.
type SeriesSummary struct {
	Count int      `json:"count"`
	Min   *float64 `json:"min,omitempty"`
	Max   *float64 `json:"max,omitempty"`
	Avg   *float64 `json:"avg,omitempty"`
	First *float64 `json:"first,omitempty"`
	Last  *float64 `json:"last,omitempty"`
}

// Point is encoded as [unixSeconds, value]. NaN and infinite values encode as null,
// because JSON has no representation for them.
type Point struct {
	Time  int64
	Value float64
}

func (p Point) MarshalJSON() ([]byte, error) {
	if math.IsNaN(p.Value) || math.IsInf(p.Value, 0) {
		return json.Marshal([]any{p.Time, nil})
	}
	return json.Marshal([]any{p.Time, p.Value})
}

func (p *Point) UnmarshalJSON(data []byte) error {
	var raw [2]*float64
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw[0] == nil {
		return fmt.Errorf("point without timestamp")
	}
	p.Time = int64(*raw[0])
	p.Value = math.NaN()
	if raw[1] != nil {
		p.Value = *raw[1]
	}
	return nil
}

type MetricInfo struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	Help string `json:"help,omitempty"`
}

type Overview struct {
	Releases *OverviewPart[[]Release] `json:"releases,omitempty"`
	Issues   *OverviewPart[[]Issue]   `json:"issues,omitempty"`
	Signals  []SignalOverview         `json:"signals,omitempty"`
}

// OverviewPart carries either items or the error that prevented loading them, so one
// failing source does not fail the whole overview.
type OverviewPart[T any] struct {
	Items T      `json:"items"`
	Error string `json:"error,omitempty"`
}

type SignalOverview struct {
	Name   string           `json:"name"`
	Series []LabeledSummary `json:"series,omitempty"`
	Error  string           `json:"error,omitempty"`
}

type LabeledSummary struct {
	Labels  map[string]string `json:"labels"`
	Summary SeriesSummary     `json:"summary"`
}

type ResultPage struct {
	Kind       string              `json:"kind"`
	Group      *int                `json:"group,omitempty"`
	Total      int                 `json:"total"`
	Offset     int                 `json:"offset"`
	NextOffset *int                `json:"nextOffset,omitempty"`
	Streams    []map[string]string `json:"streams,omitempty"`
	Lines      []LogLine           `json:"lines"`
}
