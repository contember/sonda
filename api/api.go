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
	CapabilityErrors    Capability = "errors"
	CapabilityLogs      Capability = "logs"
	CapabilityMetrics   Capability = "metrics"
	CapabilityTraces    Capability = "traces"
	CapabilityWorkloads Capability = "workloads"
	CapabilityAlerts    Capability = "alerts"
)

func ParseCapability(s string) (Capability, error) {
	switch c := Capability(s); c {
	case CapabilityErrors, CapabilityLogs, CapabilityMetrics, CapabilityTraces, CapabilityWorkloads, CapabilityAlerts:
		return c, nil
	}
	return "", fmt.Errorf("unknown capability %q (expected errors, logs, metrics, traces, workloads or alerts)", s)
}

// Dialect names the query language of a native query endpoint.
type Dialect string

const (
	DialectLogQL            Dialect = "logql"
	DialectPromQL           Dialect = "promql"
	DialectTraceQL          Dialect = "traceql"
	DialectCloudflareQuery  Dialect = "cloudflare-query"
	DialectCloudflareMetric Dialect = "cloudflare-metric"
	DialectLogsInsights     Dialect = "logs-insights"
	DialectCloudWatchMetric Dialect = "cloudwatch-metric"
)

// BackendInfo tells the agent which source type serves a capability and which query dialect
// its native query endpoint accepts. Dialect is empty for errors.
type BackendInfo struct {
	Source  string  `json:"source"`
	Dialect Dialect `json:"dialect,omitempty"`
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
	Name         string                     `json:"name"`
	Capabilities []Capability               `json:"capabilities"`
	Backends     map[Capability]BackendInfo `json:"backends,omitempty"`
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
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
	// Frames are newest first. Library frames are omitted when in-app frames exist.
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
	// Where adds field conditions, `field=value` or `field!=value`, combined by AND.
	Where []string `json:"where,omitempty"`
	// Pipeline is a LogQL pipeline appended after the service selector, e.g. `| json | level="error"`.
	// Only Loki sources accept it.
	Pipeline string `json:"pipeline,omitempty"`
	// Limit caps the number of sampled lines used for grouping.
	Limit int `json:"limit,omitempty"`
}

type LogSearchResult struct {
	Query string `json:"query"`
	// Total is the number of matching lines in the range: exact for Loki and CloudWatch, weighted
	// by sampling for Cloudflare.
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
	Releases  *OverviewPart[[]Release]        `json:"releases,omitempty"`
	Issues    *OverviewPart[[]Issue]          `json:"issues,omitempty"`
	Signals   []SignalOverview                `json:"signals,omitempty"`
	Workloads *OverviewPart[*WorkloadSummary] `json:"workloads,omitempty"`
	Alerts    *OverviewPart[[]Alert]          `json:"alerts,omitempty"`
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

type TraceSearchRequest struct {
	Window
	MinDuration string `json:"minDuration,omitempty"` // e.g. "500ms"
	MaxDuration string `json:"maxDuration,omitempty"`
	// Errors keeps only traces with an error span of the service.
	Errors bool `json:"errors,omitempty"`
	// Name keeps spans whose name contains the text.
	Name string `json:"name,omitempty"`
	// Where filters span attributes, `field=value` or `field!=value`, combined by AND.
	Where []string `json:"where,omitempty"`
	Limit int      `json:"limit,omitempty"`
}

type TraceQueryRequest struct {
	Window
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

type TraceSearchResult struct {
	Query  string         `json:"query"`
	Traces []TraceSummary `json:"traces"`
}

type TraceSummary struct {
	TraceID     string    `json:"traceId"`
	RootService string    `json:"rootService,omitempty"`
	RootName    string    `json:"rootName,omitempty"`
	Start       time.Time `json:"start"`
	DurationMs  float64   `json:"durationMs"`
	SpanCount   int       `json:"spanCount,omitempty"`
	ErrorCount  int       `json:"errorCount,omitempty"`
	Matched     []Span    `json:"matched,omitempty"`
}

type Trace struct {
	TraceID  string   `json:"traceId"`
	Services []string `json:"services"`
	// Spans are ordered depth-first from the roots, children by start time.
	Spans []Span `json:"spans"`
}

// Span of a trace. Granted is false for spans of services the identity cannot see; such
// spans keep only identifiers, service, timing and status.
type Span struct {
	SpanID        string            `json:"spanId"`
	ParentID      string            `json:"parentId,omitempty"`
	Depth         int               `json:"depth"`
	Service       string            `json:"service"`
	Granted       bool              `json:"granted"`
	Name          string            `json:"name,omitempty"`
	Kind          string            `json:"kind,omitempty"`
	Start         time.Time         `json:"start"`
	DurationMs    float64           `json:"durationMs"`
	Status        string            `json:"status,omitempty"`
	StatusMessage string            `json:"statusMessage,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	Events        []SpanEvent       `json:"events,omitempty"`
}

type SpanEvent struct {
	Time       time.Time         `json:"time"`
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes,omitempty"`
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

// Workloads is the current state of the service's pods and rollouts, and the events of its
// objects in the requested range.
type Workloads struct {
	Pods []Pod `json:"pods"`
	// Rollouts are the service's ReplicaSets, newest first.
	Rollouts []Rollout `json:"rollouts"`
	// Events are newest first; repeated events are counted, not listed.
	Events []WorkloadEvent `json:"events"`
}

type Pod struct {
	Name  string `json:"name"`
	Phase string `json:"phase"`
	Ready bool   `json:"ready"`
	// Restarts sums the container restarts since the pod was created.
	Restarts   int         `json:"restarts"`
	Owner      string      `json:"owner,omitempty"` // e.g. ReplicaSet/engine-api-7d9f
	Node       string      `json:"node,omitempty"`
	Started    *time.Time  `json:"started,omitempty"`
	Reason     string      `json:"reason,omitempty"` // e.g. Evicted
	Containers []Container `json:"containers"`
}

type Container struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	Ready    bool   `json:"ready"`
	Restarts int    `json:"restarts"`
	// State is running, waiting or terminated; Reason explains waiting and terminated states.
	State           string       `json:"state"`
	Reason          string       `json:"reason,omitempty"`
	Message         string       `json:"message,omitempty"`
	LastTermination *Termination `json:"lastTermination,omitempty"`
}

type Termination struct {
	Reason   string    `json:"reason,omitempty"` // e.g. OOMKilled, Error
	ExitCode int       `json:"exitCode"`
	Finished time.Time `json:"finished"`
	Message  string    `json:"message,omitempty"`
}

type Rollout struct {
	Name          string    `json:"name"`
	Owner         string    `json:"owner,omitempty"` // e.g. Deployment/engine-api
	Revision      string    `json:"revision,omitempty"`
	Images        []string  `json:"images"`
	Created       time.Time `json:"created"`
	Replicas      int       `json:"replicas"`
	ReadyReplicas int       `json:"readyReplicas"`
}

type WorkloadEvent struct {
	Type      string    `json:"type"` // Normal or Warning
	Reason    string    `json:"reason"`
	Object    string    `json:"object"` // e.g. Pod/engine-api-7d9f-x2k4p
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// WorkloadSummary condenses Workloads for the overview.
type WorkloadSummary struct {
	Pods     int `json:"pods"`
	Ready    int `json:"ready"`
	Restarts int `json:"restarts"`
	// Problems name pods that are not ready, wait or were terminated abnormally in the range.
	Problems []string `json:"problems,omitempty"`
	Warnings int      `json:"warnings"`
	// Rollout is the newest ReplicaSet with replicas.
	Rollout *Rollout `json:"rollout,omitempty"`
}

// Alert is an active alert of the service's alerting rules.
type Alert struct {
	Name string `json:"name"` // the alertname label
	// State is firing, pending, recovering, nodata or error.
	State string `json:"state"`
	// StateReason is Grafana's reason for the state, e.g. MissingSeries.
	StateReason string            `json:"stateReason,omitempty"`
	ActiveAt    *time.Time        `json:"activeAt,omitempty"`
	Value       string            `json:"value,omitempty"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
