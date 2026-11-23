// Package api defines the HTTP API contract shared by sonda-server and the sonda CLI.
// It must stay free of server dependencies, so the CLI stays small.
package api

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
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
	CapabilityImages    Capability = "images"
	CapabilityResources Capability = "resources"
	CapabilityAlerts    Capability = "alerts"
	CapabilityData      Capability = "data"
)

// Capabilities lists every capability in display order.
var Capabilities = []Capability{CapabilityErrors, CapabilityLogs, CapabilityMetrics, CapabilityTraces, CapabilityWorkloads, CapabilityImages, CapabilityResources, CapabilityAlerts, CapabilityData}

func ParseCapability(s string) (Capability, error) {
	if c := Capability(s); slices.Contains(Capabilities, c) {
		return c, nil
	}
	return "", fmt.Errorf("unknown capability %q (expected errors, logs, metrics, traces, workloads, images, resources, alerts or data)", s)
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
	DialectSentrySearch     Dialect = "sentry-search"
	DialectVercelKQL        Dialect = "vercel-kql"
	DialectContemberGraphQL Dialect = "contember-graphql"
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
	Project      string   `json:"project"`
	Description  string   `json:"description,omitempty"`
	Environments []string `json:"environments"`
	// Capabilities are granted in at least one environment; describe shows them per environment.
	Capabilities []CapabilitySummary `json:"capabilities"`
}

type CapabilitySummary struct {
	Name Capability `json:"name"`
	// Sources are the source types serving the capability across environments, e.g. loki.
	Sources []string `json:"sources"`
}

type ServiceDetail struct {
	Name         string              `json:"name"`
	Project      string              `json:"project"`
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
	// by sampling for Cloudflare, exact for Vercel up to a cap.
	Total int64 `json:"total"`
	// TotalLowerBound is true when the source stopped counting, so there are more than Total.
	TotalLowerBound bool `json:"totalLowerBound,omitempty"`
	SampleSize      int  `json:"sampleSize"`
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
	// Nodes are set only for a binding of a cluster's nodes; it has no pods or rollouts.
	Nodes []Node `json:"nodes,omitempty"`
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
	Name  string `json:"name"`
	Image string `json:"image"`
	// Digest is the manifest digest of the image the container runs (sha256:…), resolved by the
	// runtime even when Image names a tag. Empty until the image is pulled.
	Digest   string `json:"digest,omitempty"`
	Ready    bool   `json:"ready"`
	Restarts int    `json:"restarts"`
	// State is running, waiting or terminated; Reason explains waiting and terminated states.
	State           string       `json:"state"`
	Reason          string       `json:"reason,omitempty"`
	Message         string       `json:"message,omitempty"`
	LastTermination *Termination `json:"lastTermination,omitempty"`
	// Usage is the current use reported by the cluster's metrics API; absent without one.
	Usage *Usage `json:"usage,omitempty"`
}

// Usage is the CPU and memory a container or node uses now.
type Usage struct {
	CPUMillicores int64 `json:"cpuMillicores"`
	MemoryBytes   int64 `json:"memoryBytes"`
}

// Node is a node of a Kubernetes cluster.
type Node struct {
	Name          string    `json:"name"`
	Ready         bool      `json:"ready"`
	Unschedulable bool      `json:"unschedulable,omitempty"`
	Created       time.Time `json:"created"`
	// Problems are the conditions that are not in their healthy state, e.g. MemoryPressure or
	// Ready=False, with their reason.
	Problems         []string          `json:"problems,omitempty"`
	InstanceType     string            `json:"instanceType,omitempty"`
	Zone             string            `json:"zone,omitempty"`
	NodeGroup        string            `json:"nodeGroup,omitempty"`
	CapacityType     string            `json:"capacityType,omitempty"`
	KubeletVersion   string            `json:"kubeletVersion"`
	OSImage          string            `json:"osImage,omitempty"`
	ContainerRuntime string            `json:"containerRuntime,omitempty"`
	Allocatable      map[string]string `json:"allocatable,omitempty"`
	Taints           []string          `json:"taints,omitempty"`
	Usage            *Usage            `json:"usage,omitempty"`
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
	// State is the rollout state of an ECS deployment: COMPLETED, IN_PROGRESS or FAILED.
	State string `json:"state,omitempty"`
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
	// Nodes and NodesReady are set for a binding of a cluster's nodes.
	Nodes      int `json:"nodes,omitempty"`
	NodesReady int `json:"nodesReady,omitempty"`
}

// WorkloadObjects is the configuration of the objects that run a service: on Kubernetes its
// controllers and the objects that select its pods, on ECS the service and its task
// definitions. Values of environment variables and ConfigMaps are never included.
type WorkloadObjects struct {
	Controllers       []Controller       `json:"controllers"`
	Autoscalers       []Autoscaler       `json:"autoscalers,omitempty"`
	DisruptionBudgets []DisruptionBudget `json:"disruptionBudgets,omitempty"`
	Services          []NetworkService   `json:"services,omitempty"`
	Ingresses         []Ingress          `json:"ingresses,omitempty"`
	NetworkPolicies   []NetworkPolicy    `json:"networkPolicies,omitempty"`
	ConfigMaps        []ConfigMap        `json:"configMaps,omitempty"`
	Applications      []Application      `json:"applications,omitempty"`
	TaskDefinitions   []TaskDefinition   `json:"taskDefinitions,omitempty"`
}

// Controller is a Deployment, StatefulSet, DaemonSet, Job or CronJob, or an ECS service.
type Controller struct {
	Kind    string    `json:"kind"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	// Replicas is the desired count; nil for kinds without one.
	Replicas          *int   `json:"replicas,omitempty"`
	ReadyReplicas     int    `json:"readyReplicas,omitempty"`
	UpdatedReplicas   int    `json:"updatedReplicas,omitempty"`
	AvailableReplicas int    `json:"availableReplicas,omitempty"`
	Strategy          string `json:"strategy,omitempty"`
	Paused            bool   `json:"paused,omitempty"`
	// Jobs and CronJobs.
	Schedule     string     `json:"schedule,omitempty"`
	Suspended    bool       `json:"suspended,omitempty"`
	LastSchedule *time.Time `json:"lastSchedule,omitempty"`
	LastSuccess  *time.Time `json:"lastSuccess,omitempty"`
	Active       int        `json:"active,omitempty"`
	Succeeded    int        `json:"succeeded,omitempty"`
	Failed       int        `json:"failed,omitempty"`
	Started      *time.Time `json:"started,omitempty"`
	Completed    *time.Time `json:"completed,omitempty"`
	// Details are platform settings as text, e.g. the launch type or the load balancers of an
	// ECS service.
	Details    map[string]string `json:"details,omitempty"`
	Conditions []ObjectCondition `json:"conditions,omitempty"`
	Containers []ContainerSpec   `json:"containers,omitempty"`
}

type ObjectCondition struct {
	Type    string     `json:"type"`
	Status  string     `json:"status"`
	Reason  string     `json:"reason,omitempty"`
	Message string     `json:"message,omitempty"`
	Changed *time.Time `json:"changed,omitempty"`
}

// ContainerSpec is a container of a pod template or task definition. Env lists variable names
// only: a literal value can hold a secret.
type ContainerSpec struct {
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	Init     bool              `json:"init,omitempty"`
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
	Env      []string          `json:"env,omitempty"`
	// SecretEnv names the variables whose value comes from a secret store.
	SecretEnv []string `json:"secretEnv,omitempty"`
	// EnvFrom names the objects whose keys become variables, e.g. ConfigMap/engine-config.
	EnvFrom  []string          `json:"envFrom,omitempty"`
	Ports    []string          `json:"ports,omitempty"`
	Probes   map[string]string `json:"probes,omitempty"`
	LogGroup string            `json:"logGroup,omitempty"`
}

// Autoscaler is a HorizontalPodAutoscaler of one of the service's controllers.
type Autoscaler struct {
	Name            string            `json:"name"`
	Target          string            `json:"target"`
	MinReplicas     int               `json:"minReplicas"`
	MaxReplicas     int               `json:"maxReplicas"`
	CurrentReplicas int               `json:"currentReplicas"`
	DesiredReplicas int               `json:"desiredReplicas"`
	Metrics         []string          `json:"metrics,omitempty"`
	LastScale       *time.Time        `json:"lastScale,omitempty"`
	Conditions      []ObjectCondition `json:"conditions,omitempty"`
}

// DisruptionBudget is a PodDisruptionBudget that selects the service's pods.
type DisruptionBudget struct {
	Name               string `json:"name"`
	MinAvailable       string `json:"minAvailable,omitempty"`
	MaxUnavailable     string `json:"maxUnavailable,omitempty"`
	CurrentHealthy     int    `json:"currentHealthy"`
	DesiredHealthy     int    `json:"desiredHealthy"`
	ExpectedPods       int    `json:"expectedPods"`
	DisruptionsAllowed int    `json:"disruptionsAllowed"`
}

// NetworkService is a Kubernetes Service that selects the service's pods.
type NetworkService struct {
	Name              string            `json:"name"`
	Type              string            `json:"type"`
	Selector          map[string]string `json:"selector"`
	Ports             []string          `json:"ports"`
	ReadyEndpoints    int               `json:"readyEndpoints"`
	NotReadyEndpoints int               `json:"notReadyEndpoints"`
	LoadBalancer      []string          `json:"loadBalancer,omitempty"`
}

// Ingress keeps only the rules that route to the service's Services.
type Ingress struct {
	Name      string   `json:"name"`
	Class     string   `json:"class,omitempty"`
	Rules     []string `json:"rules"`
	TLSHosts  []string `json:"tlsHosts,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

// NetworkPolicy is a policy whose pod selector matches the service's pods, its rules as text.
type NetworkPolicy struct {
	Name        string   `json:"name"`
	PolicyTypes []string `json:"policyTypes"`
	Ingress     []string `json:"ingress,omitempty"`
	Egress      []string `json:"egress,omitempty"`
}

// ConfigMap is a ConfigMap the service's pods reference, with its keys and no values.
type ConfigMap struct {
	Name    string     `json:"name"`
	Keys    []string   `json:"keys,omitempty"`
	Created *time.Time `json:"created,omitempty"`
	// Missing is true when a pod template references a ConfigMap that does not exist.
	Missing bool `json:"missing,omitempty"`
}

// Application is the status of an Argo CD Application that manages the service's
// controllers. Resources lists only the service's own objects. A Shared Application also
// manages other objects: Sync and Health are then those of the service's own resources, and
// HealthMessage, OperationDetail and Conditions are left out.
type Application struct {
	Name            string            `json:"name"`
	Project         string            `json:"project,omitempty"`
	Shared          bool              `json:"shared,omitempty"`
	Sync            string            `json:"sync"`
	Revision        string            `json:"revision,omitempty"`
	Health          string            `json:"health"`
	HealthMessage   string            `json:"healthMessage,omitempty"`
	Operation       string            `json:"operation,omitempty"`
	OperationDetail string            `json:"operationDetail,omitempty"`
	OperationEnded  *time.Time        `json:"operationEnded,omitempty"`
	Reconciled      *time.Time        `json:"reconciled,omitempty"`
	Conditions      []ObjectCondition `json:"conditions,omitempty"`
	Resources       []AppResource     `json:"resources"`
}

type AppResource struct {
	Object string `json:"object"` // e.g. Deployment/engine-api
	Sync   string `json:"sync,omitempty"`
	Health string `json:"health,omitempty"`
}

// TaskDefinition is an ECS task definition a deployment of the service runs.
type TaskDefinition struct {
	Family        string          `json:"family"`
	Revision      int             `json:"revision"`
	Status        string          `json:"status"`
	Registered    *time.Time      `json:"registered,omitempty"`
	CPU           string          `json:"cpu,omitempty"`
	Memory        string          `json:"memory,omitempty"`
	NetworkMode   string          `json:"networkMode,omitempty"`
	Compatibility []string        `json:"compatibility,omitempty"`
	TaskRole      string          `json:"taskRole,omitempty"`
	ExecutionRole string          `json:"executionRole,omitempty"`
	Containers    []ContainerSpec `json:"containers"`
}

// ImagesRequest selects images of a service: those with Digests, or the newest Limit. An empty
// Repository means every repository of the service.
type ImagesRequest struct {
	Environment string
	Repository  string
	Digests     []string
	Limit       int
}

// Image is a container image in one of the service's registry repositories.
type Image struct {
	Repository string     `json:"repository"`
	Digest     string     `json:"digest"`
	Tags       []string   `json:"tags"`
	PushedAt   *time.Time `json:"pushedAt,omitempty"`
	SizeBytes  int64      `json:"sizeBytes,omitempty"`
	// LastPulled is the registry's record of the last pull; it lags by up to a day. For an
	// index it may record Sonda's own reads of the index manifest.
	LastPulled *time.Time `json:"lastPulled,omitempty"`
	// Artifact marks a manifest that is not a container image and so has no scan: "attestation"
	// (buildx provenance or SBOM of an image) or "build-cache" (a buildx cache export).
	Artifact string `json:"artifact,omitempty"`
	// Scan is the latest scan of this manifest, absent when the registry has none. An index (a
	// multi-platform image, or one pushed with attestations) is never scanned itself: Platforms
	// carry the scans of the image manifests it lists.
	Scan *ImageScan `json:"scan,omitempty"`
	// Platforms is present for an index only, [] when it lists no image manifest.
	Platforms []ImagePlatform `json:"platforms,omitzero"`
}

// ImagePlatform is an image manifest an index lists for one platform, attestations left out.
type ImagePlatform struct {
	Digest string `json:"digest"`
	// Platform is os/architecture[/variant] as the index states it, e.g. linux/arm64; empty
	// when it states none or not a plain lowercase name.
	Platform string `json:"platform"`
	// Scan is absent when the registry has no scan of the manifest.
	Scan *ImageScan `json:"scan,omitempty"`
}

// ImageScan is the registry's vulnerability scan of an image.
type ImageScan struct {
	// Status is e.g. COMPLETE, IN_PROGRESS, FAILED, UNSUPPORTED_IMAGE or ACTIVE (continuous
	// scanning); Description explains a failure.
	Status      string     `json:"status"`
	Description string     `json:"description,omitempty"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
	// SourceUpdatedAt is when the vulnerability database the scan used was last updated. A
	// basic scan runs at push, so it is as old as the push unless the image was scanned again.
	SourceUpdatedAt *time.Time `json:"sourceUpdatedAt,omitempty"`
	// Counts are the findings per severity of a scan with a result, e.g. {"CRITICAL": 1,
	// "HIGH": 4}; {} when it found none, absent while the scan has no result (in progress, failed).
	Counts map[string]int `json:"counts,omitzero"`
}

// ScanSeverities lists the severities of registry scan findings, most severe first.
var ScanSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED", "UNTRIAGED"}

// SeverityRank orders a severity by ScanSeverities; unknown severities come last.
func SeverityRank(severity string) int {
	if i := slices.Index(ScanSeverities, strings.ToUpper(severity)); i >= 0 {
		return i
	}
	return len(ScanSeverities)
}

// ImageFinding is one vulnerability the registry's scan found in an image.
type ImageFinding struct {
	// ID is the vulnerability ID, e.g. CVE-2024-1234 or a GHSA ID.
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Package  string `json:"package,omitempty"`
	Version  string `json:"version,omitempty"`
	// FixedIn is the first fixed version, when the scan reports it (enhanced scanning).
	FixedIn string `json:"fixedIn,omitempty"`
	URI     string `json:"uri,omitempty"`
	// Platform is the platform the finding is in, set for an index; see ImagePlatform.
	Platform string `json:"platform,omitempty"`
}

// ImageDetail is one image with its scan findings, most severe first.
type ImageDetail struct {
	Image
	Findings []ImageFinding `json:"findings"`
}

// Resources is the configuration state of the managed resources bound to a service: versions,
// upgrades, maintenance, backups and expiry. Every list is present, empty when nothing is bound.
type Resources struct {
	Databases    []Database          `json:"databases"`
	Caches       []Cache             `json:"caches"`
	Certificates []Certificate       `json:"certificates"`
	Functions    []Function          `json:"functions"`
	Clusters     []KubernetesCluster `json:"clusters"`
	// Events are the database events in the range, newest first.
	Events []ResourceEvent `json:"events"`
}

// Database is an RDS or Aurora DB cluster (Kind cluster) or a standalone DB instance (Kind
// instance).
type Database struct {
	Identifier    string `json:"identifier"`
	Kind          string `json:"kind"`
	Engine        string `json:"engine"`
	EngineVersion string `json:"engineVersion"`
	// VersionStatus is the status of the engine version in RDS, e.g. available or deprecated.
	VersionStatus string `json:"versionStatus,omitempty"`
	// Upgrades are the versions RDS can upgrade the engine to, split into minor and major.
	Upgrades Upgrades `json:"upgrades"`
	// Support lists the support periods of the engine's major version, e.g. the end of
	// standard support and of RDS Extended Support.
	Support []SupportPeriod `json:"support,omitempty"`
	// Lifecycle is the resource's own support setting, e.g. open-source-rds-extended-support.
	Lifecycle string `json:"lifecycle,omitempty"`
	Status    string `json:"status"`
	// Members are the instances of a cluster.
	Members []DatabaseInstance `json:"members,omitempty"`
	// Instance describes a standalone instance.
	Instance                *DatabaseInstance  `json:"instance,omitempty"`
	BackupRetentionDays     int                `json:"backupRetentionDays"`
	BackupWindow            string             `json:"backupWindow,omitempty"`
	MaintenanceWindow       string             `json:"maintenanceWindow,omitempty"`
	LatestRestorableTime    *time.Time         `json:"latestRestorableTime,omitempty"`
	EarliestRestorableTime  *time.Time         `json:"earliestRestorableTime,omitempty"`
	DeletionProtection      bool               `json:"deletionProtection"`
	AutoMinorVersionUpgrade bool               `json:"autoMinorVersionUpgrade"`
	StorageEncrypted        bool               `json:"storageEncrypted"`
	ParameterGroup          string             `json:"parameterGroup,omitempty"`
	PendingMaintenance      []MaintenanceItem  `json:"pendingMaintenance"`
	PendingModified         map[string]string  `json:"pendingModified,omitempty"`
	Snapshots               []DatabaseSnapshot `json:"snapshots"`
}

type Upgrades struct {
	Minor []string `json:"minor"`
	Major []string `json:"major"`
}

// SupportPeriod is one support period of an engine version, e.g. open-source-rds-standard-support.
type SupportPeriod struct {
	Name  string     `json:"name"`
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

// DatabaseInstance is a DB instance, alone or as a cluster member.
type DatabaseInstance struct {
	Identifier       string `json:"identifier"`
	Class            string `json:"class"`
	Writer           bool   `json:"writer,omitempty"`
	Status           string `json:"status"`
	AvailabilityZone string `json:"availabilityZone,omitempty"`
	MultiAZ          bool   `json:"multiAZ,omitempty"`
	EngineVersion    string `json:"engineVersion,omitempty"`
	StorageGB        int    `json:"storageGB,omitempty"`
	StorageType      string `json:"storageType,omitempty"`
	// ParameterApply is the apply status of the instance's parameter group, e.g. in-sync or
	// pending-reboot.
	ParameterApply string `json:"parameterApply,omitempty"`
	// CA is the certificate authority of the server certificate and CAValidTill its expiry.
	CA                 string            `json:"ca,omitempty"`
	CAValidTill        *time.Time        `json:"caValidTill,omitempty"`
	PendingMaintenance []MaintenanceItem `json:"pendingMaintenance,omitempty"`
}

// MaintenanceItem is a maintenance action that RDS or ElastiCache has scheduled or offers.
type MaintenanceItem struct {
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	// Status is the opt-in status (RDS) or the update action status (ElastiCache).
	Status           string     `json:"status,omitempty"`
	Severity         string     `json:"severity,omitempty"`
	AutoAppliedAfter *time.Time `json:"autoAppliedAfter,omitempty"`
	ForcedApplyDate  *time.Time `json:"forcedApplyDate,omitempty"`
	CurrentApplyDate *time.Time `json:"currentApplyDate,omitempty"`
	// ApplyBy is the date by which ElastiCache recommends applying the update.
	ApplyBy *time.Time `json:"applyBy,omitempty"`
}

type DatabaseSnapshot struct {
	Identifier string     `json:"identifier"`
	Type       string     `json:"type"` // automated, manual, awsbackup
	Created    *time.Time `json:"created,omitempty"`
	Status     string     `json:"status"`
	StorageGB  int        `json:"storageGB,omitempty"`
}

// Cache is an ElastiCache replication group.
type Cache struct {
	Identifier    string `json:"identifier"`
	Engine        string `json:"engine"`
	EngineVersion string `json:"engineVersion"`
	// NewerVersions are the engine versions ElastiCache offers above the current one, newest first.
	NewerVersions           []string          `json:"newerVersions"`
	Status                  string            `json:"status"`
	NodeType                string            `json:"nodeType,omitempty"`
	Members                 int               `json:"members"`
	MultiAZ                 bool              `json:"multiAZ"`
	AutomaticFailover       bool              `json:"automaticFailover"`
	SnapshotRetentionDays   int               `json:"snapshotRetentionDays"`
	SnapshotWindow          string            `json:"snapshotWindow,omitempty"`
	MaintenanceWindow       string            `json:"maintenanceWindow,omitempty"`
	TransitEncryption       bool              `json:"transitEncryption"`
	AtRestEncryption        bool              `json:"atRestEncryption"`
	AuthToken               bool              `json:"authToken"`
	AutoMinorVersionUpgrade bool              `json:"autoMinorVersionUpgrade"`
	PendingUpdates          []MaintenanceItem `json:"pendingUpdates"`
}

// Certificate is an ACM certificate. Sonda reads only its description, never the certificate
// or its key.
type Certificate struct {
	ARN       string     `json:"arn"`
	Domain    string     `json:"domain"`
	Names     []string   `json:"names,omitempty"`
	Status    string     `json:"status"`
	Type      string     `json:"type"` // AMAZON_ISSUED, IMPORTED, PRIVATE
	NotBefore *time.Time `json:"notBefore,omitempty"`
	NotAfter  *time.Time `json:"notAfter,omitempty"`
	// DaysLeft counts whole days until NotAfter; negative once expired.
	DaysLeft           *int     `json:"daysLeft,omitempty"`
	RenewalEligibility string   `json:"renewalEligibility,omitempty"`
	RenewalStatus      string   `json:"renewalStatus,omitempty"`
	RenewalFailure     string   `json:"renewalFailure,omitempty"`
	InUseBy            []string `json:"inUseBy"`
	KeyAlgorithm       string   `json:"keyAlgorithm,omitempty"`
}

// Function is a Lambda function's configuration. Environment holds variable names only.
type Function struct {
	Name             string   `json:"name"`
	Runtime          string   `json:"runtime,omitempty"`
	Architectures    []string `json:"architectures,omitempty"`
	PackageType      string   `json:"packageType,omitempty"`
	Handler          string   `json:"handler,omitempty"`
	MemoryMB         int      `json:"memoryMB,omitempty"`
	TimeoutSeconds   int      `json:"timeoutSeconds,omitempty"`
	State            string   `json:"state,omitempty"`
	StateReason      string   `json:"stateReason,omitempty"`
	LastUpdateStatus string   `json:"lastUpdateStatus,omitempty"`
	LastModified     string   `json:"lastModified,omitempty"`
	CodeSizeBytes    int64    `json:"codeSizeBytes,omitempty"`
	Layers           []Layer  `json:"layers,omitempty"`
	Environment      []string `json:"environment"`
	// EnvironmentError is true when Lambda could not decrypt the variables.
	EnvironmentError bool `json:"environmentError,omitempty"`
}

type Layer struct {
	ARN           string `json:"arn"`
	CodeSizeBytes int64  `json:"codeSizeBytes,omitempty"`
}

// KubernetesCluster is an EKS cluster with its add-ons.
type KubernetesCluster struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	PlatformVersion string `json:"platformVersion,omitempty"`
	Status          string `json:"status"`
	// SupportType is STANDARD or EXTENDED: whether the cluster enters extended support.
	SupportType string `json:"supportType,omitempty"`
	// StandardSupportEnd and ExtendedSupportEnd are the end dates of the cluster's version.
	StandardSupportEnd *time.Time    `json:"standardSupportEnd,omitempty"`
	ExtendedSupportEnd *time.Time    `json:"extendedSupportEnd,omitempty"`
	Health             []HealthIssue `json:"health,omitempty"`
	PublicEndpoint     bool          `json:"publicEndpoint"`
	PrivateEndpoint    bool          `json:"privateEndpoint"`
	Addons             []Addon       `json:"addons"`
}

type HealthIssue struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

type Addon struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Status  string        `json:"status"`
	Health  []HealthIssue `json:"health,omitempty"`
	// NewerVersions are the versions compatible with the cluster's version above the current
	// one, newest first; DefaultVersion is the one EKS installs by default.
	NewerVersions  []string `json:"newerVersions"`
	DefaultVersion string   `json:"defaultVersion,omitempty"`
}

// ResourceEvent is an RDS event of a bound cluster or instance.
type ResourceEvent struct {
	Time       time.Time `json:"time"`
	Source     string    `json:"source"` // e.g. db-cluster/shop-db
	Categories []string  `json:"categories,omitempty"`
	Message    string    `json:"message"`
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

// DataQueryRequest runs a read-only GraphQL query. Variables is a JSON object; Sonda inlines
// the variables into the query before it runs.
type DataQueryRequest struct {
	Environment string          `json:"env,omitempty"`
	Query       string          `json:"query"`
	Variables   json.RawMessage `json:"variables,omitempty"`
}

type DataQueryResult struct {
	// Query is the normalized query that ran: fragments and variables inlined.
	Query string `json:"query"`
	// Rows is the row budget the query uses: over every list and paginate field, the product
	// of the limits on its path. Single rows (get, has-one) are not counted.
	Rows int             `json:"rows"`
	Data json.RawMessage `json:"data"`
}

// DataSchema describes the entities an identity may read through the data endpoints. When
// the full schema would not fit the response limit, entities carry only their names and
// meta.truncated is set; ask again for chosen entities.
type DataSchema struct {
	Entities []DataEntity `json:"entities"`
	// Enums maps enum names used by the fields to their values.
	Enums map[string][]string `json:"enums,omitempty"`
}

type DataEntity struct {
	Name   string      `json:"name"`
	Fields []DataField `json:"fields"`
	// Unique lists the fields usable in get<Entity>(by: …).
	Unique []string `json:"unique,omitempty"`
}

// DataField is a column (Type set) or a relation (Target set).
type DataField struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Nullable bool   `json:"nullable,omitempty"`
	List     bool   `json:"list,omitempty"`
	Target   string `json:"target,omitempty"`
	Many     bool   `json:"many,omitempty"`
}
