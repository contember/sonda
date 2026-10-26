package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

const (
	queryPath = "/workers/observability/telemetry/query"
	keysPath  = "/workers/observability/telemetry/keys"
)

type queryResult struct {
	Events       *eventList          `json:"events"`
	Invocations  map[string][]event  `json:"invocations"`
	Calculations []calculationResult `json:"calculations"`
	Traces       []traceResult       `json:"traces"`
}

type eventList struct {
	Events []event `json:"events"`
}

type event struct {
	Metadata  eventMetadata   `json:"$metadata"`
	Workers   *workersEvent   `json:"$workers"`
	Source    json.RawMessage `json:"source"`
	Timestamp float64         `json:"timestamp"` // epoch ms
}

type eventMetadata struct {
	ID              string  `json:"id"`
	Service         string  `json:"service"`
	RequestID       string  `json:"requestId"`
	TraceID         string  `json:"traceId"`
	SpanID          string  `json:"spanId"`
	ParentSpanID    string  `json:"parentSpanId"`
	SpanName        string  `json:"spanName"`
	Duration        float64 `json:"duration"`  // ms
	StartTime       float64 `json:"startTime"` // epoch ms
	Message         string  `json:"message"`
	Level           string  `json:"level"`
	Error           string  `json:"error"`
	StatusCode      float64 `json:"statusCode"`
	URL             string  `json:"url"`
	Trigger         string  `json:"trigger"`
	Origin          string  `json:"origin"`
	TransactionName string  `json:"transactionName"`
	Type            string  `json:"type"`
}

type workersEvent struct {
	ScriptName     string         `json:"scriptName"`
	Outcome        string         `json:"outcome"`
	EventType      string         `json:"eventType"`
	Entrypoint     string         `json:"entrypoint"`
	ExecutionModel string         `json:"executionModel"`
	CPUTimeMs      float64        `json:"cpuTimeMs"`
	WallTimeMs     float64        `json:"wallTimeMs"`
	ScriptVersion  *scriptVersion `json:"scriptVersion"`
}

type scriptVersion struct {
	ID string `json:"id"`
}

type calculationResult struct {
	Calculation string            `json:"calculation"`
	Alias       string            `json:"alias"`
	Aggregates  []aggregate       `json:"aggregates"`
	Series      []calculationStep `json:"series"`
}

type calculationStep struct {
	Time string      `json:"time"`
	Data []aggregate `json:"data"`
}

type aggregate struct {
	Value  float64      `json:"value"`
	Groups []groupValue `json:"groups"`
}

type groupValue struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"` // string, number or boolean
}

type traceResult struct {
	TraceID             string   `json:"traceId"`
	RootSpanName        string   `json:"rootSpanName"`
	RootTransactionName string   `json:"rootTransactionName"`
	Services            []string `json:"services"`
	Spans               int      `json:"spans"`
	TraceDurationMs     float64  `json:"traceDurationMs"`
	TraceStartMs        float64  `json:"traceStartMs"`
	Errors              []string `json:"errors"`
}

// Key is an event field seen in the range.
type Key struct {
	Key        string  `json:"key"`
	Type       string  `json:"type"`
	LastSeenAt float64 `json:"lastSeenAt"`
}

func (c *Client) query(ctx context.Context, q policy.CloudflareQuery, r api.TimeRange) (queryResult, error) {
	body, err := q.Body(r)
	if err != nil {
		return queryResult{}, err
	}
	return call[queryResult](ctx, c, queryPath, body)
}

// Lines runs an events or invocations query and groups the events into streams. Invocation
// events carry their request ID as a label.
func (c *Client) Lines(ctx context.Context, scope authz.CloudflareScope, q policy.CloudflareQuery, r api.TimeRange) ([]telemetry.LogStream, error) {
	result, err := c.query(ctx, q, r)
	if err != nil {
		return nil, err
	}
	streams := newStreamSet()
	if result.Events != nil {
		for _, e := range result.Events.Events {
			if !e.inScope(scope) {
				return nil, c.outsideScope()
			}
			streams.add(e, "")
		}
	}
	requestIDs := make([]string, 0, len(result.Invocations))
	for id := range result.Invocations {
		requestIDs = append(requestIDs, id)
	}
	sort.Strings(requestIDs)
	for _, id := range requestIDs {
		for _, e := range result.Invocations[id] {
			if !e.inScope(scope) {
				return nil, c.outsideScope()
			}
			streams.add(e, id)
		}
	}
	return streams.list, nil
}

// Count runs a calculations query with one count and returns its value.
func (c *Client) Count(ctx context.Context, scope authz.CloudflareScope, q policy.CloudflareQuery, r api.TimeRange) (int64, error) {
	result, err := c.calculations(ctx, scope, q, r)
	if err != nil {
		return 0, err
	}
	// Cloudflare weights the count by each event's sample interval, so it estimates the total under sampling.
	var total float64
	if len(result.Calculations) > 0 {
		for _, a := range result.Calculations[0].Aggregates {
			total += a.Value
		}
	}
	return int64(math.Round(total)), nil
}

// Calculations runs a calculations query into a non-nil matrix. Each calculation and group
// becomes a series; a calculation without time buckets becomes one point at the range end.
func (c *Client) Calculations(ctx context.Context, scope authz.CloudflareScope, q policy.CloudflareQuery, r api.TimeRange) (model.Matrix, error) {
	result, err := c.calculations(ctx, scope, q, r)
	if err != nil {
		return nil, err
	}
	matrix := newMatrixBuilder()
	for _, calc := range result.Calculations {
		name := calc.Alias
		if name == "" {
			name = calc.Calculation
		}
		if len(calc.Series) == 0 {
			for _, a := range calc.Aggregates {
				matrix.add(calculationLabels(name, a.Groups), r.To, a.Value)
			}
			continue
		}
		for _, step := range calc.Series {
			at, err := time.Parse(time.RFC3339Nano, step.Time)
			if err != nil {
				return nil, apierr.Upstream("source %s returned an invalid series time %q", c.source.Name, step.Time)
			}
			for _, a := range step.Data {
				matrix.add(calculationLabels(name, a.Groups), at, a.Value)
			}
		}
	}
	return matrix.build(), nil
}

// calculations runs a calculations query grouped by service. Every aggregate must belong to the
// scoped script; the service group is removed from the result.
func (c *Client) calculations(ctx context.Context, scope authz.CloudflareScope, q policy.CloudflareQuery, r api.TimeRange) (queryResult, error) {
	result, err := c.query(ctx, q, r)
	if err != nil {
		return queryResult{}, err
	}
	for i := range result.Calculations {
		calc := &result.Calculations[i]
		if calc.Aggregates, err = c.scopedAggregates(scope, calc.Aggregates); err != nil {
			return queryResult{}, err
		}
		for j := range calc.Series {
			if calc.Series[j].Data, err = c.scopedAggregates(scope, calc.Series[j].Data); err != nil {
				return queryResult{}, err
			}
		}
	}
	return result, nil
}

// scopedAggregates strips the service group. An aggregate without one is accepted only with
// value 0, which is how a query without matches can come back, and is then dropped.
func (c *Client) scopedAggregates(scope authz.CloudflareScope, aggregates []aggregate) ([]aggregate, error) {
	kept := make([]aggregate, 0, len(aggregates))
	for _, a := range aggregates {
		groups, grouped, err := c.withoutService(scope, a.Groups)
		if err != nil {
			return nil, err
		}
		if !grouped {
			if a.Value != 0 {
				return nil, c.outsideScope()
			}
			continue
		}
		a.Groups = groups
		kept = append(kept, a)
	}
	return kept, nil
}

// withoutService removes the service group and reports whether there was one.
func (c *Client) withoutService(scope authz.CloudflareScope, groups []groupValue) ([]groupValue, bool, error) {
	grouped := false
	kept := make([]groupValue, 0, len(groups))
	for _, g := range groups {
		if g.Key != policy.CloudflareServiceKey {
			kept = append(kept, g)
			continue
		}
		if scalarText(g.Value) != scope.Script() {
			return nil, false, c.outsideScope()
		}
		grouped = true
	}
	return kept, grouped, nil
}

func calculationLabels(name string, groups []groupValue) model.Metric {
	labels := model.Metric{"calculation": model.LabelValue(name)}
	for _, g := range groups {
		labels[model.LabelName(g.Key)] = model.LabelValue(scalarText(g.Value))
	}
	return labels
}

// Traces runs a traces query. Every trace must involve the scoped script.
func (c *Client) Traces(ctx context.Context, scope authz.CloudflareScope, q policy.CloudflareQuery, r api.TimeRange) ([]telemetry.TraceSummary, error) {
	result, err := c.query(ctx, q, r)
	if err != nil {
		return nil, err
	}
	summaries := make([]telemetry.TraceSummary, 0, len(result.Traces))
	for _, t := range result.Traces {
		if !slices.Contains(t.Services, scope.Script()) {
			return nil, c.outsideScope()
		}
		summaries = append(summaries, traceSummary(t))
	}
	return summaries, nil
}

func traceSummary(t traceResult) telemetry.TraceSummary {
	summary := telemetry.TraceSummary{
		TraceID:    t.TraceID,
		RootName:   t.RootSpanName,
		Start:      fromMillis(t.TraceStartMs),
		Duration:   millis(t.TraceDurationMs),
		SpanCount:  t.Spans,
		ErrorCount: len(t.Errors),
	}
	if summary.RootName == "" {
		summary.RootName = t.RootTransactionName
	}
	// The summary does not say which service owns the root span, unless only one is involved.
	if len(t.Services) == 1 {
		summary.RootService = t.Services[0]
	}
	return summary
}

// Trace runs a trace-by-ID events query and returns its spans. It is not scope-checked: the
// caller verifies that the trace contains a span of the scoped script.
func (c *Client) Trace(ctx context.Context, q policy.CloudflareQuery, r api.TimeRange) ([]telemetry.Span, error) {
	result, err := c.query(ctx, q, r)
	if err != nil {
		return nil, err
	}
	if result.Events == nil {
		return nil, nil
	}
	if len(result.Events.Events) >= q.Limit() {
		return nil, apierr.New(api.CodeLimitExceeded, "trace has at least %d spans, more than one fetch returns", q.Limit())
	}
	var spans []telemetry.Span
	seen := map[string]bool{}
	for _, e := range result.Events.Events {
		if e.Metadata.SpanID == "" || e.Metadata.SpanName == "" || seen[e.Metadata.SpanID] {
			continue
		}
		seen[e.Metadata.SpanID] = true
		spans = append(spans, span(e))
	}
	return spans, nil
}

func span(e event) telemetry.Span {
	start := e.Metadata.StartTime
	if start == 0 {
		start = e.Timestamp
	}
	s := telemetry.Span{
		TraceID:    e.Metadata.TraceID,
		SpanID:     e.Metadata.SpanID,
		ParentID:   e.Metadata.ParentSpanID,
		Service:    e.service(),
		Name:       e.Metadata.SpanName,
		Start:      fromMillis(start),
		Duration:   millis(e.Metadata.Duration),
		Status:     telemetry.StatusUnset,
		Attributes: e.attributes(),
	}
	if e.Metadata.Error != "" {
		s.Status, s.StatusMessage = telemetry.StatusError, e.Metadata.Error
	}
	return s
}

// attributes keeps the scalar fields that the span fields do not already carry, keyed by
// their Cloudflare filter keys.
func (e event) attributes() map[string]string {
	attributes := map[string]string{}
	set := func(key, value string) {
		if value != "" {
			attributes[key] = value
		}
	}
	setNumber := func(key string, value float64) {
		if value != 0 {
			attributes[key] = strconv.FormatFloat(value, 'f', -1, 64)
		}
	}
	set("$metadata.requestId", e.Metadata.RequestID)
	set("$metadata.trigger", e.Metadata.Trigger)
	set("$metadata.url", e.Metadata.URL)
	set("$metadata.origin", e.Metadata.Origin)
	set("$metadata.transactionName", e.Metadata.TransactionName)
	set("$metadata.type", e.Metadata.Type)
	set("$metadata.level", e.Metadata.Level)
	set("$metadata.message", e.Metadata.Message)
	setNumber("$metadata.statusCode", e.Metadata.StatusCode)
	if w := e.Workers; w != nil {
		set("$workers.outcome", w.Outcome)
		set("$workers.eventType", w.EventType)
		set("$workers.entrypoint", w.Entrypoint)
		set("$workers.executionModel", w.ExecutionModel)
		setNumber("$workers.cpuTimeMs", w.CPUTimeMs)
		setNumber("$workers.wallTimeMs", w.WallTimeMs)
		if w.ScriptVersion != nil {
			set("$workers.scriptVersion.id", w.ScriptVersion.ID)
		}
	}
	return attributes
}

// Keys lists the event fields of the scoped script in the range.
func (c *Client) Keys(ctx context.Context, scope authz.CloudflareScope, r api.TimeRange) ([]Key, error) {
	body, err := policy.CloudflareKeys(scope, r)
	if err != nil {
		return nil, err
	}
	return call[[]Key](ctx, c, keysPath, body)
}

// outsideScope is the defense-in-depth error: queries filter by script, so data of another
// script means the filter did not apply.
func (c *Client) outsideScope() error {
	return apierr.New(api.CodeInternal, "source %s returned data outside the scope", c.source.Name)
}

func (e event) inScope(scope authz.CloudflareScope) bool {
	return e.service() == scope.Script() && (e.Workers == nil || e.Workers.ScriptName == scope.Script())
}

func (e event) service() string {
	if e.Metadata.Service != "" || e.Workers == nil {
		return e.Metadata.Service
	}
	return e.Workers.ScriptName
}

// line is the log message, or the raw payload when the event has none.
func (e event) line() string {
	if e.Metadata.Message != "" {
		return e.Metadata.Message
	}
	return scalarText(e.Source)
}

// scalarText renders a JSON string unquoted and any other JSON value compactly.
func scalarText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return string(raw)
	}
	return compact.String()
}

// streamKey is the label set of a stream; empty fields are left out of the labels.
type streamKey struct {
	service, level, outcome, eventType, scriptVersion, requestID string
}

func (k streamKey) labels() map[string]string {
	labels := map[string]string{}
	for name, value := range map[string]string{
		"service":       k.service,
		"level":         k.level,
		"outcome":       k.outcome,
		"eventType":     k.eventType,
		"scriptVersion": k.scriptVersion,
		"requestId":     k.requestID,
	} {
		if value != "" {
			labels[name] = value
		}
	}
	return labels
}

type streamSet struct {
	list  []telemetry.LogStream
	index map[streamKey]int
}

func newStreamSet() *streamSet {
	return &streamSet{index: map[streamKey]int{}}
}

func (s *streamSet) add(e event, requestID string) {
	key := streamKey{service: e.service(), level: e.Metadata.Level, requestID: requestID}
	if w := e.Workers; w != nil {
		key.outcome, key.eventType = w.Outcome, w.EventType
		if w.ScriptVersion != nil {
			key.scriptVersion = w.ScriptVersion.ID
		}
	}
	i, ok := s.index[key]
	if !ok {
		i = len(s.list)
		s.index[key] = i
		s.list = append(s.list, telemetry.LogStream{Labels: key.labels()})
	}
	s.list[i].Entries = append(s.list[i].Entries, telemetry.LogEntry{Time: fromMillis(e.Timestamp), Line: e.line()})
}

type matrixBuilder struct {
	streams map[model.Fingerprint]*model.SampleStream
}

func newMatrixBuilder() *matrixBuilder {
	return &matrixBuilder{streams: map[model.Fingerprint]*model.SampleStream{}}
}

func (b *matrixBuilder) add(labels model.Metric, at time.Time, value float64) {
	fingerprint := labels.Fingerprint()
	stream, ok := b.streams[fingerprint]
	if !ok {
		stream = &model.SampleStream{Metric: labels}
		b.streams[fingerprint] = stream
	}
	stream.Values = append(stream.Values, model.SamplePair{Timestamp: model.TimeFromUnixNano(at.UnixNano()), Value: model.SampleValue(value)})
}

// build returns a non-nil matrix with each series sorted by time.
func (b *matrixBuilder) build() model.Matrix {
	matrix := model.Matrix{}
	for _, stream := range b.streams {
		sort.Slice(stream.Values, func(i, j int) bool { return stream.Values[i].Timestamp < stream.Values[j].Timestamp })
		matrix = append(matrix, stream)
	}
	return matrix
}

func fromMillis(ms float64) time.Time {
	return time.UnixMicro(int64(ms * 1000)).UTC()
}

func millis(ms float64) time.Duration {
	return time.Duration(ms * float64(time.Millisecond))
}
