package tempo

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/contember/sonda/internal/telemetry"
)

type searchResponse struct {
	Traces []searchTrace `json:"traces"`
}

type searchTrace struct {
	TraceID           string                  `json:"traceID"`
	RootServiceName   string                  `json:"rootServiceName"`
	RootTraceName     string                  `json:"rootTraceName"`
	StartTimeUnixNano nanos                   `json:"startTimeUnixNano"`
	DurationMs        float64                 `json:"durationMs"`
	SpanSets          []searchSpanSet         `json:"spanSets"`
	ServiceStats      map[string]serviceStats `json:"serviceStats"`
}

// searchSpanSet deliberately omits the spanset attributes: by(...) puts the grouped values
// there, which can be values of other services' spans.
type searchSpanSet struct {
	Spans []searchSpan `json:"spans"`
}

type searchSpan struct {
	SpanID            string      `json:"spanID"`
	Name              string      `json:"name"`
	StartTimeUnixNano nanos       `json:"startTimeUnixNano"`
	DurationNanos     nanos       `json:"durationNanos"`
	Attributes        []attribute `json:"attributes"`
}

type serviceStats struct {
	SpanCount  int `json:"spanCount"`
	ErrorCount int `json:"errorCount"`
}

// summary converts a search result. A span that matched in several spansets is kept once.
func (t searchTrace) summary() (telemetry.TraceSummary, error) {
	traceID, err := normalizeID(t.TraceID, 16)
	if err != nil {
		return telemetry.TraceSummary{}, err
	}
	summary := telemetry.TraceSummary{
		TraceID:     traceID,
		RootService: t.RootServiceName,
		RootName:    t.RootTraceName,
		Start:       t.StartTimeUnixNano.time(),
		Duration:    time.Duration(t.DurationMs * float64(time.Millisecond)),
	}
	for _, stats := range t.ServiceStats {
		summary.SpanCount += stats.SpanCount
		summary.ErrorCount += stats.ErrorCount
	}
	seen := map[string]bool{}
	for _, set := range t.SpanSets {
		for _, s := range set.Spans {
			spanID, err := normalizeID(s.SpanID, 8)
			if err != nil {
				return telemetry.TraceSummary{}, err
			}
			if seen[spanID] {
				continue
			}
			seen[spanID] = true
			summary.Matched = append(summary.Matched, telemetry.Span{
				TraceID:    traceID,
				SpanID:     spanID,
				Name:       s.Name,
				Start:      s.StartTimeUnixNano.time(),
				Duration:   time.Duration(s.DurationNanos),
				Attributes: attributeMap(s.Attributes),
			})
		}
	}
	return summary, nil
}

type traceResponse struct {
	Trace otlpTrace `json:"trace"`
}

type otlpTrace struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource struct {
		Attributes []attribute `json:"attributes"`
	} `json:"resource"`
	ScopeSpans []struct {
		Spans []otlpSpan `json:"spans"`
	} `json:"scopeSpans"`
}

type otlpSpan struct {
	TraceID           string      `json:"traceId"`
	SpanID            string      `json:"spanId"`
	ParentSpanID      string      `json:"parentSpanId"`
	Name              string      `json:"name"`
	Kind              spanKind    `json:"kind"`
	StartTimeUnixNano nanos       `json:"startTimeUnixNano"`
	EndTimeUnixNano   nanos       `json:"endTimeUnixNano"`
	Attributes        []attribute `json:"attributes"`
	Events            []otlpEvent `json:"events"`
	Status            struct {
		Code    statusCode `json:"code"`
		Message string     `json:"message"`
	} `json:"status"`
}

type otlpEvent struct {
	TimeUnixNano nanos       `json:"timeUnixNano"`
	Name         string      `json:"name"`
	Attributes   []attribute `json:"attributes"`
}

// spans flattens the trace. The service of a span is its resource's service.name.
func (t otlpTrace) spans() ([]telemetry.Span, error) {
	var spans []telemetry.Span
	for _, rs := range t.ResourceSpans {
		service := attributeMap(rs.Resource.Attributes)["service.name"]
		for _, ss := range rs.ScopeSpans {
			for _, s := range ss.Spans {
				span, err := s.span(service)
				if err != nil {
					return nil, err
				}
				spans = append(spans, span)
			}
		}
	}
	return spans, nil
}

func (s otlpSpan) span(service string) (telemetry.Span, error) {
	traceID, err := normalizeID(s.TraceID, 16)
	if err != nil {
		return telemetry.Span{}, err
	}
	spanID, err := normalizeID(s.SpanID, 8)
	if err != nil {
		return telemetry.Span{}, err
	}
	var parentID string
	if s.ParentSpanID != "" {
		if parentID, err = normalizeID(s.ParentSpanID, 8); err != nil {
			return telemetry.Span{}, err
		}
	}
	span := telemetry.Span{
		TraceID:       traceID,
		SpanID:        spanID,
		ParentID:      parentID,
		Service:       service,
		Name:          s.Name,
		Kind:          string(s.Kind),
		Start:         s.StartTimeUnixNano.time(),
		Duration:      time.Duration(s.EndTimeUnixNano - s.StartTimeUnixNano),
		Status:        telemetry.StatusUnset,
		StatusMessage: s.Status.Message,
		Attributes:    attributeMap(s.Attributes),
	}
	// OTLP JSON omits a status code of 0, which means unset.
	if s.Status.Code != "" {
		span.Status = telemetry.SpanStatus(s.Status.Code)
	}
	for _, e := range s.Events {
		span.Events = append(span.Events, telemetry.SpanEvent{Time: e.TimeUnixNano.time(), Name: e.Name, Attributes: attributeMap(e.Attributes)})
	}
	return span, nil
}

// normalizeID returns an ID as lowercase hex of size bytes. Tempo writes IDs in hex,
// sometimes without leading zeros, or in base64 in OTLP JSON.
func normalizeID(id string, size int) (string, error) {
	lower := strings.ToLower(id)
	if lower != "" && len(lower) <= 2*size && strings.Trim(lower, "0123456789abcdef") == "" {
		return strings.Repeat("0", 2*size-len(lower)) + lower, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(id)
	if err != nil || len(decoded) != size {
		return "", fmt.Errorf("invalid ID %q", id)
	}
	return hex.EncodeToString(decoded), nil
}

// nanos is a nanosecond timestamp or duration, which OTLP JSON writes as a string and
// some encoders as a number.
type nanos int64

func (n *nanos) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return fmt.Errorf("invalid nanoseconds %s", data)
	}
	v, err := number.Int64()
	if err != nil {
		return fmt.Errorf("invalid nanoseconds %s", data)
	}
	*n = nanos(v)
	return nil
}

func (n nanos) time() time.Time { return time.Unix(0, int64(n)).UTC() }

// spanKind is an OTLP span kind, written as a number or as a name like SPAN_KIND_SERVER.
// It holds the short name, or is empty for an unspecified kind.
type spanKind string

var spanKinds = []string{"", "INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER"}

func (k *spanKind) UnmarshalJSON(data []byte) error {
	name, err := enumName(data, "SPAN_KIND_", spanKinds)
	if err != nil {
		return fmt.Errorf("invalid span kind %s", data)
	}
	*k = spanKind(name)
	return nil
}

// statusCode is an OTLP status code, written as a number or as a name like STATUS_CODE_ERROR.
type statusCode telemetry.SpanStatus

var statusCodes = []string{string(telemetry.StatusUnset), string(telemetry.StatusOK), string(telemetry.StatusError)}

func (c *statusCode) UnmarshalJSON(data []byte) error {
	name, err := enumName(data, "STATUS_CODE_", statusCodes)
	if err != nil {
		return fmt.Errorf("invalid status code %s", data)
	}
	*c = statusCode(name)
	return nil
}

// enumName maps an OTLP enum, given by number or by name, to names[number]. The names
// compare case-insensitively after the prefix.
func enumName(data []byte, prefix string, names []string) (string, error) {
	var number int
	if err := json.Unmarshal(data, &number); err == nil {
		if number < 0 || number >= len(names) {
			return "", fmt.Errorf("unknown value %d", number)
		}
		return names[number], nil
	}
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return "", err
	}
	short, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return "", fmt.Errorf("unknown value %q", name)
	}
	if short == "UNSPECIFIED" {
		return names[0], nil
	}
	for _, n := range names {
		if n != "" && strings.EqualFold(n, short) {
			return n, nil
		}
	}
	return "", fmt.Errorf("unknown value %q", name)
}

type attribute struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

// anyValue is an OTLP AnyValue. Exactly one field is set.
type anyValue struct {
	StringValue *string      `json:"stringValue"`
	IntValue    *json.Number `json:"intValue"`
	BoolValue   *bool        `json:"boolValue"`
	DoubleValue *float64     `json:"doubleValue"`
	BytesValue  *string      `json:"bytesValue"`
	ArrayValue  *struct {
		Values []anyValue `json:"values"`
	} `json:"arrayValue"`
	KvlistValue *struct {
		Values []attribute `json:"values"`
	} `json:"kvlistValue"`
}

// String renders the value as text. Arrays and key-value lists become JSON.
func (v anyValue) String() string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != nil:
		return v.IntValue.String()
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'g', -1, 64)
	case v.BytesValue != nil:
		return *v.BytesValue
	case v.ArrayValue != nil:
		items := make([]string, len(v.ArrayValue.Values))
		for i, item := range v.ArrayValue.Values {
			items[i] = item.String()
		}
		return jsonText(items)
	case v.KvlistValue != nil:
		return jsonText(attributeMap(v.KvlistValue.Values))
	}
	return ""
}

func jsonText(v any) string {
	encoded, _ := json.Marshal(v)
	return string(encoded)
}

func attributeMap(attributes []attribute) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	m := make(map[string]string, len(attributes))
	for _, a := range attributes {
		m[a.Key] = a.Value.String()
	}
	return m
}
