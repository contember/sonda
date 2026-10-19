package shape

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/telemetry"
)

var traceBase = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func onlyService(name string) func(string) bool {
	return func(service string) bool { return service == name }
}

func testSpan(id, parent string, startMs int) telemetry.Span {
	return telemetry.Span{SpanID: id, ParentID: parent, Service: "app", Start: traceBase.Add(time.Duration(startMs) * time.Millisecond)}
}

type spanPosition struct {
	id    string
	depth int
}

func positions(spans []api.Span) []spanPosition {
	result := make([]spanPosition, len(spans))
	for i, span := range spans {
		result[i] = spanPosition{span.SpanID, span.Depth}
	}
	return result
}

func TestTraceOrder(t *testing.T) {
	tests := []struct {
		name  string
		spans []telemetry.Span
		want  []spanPosition
	}{
		{
			name: "children by start, depth first",
			spans: []telemetry.Span{
				testSpan("c2", "root", 20),
				testSpan("root", "", 0),
				testSpan("c1", "root", 10),
				testSpan("g1", "c1", 15),
			},
			want: []spanPosition{{"root", 0}, {"c1", 1}, {"g1", 2}, {"c2", 1}},
		},
		{
			name: "siblings with equal start ordered by span id",
			spans: []telemetry.Span{
				testSpan("root", "", 0),
				testSpan("b", "root", 5),
				testSpan("a", "root", 5),
			},
			want: []spanPosition{{"root", 0}, {"a", 1}, {"b", 1}},
		},
		{
			name: "orphans become roots ordered by start",
			spans: []telemetry.Span{
				testSpan("orphan", "missing", 30),
				testSpan("root", "", 10),
				testSpan("early", "gone", 0),
				testSpan("child", "orphan", 40),
			},
			want: []spanPosition{{"early", 0}, {"root", 0}, {"orphan", 0}, {"child", 1}},
		},
		{
			name: "duplicate span ids keep the first occurrence",
			spans: []telemetry.Span{
				testSpan("root", "", 0),
				testSpan("a", "root", 10),
				testSpan("a", "", 5),
			},
			want: []spanPosition{{"root", 0}, {"a", 1}},
		},
		{
			name: "cycle terminates and emits each span once",
			spans: []telemetry.Span{
				testSpan("root", "", 0),
				testSpan("a", "b", 10),
				testSpan("b", "a", 20),
				testSpan("self", "self", 30),
			},
			want: []spanPosition{{"root", 0}, {"a", 0}, {"b", 1}, {"self", 0}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace, truncated := Trace("t1", tt.spans, onlyService("app"), testRedactor(t), 100)
			if truncated {
				t.Error("truncated")
			}
			if got := positions(trace.Spans); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("order = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTraceTruncation(t *testing.T) {
	spans := []telemetry.Span{
		testSpan("root", "", 0),
		testSpan("b", "root", 20),
		testSpan("a", "root", 10),
		testSpan("a1", "a", 11),
	}
	tests := []struct {
		maxSpans      int
		want          []spanPosition
		wantTruncated bool
	}{
		{4, []spanPosition{{"root", 0}, {"a", 1}, {"a1", 2}, {"b", 1}}, false},
		{3, []spanPosition{{"root", 0}, {"a", 1}, {"a1", 2}}, true},
		{1, []spanPosition{{"root", 0}}, true},
	}
	for _, tt := range tests {
		trace, truncated := Trace("t1", spans, onlyService("app"), testRedactor(t), tt.maxSpans)
		if truncated != tt.wantTruncated {
			t.Errorf("maxSpans %d: truncated = %v", tt.maxSpans, truncated)
		}
		if got := positions(trace.Spans); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("maxSpans %d: order = %v, want %v", tt.maxSpans, got, tt.want)
		}
		if !reflect.DeepEqual(trace.Services, []string{"app"}) {
			t.Errorf("maxSpans %d: services = %v", tt.maxSpans, trace.Services)
		}
	}
}

func fullSpan(id, parent, service string) telemetry.Span {
	return telemetry.Span{
		TraceID:       "t1",
		SpanID:        id,
		ParentID:      parent,
		Service:       service,
		Name:          "GET /orders cust-7",
		Kind:          "server",
		Start:         traceBase,
		Duration:      1500 * time.Microsecond,
		Status:        telemetry.StatusError,
		StatusMessage: "failed for cust-7",
		Attributes:    map[string]string{"http.url": "https://u:pw@example.com/x", "customer": "cust-7", "body": strings.Repeat("x", 600)},
		Events: []telemetry.SpanEvent{
			{Time: traceBase, Name: "exception", Attributes: map[string]string{"message": "token=abc123 for cust-9"}},
		},
	}
}

func TestTraceGrantedAndStubSpans(t *testing.T) {
	spans := []telemetry.Span{
		fullSpan("root", "", "app"),
		fullSpan("db", "root", "database"),
	}
	trace, _ := Trace("t1", spans, onlyService("app"), testRedactor(t), 10)

	want := api.Trace{
		TraceID:  "t1",
		Services: []string{"app", "database"},
		Spans: []api.Span{
			{
				SpanID:        "root",
				Service:       "app",
				Granted:       true,
				Name:          "GET /orders cust-7",
				Kind:          "server",
				Start:         traceBase,
				DurationMs:    1.5,
				Status:        "error",
				StatusMessage: "failed for [REDACTED]",
				Attributes: map[string]string{
					"http.url": "https://[REDACTED]@example.com/x",
					"customer": "[REDACTED]",
					"body":     strings.Repeat("x", 500) + "…",
				},
				Events: []api.SpanEvent{
					{Time: traceBase, Name: "exception", Attributes: map[string]string{"message": "token=[REDACTED] for [REDACTED]"}},
				},
			},
			{
				SpanID:     "db",
				ParentID:   "root",
				Depth:      1,
				Service:    "database",
				Start:      traceBase,
				DurationMs: 1.5,
				Status:     "error",
			},
		},
	}
	if !reflect.DeepEqual(trace, want) {
		t.Errorf("trace =\n%+v\nwant\n%+v", trace, want)
	}
}

func TestTraceStatus(t *testing.T) {
	tests := []struct {
		in   telemetry.SpanStatus
		want string
	}{
		{telemetry.StatusOK, "ok"},
		{telemetry.StatusError, "error"},
		{telemetry.StatusUnset, ""},
		{"", ""},
	}
	for _, tt := range tests {
		span := testSpan("root", "", 0)
		span.Status = tt.in
		trace, _ := Trace("t1", []telemetry.Span{span}, onlyService("app"), testRedactor(t), 10)
		if got := trace.Spans[0].Status; got != tt.want {
			t.Errorf("status %q = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTraceEmpty(t *testing.T) {
	trace, truncated := Trace("t1", nil, onlyService("app"), testRedactor(t), 10)
	if truncated || trace.Services == nil || trace.Spans == nil || len(trace.Spans) != 0 {
		t.Errorf("trace = %+v, truncated = %v", trace, truncated)
	}
}

func TestTraceSummaries(t *testing.T) {
	traces := []telemetry.TraceSummary{
		{
			TraceID:     "visible",
			RootService: "app",
			RootName:    "GET /orders",
			Start:       traceBase,
			Duration:    2250 * time.Microsecond,
			SpanCount:   3,
			ErrorCount:  1,
			Matched:     []telemetry.Span{fullSpan("m1", "root", "app")},
		},
		{
			TraceID:     "hidden-root",
			RootService: "gateway",
			RootName:    "POST /internal/secret-route",
			Start:       traceBase,
			Duration:    time.Second,
		},
	}
	got := TraceSummaries(traces, onlyService("app"), testRedactor(t))
	if len(got) != 2 {
		t.Fatalf("summaries = %+v", got)
	}

	first := got[0]
	if first.RootName != "GET /orders" || first.DurationMs != 2.25 || first.SpanCount != 3 || first.ErrorCount != 1 {
		t.Errorf("first = %+v", first)
	}
	if len(first.Matched) != 1 {
		t.Fatalf("matched = %+v", first.Matched)
	}
	matched := first.Matched[0]
	if !matched.Granted || matched.Depth != 0 || matched.Name == "" || matched.Attributes["customer"] != "[REDACTED]" {
		t.Errorf("matched = %+v", matched)
	}

	second := got[1]
	if second.RootName != "" || second.RootService != "gateway" || second.DurationMs != 1000 || second.Matched != nil {
		t.Errorf("second = %+v", second)
	}
}

func testRedactor(t *testing.T) *Redactor {
	t.Helper()
	r, err := NewRedactor([]string{`cust-[0-9]+`})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
