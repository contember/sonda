package shape

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/telemetry"
)

func TestRedact(t *testing.T) {
	r, err := NewRedactor([]string{`cust-[0-9]+`})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ in, want string }{
		{`Authorization: Bearer abc.def-123`, `Authorization: Bearer [REDACTED]`},
		{`connecting to postgres://app:s3cret@db:5432/main`, `connecting to postgres://[REDACTED]@db:5432/main`},
		{`key AKIAIOSFODNN7EXAMPLE used`, `key [REDACTED] used`},
		{`password=hunter2 user=bob`, `password=[REDACTED] user=bob`},
		{`{"api_key": "xyz123", "n": 1}`, `{"api_key": "[REDACTED]", "n": 1}`},
		{`jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4`, `jwt [REDACTED]`},
		{`customer cust-42 failed`, `customer [REDACTED] failed`},
		{`plain message`, `plain message`},
	}
	for _, tt := range tests {
		if got := r.Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestGroupLines(t *testing.T) {
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var lines []api.LogLine
	for i := range 30 {
		text := fmt.Sprintf("level=error msg=\"connection timeout\" waited_ms=%d request=r%d", i*7, i)
		if i%3 == 0 {
			text = fmt.Sprintf("level=info msg=\"request completed\" path=/items/%d status=200", i)
		}
		lines = append(lines, api.LogLine{Time: base.Add(-time.Duration(i) * time.Second), Line: text})
	}
	lines = append(lines, api.LogLine{Time: base, Line: "ok"})

	g := GroupLines(lines, 310)
	if len(g.Groups) != 2 {
		t.Fatalf("groups = %+v", g.Groups)
	}
	first := g.Groups[0]
	if first.SampleCount != 20 || first.EstimatedCount != 200 || !strings.Contains(first.Pattern, "connection timeout") {
		t.Errorf("first group = %+v", first)
	}
	if g.Ungrouped != 1 || g.Assignment[len(lines)-1] != -1 {
		t.Errorf("short line not ungrouped: %d", g.Ungrouped)
	}
	if g.Assignment[0] != 1 || g.Assignment[1] != 0 {
		t.Errorf("assignment = %v", g.Assignment[:3])
	}
}

func TestFitLines(t *testing.T) {
	lines := []api.LogLine{{Line: strings.Repeat("a", 100)}, {Line: strings.Repeat("b", 100)}, {Line: "c"}}
	kept, truncated := FitLines(lines, 200)
	if len(kept) != 1 || !truncated {
		t.Errorf("kept %d, truncated %v", len(kept), truncated)
	}
	kept, truncated = FitLines(lines[:1], 10)
	if len(kept) != 1 || truncated {
		t.Errorf("first line must always be kept")
	}
}

func TestFlatten(t *testing.T) {
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	streams := []telemetry.LogStream{
		{Labels: map[string]string{"app": "a"}, Entries: []telemetry.LogEntry{{Time: base, Line: "old"}}},
		{Labels: map[string]string{"app": "b"}, Entries: []telemetry.LogEntry{
			{Time: base.Add(time.Second), Line: "password=hunter2"},
			{Time: base.Add(2 * time.Second), Line: strings.Repeat("x", maxLineLength+1)},
		}},
	}
	sample := Flatten(streams, r)
	if len(sample.Streams) != 2 || sample.Streams[1]["app"] != "b" {
		t.Fatalf("streams = %v", sample.Streams)
	}
	want := []api.LogLine{
		{Time: base.Add(2 * time.Second), Stream: 1, Line: strings.Repeat("x", maxLineLength) + "…"},
		{Time: base.Add(time.Second), Stream: 1, Line: "password=[REDACTED]"},
		{Time: base, Stream: 0, Line: "old"},
	}
	if !reflect.DeepEqual(sample.Lines, want) {
		t.Errorf("lines = %v, want %v", sample.Lines, want)
	}
}
