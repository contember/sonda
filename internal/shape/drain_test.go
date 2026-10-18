package shape

import (
	"fmt"
	"strings"
	"testing"
)

func patterns(lines ...string) []string {
	d := newDrain()
	var out []string
	seen := map[*template]bool{}
	var order []*template
	for _, line := range lines {
		if t := d.train(line); t != nil && !seen[t] {
			seen[t] = true
			order = append(order, t)
		}
	}
	for _, t := range order {
		out = append(out, t.pattern())
	}
	return out
}

func TestDrainPatterns(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name: "values of logfmt keys become placeholders",
			lines: []string{
				`level=error msg="connection timeout" waited_ms=12 request=r1`,
				`level=error msg="connection timeout" waited_ms=40 request=r2`,
			},
			want: []string{`level=error msg="connection timeout" waited_ms=<_> request=<_>`},
		},
		{
			name: "whitespace is kept",
			lines: []string{
				"GET  /items/1\t200 12ms",
				"GET  /items/2\t200 30ms",
			},
			want: []string{"GET  <_>\t200 <_>"},
		},
		{
			name: "dissimilar lines with the same shape stay apart",
			lines: []string{
				`level=error msg="connection timeout" waited_ms=12 request=r1`,
				`level=info msg="request completed" path=/items/1 status=200`,
			},
			want: []string{
				`level=error msg="connection timeout" waited_ms=12 request=r1`,
				`level=info msg="request completed" path=/items/1 status=200`,
			},
		},
		{
			name: "JSON lines are grouped by their message",
			lines: []string{
				`{"level":"error","msg":"payment 17 failed for user 3","ts":1}`,
				`{"level":"error","msg":"payment 18 failed for user 9","ts":2}`,
			},
			want: []string{`payment <_> failed for user <_>`},
		},
		{
			name:  "JSON without a message field is grouped as text",
			lines: []string{`{"a": 1, "b": 2, "c": 3}`, `{"a": 4, "b": 2, "c": 3}`},
			want:  []string{`{"a": <_> "b": 2, "c": 3}`},
		},
	}
	for _, tt := range tests {
		got := patterns(tt.lines...)
		if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
			t.Errorf("%s:\n got  %q\n want %q", tt.name, got, tt.want)
		}
	}
}

func TestDrainSkipsShortAndLongLines(t *testing.T) {
	d := newDrain()
	if d.train("only three tokens") != nil {
		t.Error("short line was grouped")
	}
	if d.train(strings.Repeat("word ", maxTokens+1)) != nil {
		t.Error("long line was grouped")
	}
	if d.train(strings.TrimSpace(strings.Repeat("word ", maxTokens))) == nil {
		t.Error("line with the maximum token count was not grouped")
	}
}

func TestDrainKeepsTemplatesApartByFirstToken(t *testing.T) {
	var lines []string
	for i := range 3 {
		lines = append(lines, fmt.Sprintf("started job %d in 5ms", i), fmt.Sprintf("finished job %d in 5ms", i))
	}
	if got := patterns(lines...); len(got) != 2 {
		t.Errorf("patterns = %q", got)
	}
}
