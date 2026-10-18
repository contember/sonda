package logql

import (
	"slices"
	"testing"
)

func selectorStrings(q Query) []string {
	var out []string
	for _, matchers := range q.Selectors() {
		out = append(out, FormatSelector(matchers))
	}
	return out
}

func TestParseFindsSelectors(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`{a="b"}`, []string{`{a="b"}`}},
		{`{}`, []string{`{}`}},
		{`{ a = "b" , c!~"d" }`, []string{`{a="b", c!~"d"}`}},
		{"{a=`b\\`}", []string{`{a="b\\"}`}},
		{`{a="x\"}"}`, []string{`{a="x\"}"}`}},
		{`{a="b"} |= "{c=\"d\"}"`, []string{`{a="b"}`}},
		{"{a=\"b\"} |= `{c=\"d\"}`", []string{`{a="b"}`}},
		{`{a="b"} | line_format "{{.c}}"`, []string{`{a="b"}`}},
		{"{a=\"b\"} # {c=\"d\"}", []string{`{a="b"}`}},
		{"# {c=\"d\"}\n{a=\"b\"}", []string{`{a="b"}`}},
		{"// {c=\"d\"}\n{a=\"b\"}", []string{`{a="b"}`}},
		{`/* {c="d"} */ {a="b"}`, []string{`{a="b"}`}},
		{`{a="b" /* , c="d" */}`, []string{`{a="b"}`}},
		{`sum(rate({a="b"}[5m])) /sum(rate({c="d"}[5m]))`, []string{`{a="b"}`, `{c="d"}`}},
		{`count_over_time({a="b"} | json | unwrap x [1h] offset 5m)`, []string{`{a="b"}`}},
	}
	for _, tt := range tests {
		q, err := Parse(tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if got := selectorStrings(q); !slices.Equal(got, tt.want) {
			t.Errorf("%s:\n got  %q\n want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{
		`{a=}`,
		`{a="b",}`,
		`{a=="b"}`,
		`{1a="b"}`,
		`{a="b" | c="d"}`,
		`{a="b"`,
		`{a="b"}}`,
		`{a='b'}`,
		`{a="b"} |= 'c'`,
		`{a="b"} |= "c`,
		"{a=\"b\"} |= \"c\nd\"",
		`{a="\q"}`,
		`{a="b"} /* {c="d"}`,
		`rate({a="b"}[{c="d"}])`,
		`rate({a="b"}[5m]`,
		`rate({a="b"}[5m]))`,
		`rate({a="b"} 5m])`,
		"{a=\"b\"} |= \"\xff\"",
		"{a=\"b\"} |= \"\uFEFF\"",
	} {
		if q, err := Parse(in); err == nil {
			t.Errorf("%s: accepted with selectors %q", in, selectorStrings(q))
		}
	}
}

func TestIsLogQuery(t *testing.T) {
	tests := []struct {
		in  string
		log bool
	}{
		{`{a="b"} | json`, true},
		{`(({a="b"} |= "x"))`, true},
		{`# comment` + "\n" + `{a="b"}`, true},
		{`rate({a="b"}[1m])`, false},
		{`(sum(rate({a="b"}[1m])))`, false},
		{`vector(1)`, false},
	}
	for _, tt := range tests {
		q, err := Parse(tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if q.IsLogQuery() != tt.log {
			t.Errorf("%s: log query = %v", tt.in, q.IsLogQuery())
		}
	}
}

func TestRewriteReplacesCommentsAndKeepsTheRest(t *testing.T) {
	q, err := Parse("{a=\"b\" /* x */} |= \"c\" # tail")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := q.Rewrite(nil), `{a="b"} |= "c"  `; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseSelector(t *testing.T) {
	for _, in := range []string{`{a="b"}`, ` {a="b"} `, "# c\n{a=\"b\"}"} {
		if _, err := ParseSelector(in); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	for _, in := range []string{`{a="b"} |= "x"`, `{a="b"} {c="d"}`, `({a="b"})`, ``} {
		if _, err := ParseSelector(in); err == nil {
			t.Errorf("%s: accepted", in)
		}
	}
}
