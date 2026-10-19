package insights

import (
	"slices"
	"strings"
	"testing"
)

func TestParseCommands(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`fields @timestamp, @message`, []string{"fields"}},
		{"fields @timestamp, @message\n| sort @timestamp desc\n| limit 20", []string{"fields", "sort", "limit"}},
		{`FILTER @message LIKE "x" | Stats count(*) by bin(5m)`, []string{"filter", "stats"}},
		{`filter @message like /source/`, []string{"filter"}},
		{`filter @message like /a|b/ | limit 1`, []string{"filter", "limit"}},
		{`filter @message not like /x/`, []string{"filter"}},
		{`filter f1 =~ /Exception/`, []string{"filter"}},
		{`filter lower(f1) like /x/`, []string{"filter"}},
		{`filter "source | x" = 'source | y'`, []string{"filter"}},
		{"filter `source` = \"a\"", []string{"filter"}},
		{"filter @`aws.tag.a:b-c` = \"my-stack\"", []string{"filter"}},
		{`filter x like "a\\b\nc"`, []string{"filter"}},
		{"# source logGroups()\nfields @message # | source\n| limit 5", []string{"fields", "limit"}},
		{`parse @message /user=(?<user>\S+)/ | stats count(*) by user`, []string{"parse", "stats"}},
		{"parse @message /(?<a>.*?),\n (?<b>.*)/ as x multi", []string{"parse"}},
		{`parse /(?<a>\d+)/`, []string{"parse"}},
		{`parse @message "user=*, method:*" as user, method`, []string{"parse"}},
		{`fields concat(a, /x/), b`, []string{"fields"}},
		{`filter requestId in (fields requestId | filter x = 1) | limit 3`, []string{"filter", "limit"}},
		{`filter logGroup in ["a", "b"] and x != -1.5 and !ispresent(y)`, []string{"filter"}},
		{`filter @message like /[a-z\]\[]+[^0-9]/`, []string{"filter"}},
		{`parse @message /(?<path>[^ ]+) [\[]x/`, []string{"parse"}},
	}
	for _, tt := range tests {
		q, err := Parse(tt.in)
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		if got := q.Commands(); !slices.Equal(got, tt.want) {
			t.Errorf("%q: commands %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseWords(t *testing.T) {
	tests := []struct {
		in     string
		has    []string
		hasNot []string
	}{
		{`filter @message like /source/`, []string{"filter", "message", "like"}, []string{"source"}},
		{`filter "source" = 'source'`, nil, []string{"source"}},
		{"filter `source` = 1 # source", nil, []string{"source"}},
		{`filter detail.source = "x"`, []string{"detail", "source"}, nil},
		{`filter @Source = "x"`, []string{"source"}, nil},
		{`filter x in (SOURCE '/aws/lambda/other' | fields x)`, []string{"source"}, nil},
		{`filter x = 1 | join left=a right=b where a.id=b.id (SOURCE '/aws/other')`, []string{"source", "join"}, nil},
		{`fields a | appendcols ( SOURCE lg | stats count(*) )`, []string{"source"}, nil},
		{"fields a\n|\n  sOuRcE logGroups()", []string{"source"}, nil},
	}
	for _, tt := range tests {
		q, err := Parse(tt.in)
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		words := q.Words()
		for _, w := range tt.has {
			if !slices.Contains(words, w) {
				t.Errorf("%q: words %q lack %q", tt.in, words, w)
			}
		}
		for _, w := range tt.hasNot {
			if slices.Contains(words, w) {
				t.Errorf("%q: words %q contain %q", tt.in, words, w)
			}
		}
	}
}

func TestParseNestedCommands(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`filter x in (fields x | lookup t x OUTPUT y | limit 1) | limit 2`, []string{"lookup", "limit"}},
		{`fields a | appendcols ( SOURCE lg | stats count(*) )`, []string{"stats"}},
		{`filter x in [1, 2] | stats count(*) by bin(5m)`, nil},
	}
	for _, tt := range tests {
		q, err := Parse(tt.in)
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		if got := q.NestedCommands(); !slices.Equal(got, tt.want) {
			t.Errorf("%q: nested commands %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseSourceStageCommands(t *testing.T) {
	for _, in := range []string{
		`SOURCE logGroups() | fields @message`,
		`source logGroups(namePrefix: ['/aws']) | fields @message`,
		` Source logGroups()`,
		"# comment\nSOURCE logGroups()",
		"fields @message\n| SOURCE logGroups()",
		"fields @message | # c\n source logGroups()",
	} {
		q, err := Parse(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if !slices.Contains(q.Commands(), "source") {
			t.Errorf("%q: commands %q lack source", in, q.Commands())
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{
		``,
		"   \n # only a comment",
		`fields a |`,
		`fields a || limit 1`,
		`| fields a`,
		`"fields" a`,
		"`fields` a",
		`fields.x a`,
		`fields a, (b`,
		`fields a, b)`,
		`filter x in [1, 2)`,
		`filter x = "a`,
		`filter x = 'a`,
		"filter `a = 1",
		"filter x = \"a\nb\"",
		`filter x = "a\"b"`,
		`filter x = 'a\'b'`,
		`filter x like /a\/b/`,
		"filter `a\\`b` = 1",
		`filter x like /abc`,
		`fields a / 2`,
		`fields a, b / c / d`,
		`filter x = /a/`,
		`fields like /a/`,
		`filter and like /a/`,
		`filter x like "a" | fields y / 2 / 3`,
		`filter x = 1; fields y`,
		`filter x = ${y}`,
		`filter x = {a}`,
		`filter x \ y`,
		`filter a in [1, /[/]x,/] | source logGroups() | filter c in [d, e like /[,/]/]`,
		`filter x like /[/]/`,
		`filter x like /[^/]/`,
		`filter x like /[a/`,
		`filter x like /[]/]/`,
		`filter x like /[^]/]/`,
		`filter x like /[[:alpha:]]/`,
		"filter x = 1 # comment\r| source logGroups()",
		"filter x = 1 # comment | source logGroups()",
		"filter x = 1 # comment\u0085| source logGroups()",
		"filter x = \x00",
		"filter x = \"\x01\"",
		"filter x = \xff",
		"filter ſource = 1",
		"fiKlter x",
		"filter x = 1",
	} {
		if q, err := Parse(in); err == nil {
			t.Errorf("%q: accepted with commands %q", in, q.Commands())
		}
	}
}

// stripBackslashes removes every backslash. On an accepted query this keeps the structure when
// regexes are read without classes, because no escape may hide a delimiter: a lexer that
// ignores escapes must agree. With classes, an escaped ']' does matter.
func stripBackslashes(s string) string { return strings.ReplaceAll(s, `\`, "") }

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`fields @timestamp, @message | sort @timestamp desc | limit 20`,
		`filter @message like /source/ | stats count(*) by bin(5m)`,
		`SOURCE logGroups() | fields @message`,
		`filter x in (SOURCE '/aws/x' | fields x)`,
		`parse @message /(?<a>\d+)/ | filter a like "x\\y"`,
		"# c\nfields `source`, @`a.b` | filter x = 'y'",
		`filter x like /a\/b/ | source logGroups() | filter y like /c/`,
		`filter x = "a\" | source logGroups() | filter y = "b"`,
		`filter a in [1, /[/]x,/] | source logGroups() | filter c in [d, e like /[,/]/]`,
		`filter x like /[a-z\]]+/ | filter y in (fields y | lookup t y OUTPUT z)`,
		`filter x like /[a-z\]\[]+[^0-9]/`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		q, err := Parse(input)
		if err != nil {
			return
		}
		commands, words := q.Commands(), q.Words()
		if len(commands) == 0 {
			t.Fatalf("%q: accepted without commands", input)
		}
		for _, command := range commands {
			if !slices.Contains(words, command) {
				t.Fatalf("%q: command %q is not among the words %q, so a word ban would miss it", input, command, words)
			}
		}
		classBlind, err := parse(input, true)
		if err != nil {
			t.Fatalf("%q: accepted, but rejected when regexes have no character classes: %v", input, err)
		}
		if !slices.Equal(classBlind.Commands(), commands) || !slices.Equal(classBlind.NestedCommands(), q.NestedCommands()) || !slices.Equal(classBlind.Words(), words) {
			t.Fatalf("%q: character classes change the structure", input)
		}
		stripped, err := parse(stripBackslashes(input), true)
		if err != nil {
			t.Fatalf("%q: accepted, but rejected without backslashes: %v", input, err)
		}
		if !slices.Equal(stripped.Commands(), commands) || !slices.Equal(stripped.Words(), words) {
			t.Fatalf("%q: escapes change the structure:\n got  %q %q\n want %q %q", input, stripped.Commands(), stripped.Words(), commands, words)
		}
	})
}
