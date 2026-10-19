// Package traceql finds the spanset filters of a TraceQL query without parsing the whole
// language. Outside strings a brace always opens a spanset filter, so a lexer that ends
// strings where Tempo's lexer ends them finds every filter Tempo evaluates. The lexer also
// requires every pipeline to start with a filter. Anything it does not understand is
// rejected rather than guessed.
package traceql

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Query is a lexed TraceQL query with the positions of its spanset filters.
type Query struct {
	text string
	// filters holds the byte spans of the filters' inner text, without the braces.
	filters []span
}

type span struct {
	start, end int
}

// Parse lexes a query and finds its spanset filters. It does not validate the rest of the
// query; Tempo does that when it runs the query.
func Parse(query string) (Query, error) {
	if err := checkInput(query); err != nil {
		return Query{}, err
	}
	l := &lexer{text: query, pipelineStart: true}
	if err := l.run(); err != nil {
		return Query{}, err
	}
	return Query{text: query, filters: l.filters}, nil
}

// Filters returns the inner text of every spanset filter, in query order.
func (q Query) Filters() []string {
	out := make([]string, len(q.filters))
	for i, f := range q.filters {
		out[i] = q.text[f.start:f.end]
	}
	return out
}

// Rewrite replaces the inner text of every spanset filter with what replace returns for it.
// Everything outside the filters is kept byte for byte.
func (q Query) Rewrite(replace func(inner string) string) string {
	var b strings.Builder
	pos := 0
	for _, f := range q.filters {
		b.WriteString(q.text[pos:f.start])
		b.WriteString(replace(q.text[f.start:f.end]))
		pos = f.end
	}
	b.WriteString(q.text[pos:])
	return b.String()
}

// checkInput rejects input that Tempo's scanner reports as an error or treats differently
// from this lexer, such as whitespace that is not Go whitespace.
func checkInput(query string) error {
	if !utf8.ValidString(query) {
		return errors.New("query is not valid UTF-8")
	}
	for _, r := range query {
		switch {
		case r == 0:
			return errors.New("query contains a NUL character")
		case r == '\uFEFF':
			return errors.New("query contains a byte order mark")
		case unicode.IsSpace(r) && !isSpace(r):
			return fmt.Errorf("query contains unsupported whitespace %U", r)
		}
	}
	return nil
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// callKeywords are the TraceQL functions and clauses whose parentheses hold arguments.
// Arguments never contain a pipeline, so no pipeline can start inside them.
var callKeywords = []string{
	"by", "select", "coalesce", "count", "avg", "min", "max", "sum", "with",
	"rate", "count_over_time", "min_over_time", "max_over_time", "avg_over_time",
	"sum_over_time", "quantile_over_time", "histogram_over_time", "compare", "topk", "bottomk",
}

type lexer struct {
	text    string
	pos     int
	filters []span
	// parens holds one entry per open parenthesis outside filters: true for a call.
	parens []bool
	// pipelineStart is set where a pipeline can start: at the beginning of the query and
	// after a grouping parenthesis. Tempo evaluates a pipeline that starts with by(),
	// select() or a scalar filter on all spans, so a pipeline must start with a filter.
	pipelineStart bool
}

func (l *lexer) eof() bool { return l.pos >= len(l.text) }

func (l *lexer) peekAt(offset int) byte {
	if l.pos+offset >= len(l.text) {
		return 0
	}
	return l.text[l.pos+offset]
}

func (l *lexer) errorf(format string, args ...any) error {
	return fmt.Errorf("at offset %d: %s", l.pos, fmt.Sprintf(format, args...))
}

func (l *lexer) run() error {
	for {
		l.skipSpace()
		if l.eof() {
			break
		}
		c := l.text[l.pos]
		if l.pipelineStart && c != '{' && c != '(' {
			return l.errorf("expected a spanset filter")
		}
		l.pipelineStart = false
		var err error
		switch c {
		case '{':
			err = l.filter()
		case '}':
			err = l.errorf("unexpected '}'")
		case '(':
			l.openParen()
		case ')':
			if len(l.parens) == 0 {
				return l.errorf("unexpected ')'")
			}
			l.parens = l.parens[:len(l.parens)-1]
			l.pos++
		default:
			err = l.other()
		}
		if err != nil {
			return err
		}
	}
	if l.pipelineStart {
		return l.errorf("expected a spanset filter")
	}
	if len(l.parens) != 0 {
		return l.errorf("missing ')'")
	}
	return nil
}

func (l *lexer) skipSpace() {
	for !l.eof() && isSpace(rune(l.text[l.pos])) {
		l.pos++
	}
}

func (l *lexer) openParen() {
	inCall := slices.Contains(l.parens, true)
	call := inCall || l.followsCallKeyword()
	l.parens = append(l.parens, call)
	l.pipelineStart = !call
	l.pos++
}

// followsCallKeyword reports whether the parenthesis at pos follows a call keyword that
// stands on its own. A keyword glued to a preceding quote or attribute character, as in
// .a"x"count(, may be part of an attribute name for Tempo, so it does not count.
func (l *lexer) followsCallKeyword() bool {
	end := l.pos
	for end > 0 && isSpace(rune(l.text[end-1])) {
		end--
	}
	start := end
	for start > 0 && isWordByte(l.text[start-1]) {
		start--
	}
	if start > 0 && !isSeparator(rune(l.text[start-1])) {
		return false
	}
	return slices.Contains(callKeywords, l.text[start:end])
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// isSeparator reports whether Tempo ends an attribute name at r.
func isSeparator(r rune) bool {
	return isSpace(r) || strings.ContainsRune("{}()=~!<>&|^,", r)
}

// other lexes a character that is neither a brace nor a parenthesis.
func (l *lexer) other() error {
	switch c := l.text[l.pos]; {
	case c == '"':
		return l.stringLiteral()
	case c == '`':
		return l.rawString()
	case c == '\'':
		return l.errorf("single-quoted literals are not supported")
	case c == '#' || c == '/' && (l.peekAt(1) == '/' || l.peekAt(1) == '*'):
		return l.errorf("comments are not supported")
	case c == '\\':
		return l.errorf("unexpected '\\'")
	}
	_, size := utf8.DecodeRuneInString(l.text[l.pos:])
	l.pos += size
	return nil
}

// filter reads "{...}" and records its inner text. Inside a filter Tempo's grammar allows
// neither braces nor unbalanced parentheses.
func (l *lexer) filter() error {
	l.pos++
	start := l.pos
	depth := 0
	for {
		if l.eof() {
			return l.errorf("missing '}'")
		}
		var err error
		switch l.text[l.pos] {
		case '}':
			if depth != 0 {
				return l.errorf("missing ')' in spanset filter")
			}
			l.filters = append(l.filters, span{start, l.pos})
			l.pos++
			return nil
		case '{':
			return l.errorf("unexpected '{' in spanset filter")
		case '(':
			depth++
			l.pos++
		case ')':
			if depth == 0 {
				return l.errorf("unexpected ')' in spanset filter")
			}
			depth--
			l.pos++
		default:
			err = l.other()
		}
		if err != nil {
			return err
		}
	}
}

// stringLiteral reads a double-quoted string with Go escapes. Tempo reads a quoted part of
// an attribute name such as span."a b" with other escape rules, but it ends at the same
// quote, so both readings agree on where the string ends.
func (l *lexer) stringLiteral() error {
	start := l.pos
	l.pos++
	for {
		if l.eof() {
			return l.errorf("string not terminated")
		}
		switch l.text[l.pos] {
		case '"':
			l.pos++
			if _, err := strconv.Unquote(l.text[start:l.pos]); err != nil {
				return fmt.Errorf("at offset %d: invalid string %s", start, l.text[start:l.pos])
			}
			return nil
		case '\n':
			return l.errorf("string not terminated")
		case '\\':
			l.pos++
			if l.eof() || l.text[l.pos] == '\n' {
				return l.errorf("string not terminated")
			}
			l.pos++
		default:
			l.pos++
		}
	}
}

// rawString reads a backquoted string. Within an attribute name Tempo reads a backquote as
// a plain character, so a raw string must follow a character that ends attribute names.
func (l *lexer) rawString() error {
	if l.pos > 0 && !isSeparator(rune(l.text[l.pos-1])) {
		return l.errorf("a raw string must follow whitespace or an operator")
	}
	end := strings.IndexByte(l.text[l.pos+1:], '`')
	if end < 0 {
		return l.errorf("string not terminated")
	}
	l.pos += end + 2
	return nil
}
