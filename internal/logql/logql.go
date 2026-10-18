// Package logql finds the stream selectors of a LogQL query without parsing the whole
// language. Braces outside strings, comments and ranges only ever open a stream selector,
// so a lexer that skips those exactly like Loki's lexer finds every selector Loki executes.
// Anything the lexer does not understand is rejected rather than guessed.
package logql

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
)

// Query is a lexed LogQL query with the positions of its stream selectors.
type Query struct {
	text      string
	selectors []selector
	// comments holds the byte spans of comments outside selectors, which Rewrite replaces
	// with a space. Comments inside a selector disappear when it is serialized.
	comments []span
	tokens   int
	logQuery bool
}

type span struct {
	start, end int
}

type selector struct {
	span
	matchers []*labels.Matcher
}

// Parse lexes a query and parses its stream selectors. It does not validate the rest of the
// query; Loki does that when it runs the query.
func Parse(query string) (Query, error) {
	if err := checkInput(query); err != nil {
		return Query{}, err
	}
	l := &lexer{text: query}
	if err := l.run(); err != nil {
		return Query{}, err
	}
	return Query{text: query, selectors: l.selectors, comments: l.comments, tokens: l.tokens, logQuery: l.logQuery}, nil
}

// ParseSelector parses a query that consists of exactly one stream selector.
func ParseSelector(text string) ([]*labels.Matcher, error) {
	q, err := Parse(text)
	if err != nil {
		return nil, err
	}
	if len(q.selectors) != 1 || q.tokens != 1 {
		return nil, errors.New("expected a single stream selector")
	}
	return q.selectors[0].matchers, nil
}

// Selectors returns the matchers of every stream selector, in query order.
func (q Query) Selectors() [][]*labels.Matcher {
	out := make([][]*labels.Matcher, len(q.selectors))
	for i, s := range q.selectors {
		out[i] = s.matchers
	}
	return out
}

// IsLogQuery reports whether the query returns log lines. A log query is a selector with an
// optional pipeline, possibly in parentheses; everything else returns series.
func (q Query) IsLogQuery() bool { return q.logQuery }

// Rewrite replaces every selector with the matchers that replace returns for it, and every
// comment with a space, so the result can be embedded in a larger query. Everything else is
// kept byte for byte. A nil replace keeps the matchers.
func (q Query) Rewrite(replace func([]*labels.Matcher) []*labels.Matcher) string {
	var b strings.Builder
	pos := 0
	si, ci := 0, 0
	for si < len(q.selectors) || ci < len(q.comments) {
		if ci < len(q.comments) && (si == len(q.selectors) || q.comments[ci].start < q.selectors[si].start) {
			c := q.comments[ci]
			b.WriteString(q.text[pos:c.start])
			b.WriteString(" ")
			pos = c.end
			ci++
			continue
		}
		s := q.selectors[si]
		matchers := s.matchers
		if replace != nil {
			matchers = replace(matchers)
		}
		b.WriteString(q.text[pos:s.start])
		b.WriteString(FormatSelector(matchers))
		pos = s.end
		si++
	}
	b.WriteString(q.text[pos:])
	return b.String()
}

// FormatSelector serializes matchers as a LogQL stream selector.
func FormatSelector(matchers []*labels.Matcher) string {
	parts := make([]string, len(matchers))
	for i, m := range matchers {
		parts[i] = m.Name + m.Type.String() + strconv.Quote(m.Value)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// checkInput rejects input that Loki's scanner reports as an error, so the lexers never
// disagree about where a token ends.
func checkInput(query string) error {
	if !utf8.ValidString(query) {
		return errors.New("query is not valid UTF-8")
	}
	if strings.ContainsRune(query, 0) {
		return errors.New("query contains a NUL character")
	}
	if strings.ContainsRune(query, '\uFEFF') {
		return errors.New("query contains a byte order mark")
	}
	return nil
}

type lexer struct {
	text      string
	pos       int
	depth     int
	selectors []selector
	comments  []span
	// tokens counts the tokens outside selectors plus one per selector.
	tokens     int
	inSelector bool
	// sawToken is set by the first token that is not an opening parenthesis.
	sawToken bool
	logQuery bool
}

func (l *lexer) peek() rune {
	r, _ := utf8.DecodeRuneInString(l.text[l.pos:])
	return r
}

func (l *lexer) peekAt(offset int) byte {
	if l.pos+offset >= len(l.text) {
		return 0
	}
	return l.text[l.pos+offset]
}

func (l *lexer) eof() bool { return l.pos >= len(l.text) }

func (l *lexer) errorf(format string, args ...any) error {
	return fmt.Errorf("at offset %d: %s", l.pos, fmt.Sprintf(format, args...))
}

func (l *lexer) run() error {
	for {
		if err := l.skipSpace(); err != nil {
			return err
		}
		if l.eof() {
			break
		}
		l.tokens++
		r := l.peek()
		if r != '(' && !l.sawToken {
			l.sawToken = true
			l.logQuery = r == '{'
		}
		var err error
		switch r {
		case '{':
			err = l.selector()
		case '}':
			err = l.errorf("unexpected '}'")
		case '(':
			l.depth++
			l.pos++
		case ')':
			if l.depth == 0 {
				return l.errorf("unexpected ')'")
			}
			l.depth--
			l.pos++
		case '[':
			err = l.rangeLiteral()
		case ']':
			err = l.errorf("unexpected ']'")
		case '"', '`':
			_, err = l.stringLiteral()
		case '\'':
			err = l.errorf("single-quoted literals are not supported")
		default:
			l.pos += utf8.RuneLen(r)
		}
		if err != nil {
			return err
		}
	}
	if l.depth != 0 {
		return l.errorf("missing ')'")
	}
	return nil
}

// skipSpace skips whitespace and the three comment forms Loki's lexer skips: #, // and /* */.
func (l *lexer) skipSpace() error {
	for !l.eof() {
		switch c := l.text[l.pos]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			l.pos++
		case c == '#' || c == '/' && l.peekAt(1) == '/':
			start := l.pos
			if end := strings.IndexByte(l.text[l.pos:], '\n'); end >= 0 {
				l.pos += end
			} else {
				l.pos = len(l.text)
			}
			l.comment(start)
		case c == '/' && l.peekAt(1) == '*':
			start := l.pos
			end := strings.Index(l.text[l.pos+2:], "*/")
			if end < 0 {
				return l.errorf("comment not terminated")
			}
			l.pos += 2 + end + 2
			l.comment(start)
		default:
			return nil
		}
	}
	return nil
}

func (l *lexer) comment(start int) {
	if !l.inSelector {
		l.comments = append(l.comments, span{start, l.pos})
	}
}

// rangeLiteral reads "[...]" verbatim up to the first ']', as Loki does, and requires a
// duration inside.
func (l *lexer) rangeLiteral() error {
	end := strings.IndexByte(l.text[l.pos:], ']')
	if end < 0 {
		return l.errorf("missing ']'")
	}
	inner := l.text[l.pos+1 : l.pos+end]
	if _, err := model.ParseDuration(inner); err != nil {
		return l.errorf("invalid range [%s]", inner)
	}
	l.pos += end + 1
	return nil
}

// stringLiteral reads a double-quoted or raw string and returns its value.
func (l *lexer) stringLiteral() (string, error) {
	start := l.pos
	quote := l.text[l.pos]
	l.pos++
	for {
		if l.eof() {
			return "", l.errorf("string not terminated")
		}
		c := l.text[l.pos]
		switch {
		case c == quote:
			l.pos++
			literal := l.text[start:l.pos]
			if quote == '`' {
				return literal[1 : len(literal)-1], nil
			}
			value, err := strconv.Unquote(literal)
			if err != nil {
				return "", fmt.Errorf("at offset %d: invalid string %s", start, literal)
			}
			return value, nil
		case quote == '"' && c == '\n':
			return "", l.errorf("string not terminated")
		case quote == '"' && c == '\\':
			l.pos++
			if l.eof() || l.text[l.pos] == '\n' {
				return "", l.errorf("string not terminated")
			}
			l.pos++
		default:
			l.pos++
		}
	}
}

// selector parses "{name op "value", ...}". The grammar allows nothing else between the braces.
func (l *lexer) selector() error {
	start := l.pos
	l.pos++
	l.inSelector = true
	defer func() { l.inSelector = false }()
	var matchers []*labels.Matcher
	for {
		if err := l.skipSpace(); err != nil {
			return err
		}
		if l.peekAt(0) == '}' && len(matchers) == 0 {
			break
		}
		m, err := l.matcher()
		if err != nil {
			return err
		}
		matchers = append(matchers, m)
		if err := l.skipSpace(); err != nil {
			return err
		}
		if l.peekAt(0) == '}' {
			break
		}
		if l.peekAt(0) != ',' {
			return l.errorf("expected ',' or '}' in stream selector")
		}
		l.pos++
	}
	l.pos++
	l.selectors = append(l.selectors, selector{span: span{start, l.pos}, matchers: matchers})
	return nil
}

func (l *lexer) matcher() (*labels.Matcher, error) {
	name := l.identifier()
	if !model.LegacyValidation.IsValidLabelName(name) {
		return nil, l.errorf("expected a label name in stream selector")
	}
	if err := l.skipSpace(); err != nil {
		return nil, err
	}
	var matchType labels.MatchType
	switch op := l.text[l.pos:min(l.pos+2, len(l.text))]; {
	case op == "=~":
		matchType = labels.MatchRegexp
	case op == "!=":
		matchType = labels.MatchNotEqual
	case op == "!~":
		matchType = labels.MatchNotRegexp
	case op == "==":
		return nil, l.errorf("unexpected '==' in stream selector")
	case strings.HasPrefix(op, "="):
		matchType = labels.MatchEqual
	default:
		return nil, l.errorf("expected a matcher operator after %s", name)
	}
	l.pos += len(matchType.String())
	if err := l.skipSpace(); err != nil {
		return nil, err
	}
	if c := l.peekAt(0); c != '"' && c != '`' {
		return nil, l.errorf("expected a string after %s%s", name, matchType)
	}
	value, err := l.stringLiteral()
	if err != nil {
		return nil, err
	}
	m, err := labels.NewMatcher(matchType, name, value)
	if err != nil {
		return nil, l.errorf("%v", err)
	}
	return m, nil
}

// identifier reads a Go identifier, the token Loki's scanner produces for label names.
func (l *lexer) identifier() string {
	start := l.pos
	for !l.eof() {
		r, size := utf8.DecodeRuneInString(l.text[l.pos:])
		if r != '_' && !unicode.IsLetter(r) && !(unicode.IsDigit(r) && l.pos > start) {
			break
		}
		l.pos += size
	}
	return l.text[start:l.pos]
}
