// Package insights splits a CloudWatch Logs Insights (CWLI) query into pipeline stages and
// finds its bare words without parsing the whole language. Words inside strings, regexes,
// backtick-quoted field names and comments are skipped, so a caller can ban a keyword
// everywhere it can take effect. AWS publishes no grammar, so the lexer accepts only input on
// which every plausible reading of the delimiters agrees, and rejects everything else.
package insights

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Query is a lexed Logs Insights query.
type Query struct {
	commands []string
	words    []string
}

// Commands returns the lower-cased command word of each top-level stage, in query order.
func (q Query) Commands() []string { return append([]string(nil), q.commands...) }

// Words returns every lower-cased run of ASCII letters, digits and underscores outside
// strings, regexes, backtick-quoted names and comments, including the command words.
func (q Query) Words() []string { return append([]string(nil), q.words...) }

// Parse lexes a query. It fails closed on anything it does not understand.
func Parse(query string) (Query, error) {
	if !utf8.ValidString(query) {
		return Query{}, errors.New("query is not valid UTF-8")
	}
	l := &lexer{text: query}
	if err := l.run(); err != nil {
		return Query{}, err
	}
	return Query{commands: l.commands, words: l.words}, nil
}

type tokenKind int

const (
	tokenNone tokenKind = iota
	tokenCommand
	tokenWord
	tokenName
	tokenString
	tokenRegex
	tokenOpen
	tokenClose
	tokenComma
	tokenOperator
)

type token struct {
	kind tokenKind
	text string // lower-cased for words, the operator for operators
}

// keywords are words that never stand for a value, so they cannot precede "like" as its operand.
var keywords = map[string]bool{"and": true, "or": true, "not": true, "like": true, "in": true, "by": true, "as": true, "asc": true, "desc": true}

type lexer struct {
	text     string
	pos      int
	brackets []byte
	commands []string
	words    []string
	// history holds the last three tokens of the current stage, newest last.
	history []token
	// expectCommand is set at the start of every stage, top-level or nested.
	expectCommand bool
	// command is the command of the current stage at any depth, and argTokens counts the
	// tokens after it.
	command   string
	argTokens int
}

func (l *lexer) errorf(format string, args ...any) error {
	return fmt.Errorf("at offset %d: %s", l.pos, fmt.Sprintf(format, args...))
}

func (l *lexer) run() error {
	l.startStage()
	for {
		if err := l.skipSpace(); err != nil {
			return err
		}
		if l.pos >= len(l.text) {
			break
		}
		if err := l.next(); err != nil {
			return err
		}
	}
	if l.expectCommand {
		if len(l.commands) == 0 {
			return errors.New("query is empty")
		}
		return l.errorf("expected a command after '|'")
	}
	if len(l.brackets) > 0 {
		return l.errorf("missing closing %q", closing(l.brackets[len(l.brackets)-1]))
	}
	return nil
}

func (l *lexer) startStage() {
	l.expectCommand = true
	l.command = ""
	l.argTokens = 0
	l.history = l.history[:0]
}

func (l *lexer) next() error {
	c := l.text[l.pos]
	if l.expectCommand {
		return l.commandWord()
	}
	switch {
	case c == '|':
		l.pos++
		l.startStage()
		return nil
	case isWordByte(c):
		return l.word()
	case c == '`':
		return l.literal('`', tokenName, false)
	case c == '"' || c == '\'':
		return l.literal(c, tokenString, false)
	case c == '/':
		if !l.regexAllowed() {
			return l.errorf("'/' is supported only as a regex delimiter after like, =~, !~, '(' or ',' and in parse")
		}
		return l.literal('/', tokenRegex, true)
	case c == '(' || c == '[':
		l.brackets = append(l.brackets, c)
		l.pos++
		l.push(token{kind: tokenOpen, text: string(c)})
		return nil
	case c == ')' || c == ']':
		if len(l.brackets) == 0 || closing(l.brackets[len(l.brackets)-1]) != c {
			return l.errorf("unexpected %q", c)
		}
		l.brackets = l.brackets[:len(l.brackets)-1]
		l.pos++
		l.push(token{kind: tokenClose, text: string(c)})
		return nil
	case c == ',':
		l.pos++
		l.push(token{kind: tokenComma, text: ","})
		return nil
	case isOperatorByte(c):
		start := l.pos
		for l.pos < len(l.text) && isOperatorByte(l.text[l.pos]) {
			l.pos++
		}
		l.push(token{kind: tokenOperator, text: l.text[start:l.pos]})
		return nil
	}
	r, _ := utf8.DecodeRuneInString(l.text[l.pos:])
	return l.errorf("unexpected character %q", r)
}

func (l *lexer) push(t token) {
	if l.command != "" {
		l.argTokens++
	}
	l.history = append(l.history, t)
	if len(l.history) > 3 {
		l.history = l.history[1:]
	}
}

// back returns the n-th previous token of the stage, 1 being the newest.
func (l *lexer) back(n int) token {
	if n > len(l.history) {
		return token{}
	}
	return l.history[len(l.history)-n]
}

// commandWord reads the first token of a stage, which must be a plain word.
func (l *lexer) commandWord() error {
	start := l.pos
	for l.pos < len(l.text) && isWordByte(l.text[l.pos]) {
		l.pos++
	}
	word := l.text[start:l.pos]
	if !isCommand(word) {
		l.pos = start
		return l.errorf("expected a command at the start of a stage")
	}
	command := strings.ToLower(word)
	if len(l.brackets) == 0 {
		l.commands = append(l.commands, command)
	}
	l.words = append(l.words, command)
	l.expectCommand = false
	l.push(token{kind: tokenCommand, text: command})
	l.command = command
	return nil
}

// word reads an identifier, a number or a duration. A lone "@" followed by a backtick is the
// system-field form @`name`.
func (l *lexer) word() error {
	start := l.pos
	for l.pos < len(l.text) && isWordByte(l.text[l.pos]) {
		l.pos++
	}
	text := l.text[start:l.pos]
	if text == "@" && l.pos < len(l.text) && l.text[l.pos] == '`' {
		return l.literal('`', tokenName, false)
	}
	l.addWords(text)
	l.push(token{kind: tokenWord, text: strings.ToLower(text)})
	return nil
}

func (l *lexer) addWords(text string) {
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return !isAlnum(r) }) {
		l.words = append(l.words, strings.ToLower(part))
	}
}

// literal reads a string, regex or backtick-quoted name. A backslash escapes the next
// character, but never the closing delimiter: without that rule a lexer that ignores escapes
// would end the literal earlier and see the rest as query text.
func (l *lexer) literal(delimiter byte, kind tokenKind, multiline bool) error {
	start := l.pos
	l.pos++
	for {
		if l.pos >= len(l.text) {
			l.pos = start
			return l.errorf("%s not terminated", kindName(kind))
		}
		c := l.text[l.pos]
		switch {
		case c == delimiter:
			l.pos++
			l.push(token{kind: kind})
			return nil
		case c == '\n' && !multiline:
			return l.errorf("%s spans lines", kindName(kind))
		case c == '\\' && kind != tokenName:
			if l.pos+1 < len(l.text) && l.text[l.pos+1] == delimiter {
				return l.errorf("escaped %q in %s is not supported", delimiter, kindName(kind))
			}
			l.pos++
			if err := l.literalChar(kind, multiline); err != nil {
				return err
			}
		case c == '\\':
			return l.errorf("backslash in a backtick-quoted name is not supported")
		default:
			if err := l.literalChar(kind, multiline); err != nil {
				return err
			}
		}
	}
}

func (l *lexer) literalChar(kind tokenKind, multiline bool) error {
	if l.pos >= len(l.text) {
		return l.errorf("%s not terminated", kindName(kind))
	}
	r, size := utf8.DecodeRuneInString(l.text[l.pos:])
	if r == '\n' && !multiline {
		return l.errorf("%s spans lines", kindName(kind))
	}
	if r != '\n' && r != '\t' && isControl(r) {
		return l.errorf("control character %q in %s", r, kindName(kind))
	}
	l.pos += size
	return nil
}

// regexAllowed reports whether a '/' starts a regex. It does only where a division cannot
// stand, because AWS decides by its grammar and division is not supported here at all.
func (l *lexer) regexAllowed() bool {
	prev := l.back(1)
	switch prev.kind {
	case tokenOpen:
		return prev.text == "("
	case tokenComma:
		return true
	case tokenOperator:
		return prev.text == "=~" || prev.text == "!~"
	case tokenCommand:
		return prev.text == "parse"
	case tokenWord, tokenName:
		if l.command == "parse" && l.argTokens == 1 {
			return true
		}
		return prev.text == "like" && l.likeIsOperator()
	}
	return false
}

// likeIsOperator reports whether the "like" just read follows an operand, directly or
// through "not", so it cannot be a field named like.
func (l *lexer) likeIsOperator() bool {
	before := l.back(2)
	if before.kind == tokenWord && before.text == "not" {
		before = l.back(3)
	}
	switch before.kind {
	case tokenWord:
		return !keywords[before.text]
	case tokenName, tokenString, tokenClose:
		return true
	}
	return false
}

// skipSpace skips whitespace and # comments, which end at a line feed.
func (l *lexer) skipSpace() error {
	for l.pos < len(l.text) {
		switch c := l.text[l.pos]; c {
		case ' ', '\t', '\n', '\r':
			l.pos++
		case '#':
			if err := l.comment(); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

// comment rejects any other line terminator, because AWS might end the comment there.
func (l *lexer) comment() error {
	for l.pos < len(l.text) {
		r, size := utf8.DecodeRuneInString(l.text[l.pos:])
		if r == '\n' {
			return nil
		}
		if r == '\r' || r == '\u0085' || r == ' ' || r == ' ' || (r != '\t' && isControl(r)) {
			return l.errorf("comment contains %q", r)
		}
		l.pos += size
	}
	return nil
}

func isCommand(word string) bool {
	if word == "" || !isLetter(word[0]) {
		return false
	}
	for i := 0; i < len(word); i++ {
		if !isAlnum(rune(word[i])) {
			return false
		}
	}
	return true
}

// isWordByte covers identifiers like @message and a.b, numbers like 1.5 and durations like 5m.
func isWordByte(c byte) bool { return isAlnum(rune(c)) || c == '@' || c == '.' }

func isOperatorByte(c byte) bool { return strings.IndexByte("=!<>~+-*%^:", c) >= 0 }

func isAlnum(r rune) bool {
	return r < utf8.RuneSelf && (isLetter(byte(r)) || r >= '0' && r <= '9' || r == '_')
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func closing(open byte) byte {
	if open == '(' {
		return ')'
	}
	return ']'
}

func kindName(kind tokenKind) string {
	switch kind {
	case tokenRegex:
		return "regex"
	case tokenName:
		return "backtick-quoted name"
	}
	return "string"
}
