package shape

import (
	"encoding/json"
	"strings"
	"unicode"
)

// drain clusters log lines into templates with the Drain algorithm (He et al., "Drain: An
// Online Log Parsing Approach with Fixed Depth Tree", 2017). Lines with the same token count
// and first token are candidates for one template. A line joins the most similar candidate
// when enough of its tokens match; tokens that differ become a placeholder.
type drain struct {
	leaves map[leafKey][]*template
}

type leafKey struct {
	tokens int
	first  string
}

type template struct {
	tokens []token
	count  int
}

// token keeps the whitespace before it, so a template prints like the line it came from.
type token struct {
	space, text string
}

const (
	placeholder         = "<_>"
	similarityThreshold = 0.4
	// Lines with fewer or more tokens are left ungrouped: short lines have too little
	// structure to cluster, and long ones are mostly payload.
	minTokens = 4
	maxTokens = 80
)

// messageFields are the JSON fields that hold the message of a structured log line, in order
// of preference.
var messageFields = []string{"log", "message", "msg", "msg_", "_msg", "content"}

func newDrain() *drain {
	return &drain{leaves: map[leafKey][]*template{}}
}

// train adds a line and returns its template, or nil when the line is left ungrouped.
func (d *drain) train(line string) *template {
	tokens := tokenize(message(line))
	if len(tokens) < minTokens || len(tokens) > maxTokens {
		return nil
	}
	key := leafKey{tokens: len(tokens), first: prefix(tokens[0].text)}
	var best *template
	bestSimilarity, bestPlaceholders := -1.0, -1
	for _, candidate := range d.leaves[key] {
		similarity, placeholders := candidate.similarity(tokens)
		if similarity > bestSimilarity || similarity == bestSimilarity && placeholders > bestPlaceholders {
			best, bestSimilarity, bestPlaceholders = candidate, similarity, placeholders
		}
	}
	if best != nil && bestSimilarity >= similarityThreshold {
		best.merge(tokens)
		best.count++
		return best
	}
	created := &template{tokens: tokens, count: 1}
	d.leaves[key] = append(d.leaves[key], created)
	return created
}

// similarity returns the share of tokens equal to the template's and the number of
// placeholders in the template.
func (t *template) similarity(tokens []token) (float64, int) {
	equal, placeholders := 0, 0
	for i, tok := range t.tokens {
		switch {
		case tok.text == placeholder:
			placeholders++
		case tok.text == tokens[i].text:
			equal++
		}
	}
	return float64(equal) / float64(len(tokens)), placeholders
}

func (t *template) merge(tokens []token) {
	for i := range t.tokens {
		if t.tokens[i].text != tokens[i].text {
			t.tokens[i].text = placeholder
		}
	}
}

func (t *template) pattern() string {
	var b strings.Builder
	for i, tok := range t.tokens {
		if i > 0 {
			b.WriteString(tok.space)
		}
		b.WriteString(tok.text)
	}
	return b.String()
}

// prefix keys the first token. Tokens with digits are usually values, so they share a key.
func prefix(text string) string {
	if strings.IndexFunc(text, unicode.IsDigit) >= 0 {
		return placeholder
	}
	return text
}

// message returns the message field of a JSON line, or the line itself.
func message(line string) string {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		return line
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(trimmed), &fields) != nil {
		return line
	}
	for _, name := range messageFields {
		var text string
		if raw, ok := fields[name]; ok && json.Unmarshal(raw, &text) == nil {
			return text
		}
	}
	return line
}

// tokenize splits a line at whitespace, and splits "key=value" after the "=", so a value
// that varies becomes a placeholder while its key stays in the pattern.
func tokenize(line string) []token {
	var tokens []token
	space := ""
	for len(line) > 0 {
		start := strings.IndexFunc(line, func(r rune) bool { return !unicode.IsSpace(r) })
		if start < 0 {
			break
		}
		space, line = line[:start], line[start:]
		end := strings.IndexFunc(line, unicode.IsSpace)
		if end < 0 {
			end = len(line)
		}
		word := line[:end]
		line = line[end:]
		if eq := strings.IndexByte(word, '='); eq >= 0 && eq < len(word)-1 {
			tokens = append(tokens, token{space: space, text: word[:eq+1]}, token{text: word[eq+1:]})
			continue
		}
		tokens = append(tokens, token{space: space, text: word})
	}
	return tokens
}
