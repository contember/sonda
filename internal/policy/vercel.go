package policy

import (
	"slices"
	"strings"
	"unicode"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// VercelQuery is a KQL filter over the runtime logs of one Vercel project. The project is set
// in the request scope; the filter always starts with the scope's environment.
type VercelQuery struct {
	filter string
}

func (q VercelQuery) String() string { return q.filter }

// ScopeVercelQuery AND-combines agent KQL with the environment. The agent filter must have
// balanced parentheses and quotes, so the group around it cannot be closed from inside.
func ScopeVercelQuery(scope authz.VercelScope, text string) (VercelQuery, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return VercelQuery{filter: vercelEnvironment(scope)}, nil
	}
	if err := checkKQL(text); err != nil {
		return VercelQuery{}, err
	}
	return VercelQuery{filter: vercelEnvironment(scope) + " AND (" + text + ")"}, nil
}

// VercelLogSearch translates a backend-neutral log search. Vercel matches bare terms as whole
// words of the message, case-insensitive, so contains is a word or an escaped phrase.
func VercelLogSearch(scope authz.VercelScope, f LogFilter) (VercelQuery, error) {
	if strings.TrimSpace(f.Pipeline) != "" {
		return VercelQuery{}, apierr.InvalidRequest("pipeline is supported only for Loki sources")
	}
	clauses := []string{vercelEnvironment(scope)}
	for _, text := range f.Contains {
		term, err := kqlTerm(text)
		if err != nil {
			return VercelQuery{}, err
		}
		clauses = append(clauses, term)
	}
	for _, w := range f.Where {
		clause := w.Field + ":" + kqlString(w.Value)
		if w.Negate {
			clause = "NOT " + clause
		}
		clauses = append(clauses, clause)
	}
	return VercelQuery{filter: strings.Join(clauses, " AND ")}, nil
}

func vercelEnvironment(scope authz.VercelScope) string {
	return "environment:" + kqlString(scope.VercelEnvironment())
}

// checkKQL tokenizes as Vercel does: a backslash escapes the next character inside and outside
// quotes, and only double quotes delimit strings.
func checkKQL(text string) error {
	depth := 0
	quoted := false
	escaped := false
	for _, r := range text {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case quoted:
		case r == '(':
			depth++
		case r == ')':
			depth--
			if depth < 0 {
				return apierr.InvalidQuery("unbalanced parentheses: ) without (")
			}
		}
	}
	switch {
	case escaped:
		return apierr.InvalidQuery("the query ends with an unfinished escape")
	case quoted:
		return apierr.InvalidQuery("unterminated quoted string")
	case depth > 0:
		return apierr.InvalidQuery("unbalanced parentheses: ( without )")
	}
	return nil
}

var kqlKeywords = []string{"and", "or", "not"}

// kqlTerm escapes text into one bare term, a phrase when it has several words.
func kqlTerm(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", apierr.InvalidRequest("contains needs at least one word")
	}
	var b strings.Builder
	for i, r := range text {
		keyword := i == 0 && slices.Contains(kqlKeywords, strings.ToLower(text))
		if keyword || !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}

func kqlString(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}
