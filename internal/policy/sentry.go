package policy

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/contember/sonda/internal/apierr"
)

// SentrySpanQuery is a query in Sentry's search syntax over the spans dataset. It carries no
// scope: the connector sends the project and environment as request parameters, which Sentry
// ANDs with the query, so the text cannot widen them.
type SentrySpanQuery struct {
	text string
}

func (q SentrySpanQuery) String() string { return q.text }

// SentrySpans takes a native query as it is; the scope does not depend on its text.
func SentrySpans(text string) SentrySpanQuery {
	return SentrySpanQuery{text: strings.TrimSpace(text)}
}

// SentrySpanSearch translates a structured trace search. Name matches the span description.
func SentrySpanSearch(f TraceFilter) (SentrySpanQuery, error) {
	var terms []string
	if f.MinDuration > 0 {
		terms = append(terms, "span.duration:>="+sentryMilliseconds(f.MinDuration.Seconds()*1000))
	}
	if f.MaxDuration > 0 {
		terms = append(terms, "span.duration:<="+sentryMilliseconds(f.MaxDuration.Seconds()*1000))
	}
	if f.Errors {
		terms = append(terms, "has:span.status", "!span.status:ok")
	}
	if f.Name != "" {
		name, err := sentryValue("name", f.Name)
		if err != nil {
			return SentrySpanQuery{}, err
		}
		terms = append(terms, `span.description:"*`+name+`*"`)
	}
	for _, w := range f.Where {
		value, err := sentryValue(w.Field, w.Value)
		if err != nil {
			return SentrySpanQuery{}, err
		}
		term := w.Field + `:"` + value + `"`
		if w.Negate {
			term = "!" + term
		}
		terms = append(terms, term)
	}
	return SentrySpanQuery{text: strings.Join(terms, " ")}, nil
}

var sentryTraceID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// SentryTraceByID selects every span of one trace. The connector runs it across all projects;
// the caller checks that the trace contains a span of the scope.
func SentryTraceByID(id string) (SentrySpanQuery, error) {
	if !sentryTraceID.MatchString(id) {
		return SentrySpanQuery{}, apierr.InvalidRequest("invalid trace ID %q, Sentry trace IDs have 32 hex characters", id)
	}
	return SentrySpanQuery{text: "trace:" + id}, nil
}

// SentryTraceSegments selects the transaction segments of the traces, whose roots name the
// traces in a search result. IDs come from Sentry, so invalid ones are skipped.
func SentryTraceSegments(ids []string) SentrySpanQuery {
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if sentryTraceID.MatchString(id) {
			valid = append(valid, id)
		}
	}
	return SentrySpanQuery{text: "is_transaction:true trace:[" + strings.Join(valid, ",") + "]"}
}

func sentryMilliseconds(ms float64) string {
	return strconv.FormatFloat(ms, 'f', -1, 64) + "ms"
}

// sentryValue escapes a value for a quoted term: \" is a quote and \* a literal asterisk.
// Sentry has no escape for a backslash before the closing quote, so backslashes are rejected.
func sentryValue(field, value string) (string, error) {
	if strings.Contains(value, `\`) {
		return "", apierr.InvalidRequest("%s value %q contains a backslash, which Sentry search cannot express", field, value)
	}
	return strings.NewReplacer(`"`, `\"`, `*`, `\*`).Replace(value), nil
}
