package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/traceql"
)

// TraceQL is a TraceQL query in which every spanset filter carries the scope condition.
type TraceQL struct {
	expr string
}

func (q TraceQL) String() string { return q.expr }

// ScopeTraceQL adds the scope condition to every spanset filter of the query: {X} becomes
// { (X) && resource.service.name = "svc" }. The condition combines with AND, so the query
// can only narrow the scope, never widen it.
func ScopeTraceQL(scope authz.TempoScope, query string) (TraceQL, error) {
	condition := scopeCondition(scope)
	parsed, err := traceql.Parse(query)
	if err != nil {
		return TraceQL{}, apierr.InvalidQuery("invalid TraceQL: %v", err)
	}
	scoped := parsed.Rewrite(func(inner string) string { return scopeTraceQLFilter(inner, condition) })
	if err := verifyTraceQL(scoped, condition); err != nil {
		return TraceQL{}, err
	}
	return TraceQL{expr: scoped}, nil
}

func scopeCondition(scope authz.TempoScope) string {
	return "resource.service.name = " + strconv.Quote(scope.ServiceName())
}

func scopeTraceQLFilter(inner, condition string) string {
	if strings.TrimSpace(inner) == "" {
		return " " + condition + " "
	}
	return " (" + inner + ") && " + condition + " "
}

// verifyTraceQL re-lexes the scoped query and checks that every filter has exactly the
// shape scopeTraceQLFilter produces, so a rewrite bug cannot silently drop the scope.
func verifyTraceQL(query, condition string) error {
	parsed, err := traceql.Parse(query)
	if err != nil {
		return fmt.Errorf("scoped TraceQL does not parse: %w", err)
	}
	for _, filter := range parsed.Filters() {
		if !isScopedFilter(filter, condition) {
			return fmt.Errorf("scoped TraceQL has a filter without the scope condition: %s", query)
		}
	}
	return nil
}

// isScopedFilter reports whether the condition stands at the top level of the filter: the
// filter is the condition alone, or a parenthesized expression AND the condition.
func isScopedFilter(filter, condition string) bool {
	if filter == " "+condition+" " {
		return true
	}
	suffix := ") && " + condition + " "
	if !strings.HasPrefix(filter, " (") || !strings.HasSuffix(filter, suffix) {
		return false
	}
	// The original filter must lex on its own, so its parentheses are balanced and the
	// added parentheses enclose it.
	original := filter[len(" (") : len(filter)-len(suffix)]
	parsed, err := traceql.Parse("{" + original + "}")
	return err == nil && slices.Equal(parsed.Filters(), []string{original})
}

var (
	traceQLAttribute = regexp.MustCompile(`^(?:span|resource)?\.[A-Za-z0-9_.\-]+$`)
	// traceQLStringIntrinsics are the intrinsics a where condition compares with a string.
	traceQLStringIntrinsics = []string{"name", "statusMessage", "rootServiceName"}
)

// TempoSearch builds a scoped TraceQL query from a backend-neutral trace filter. Where
// fields are attribute names like span.http.route or .http.route, or string intrinsics.
func TempoSearch(scope authz.TempoScope, f TraceFilter) (TraceQL, error) {
	var conditions []string
	if f.MinDuration > 0 {
		conditions = append(conditions, "duration >= "+f.MinDuration.String())
	}
	if f.MaxDuration > 0 {
		conditions = append(conditions, "duration <= "+f.MaxDuration.String())
	}
	if f.Errors {
		conditions = append(conditions, "status = error")
	}
	if f.Name != "" {
		conditions = append(conditions, "name =~ "+strconv.Quote(".*"+regexp.QuoteMeta(f.Name)+".*"))
	}
	for _, w := range f.Where {
		if !traceQLAttribute.MatchString(w.Field) && !slices.Contains(traceQLStringIntrinsics, w.Field) {
			return TraceQL{}, apierr.InvalidRequest("where field %q is not a TraceQL attribute like span.http.route, resource.k8s.namespace or .http.route", w.Field)
		}
		operator := " = "
		if w.Negate {
			operator = " != "
		}
		conditions = append(conditions, w.Field+operator+strconv.Quote(w.Value))
	}
	return ScopeTraceQL(scope, "{ "+strings.Join(conditions, " && ")+" }")
}
