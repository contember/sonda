// Package policy turns user query text into upstream query text restricted to one scope.
// It is the only code allowed to do so: connectors accept only PromQL and LogQL values,
// which cannot be constructed outside this package.
package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// PromQL is a PromQL expression in which every selector carries the scope matchers.
type PromQL struct {
	expr string
}

func (q PromQL) String() string { return q.expr }

// LogQL is a LogQL expression in which every stream selector carries the scope matchers.
type LogQL struct {
	expr   string
	metric bool
}

func (q LogQL) String() string { return q.expr }

// IsMetric reports whether the query returns series instead of log lines.
func (q LogQL) IsMetric() bool { return q.metric }

var promParser = parser.NewParser(parser.Options{})

// ScopePromQL appends the scope matchers to every selector of the query. Matchers combine
// with AND, so the query can only narrow the scope, never widen it.
func ScopePromQL(scope authz.SelectorScope, query string) (PromQL, error) {
	matchers := scope.Matchers()
	expr, err := promParser.ParseExpr(query)
	if err != nil {
		return PromQL{}, apierr.InvalidQuery("invalid PromQL: %v", err)
	}
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok {
			vs.LabelMatchers = withScope(vs.LabelMatchers, matchers)
		}
		return nil
	})
	scoped := expr.String()
	if err := verifyPromQL(scoped, matchers); err != nil {
		return PromQL{}, err
	}
	return PromQL{expr: scoped}, nil
}

// verifyPromQL re-parses the serialized query and checks every selector, so a
// serialization bug cannot silently drop the scope.
func verifyPromQL(query string, matchers []*labels.Matcher) error {
	expr, err := promParser.ParseExpr(query)
	if err != nil {
		return fmt.Errorf("scoped PromQL does not parse: %w", err)
	}
	var unscoped bool
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok && !containsAll(vs.LabelMatchers, matchers) {
			unscoped = true
		}
		return nil
	})
	if unscoped {
		return fmt.Errorf("scoped PromQL has a selector without scope matchers: %s", query)
	}
	return nil
}

// ScopeLogQL appends the scope matchers to every stream selector of the query.
func ScopeLogQL(scope authz.SelectorScope, query string) (LogQL, error) {
	matchers := scope.Matchers()
	expr, err := syntax.ParseExpr(query)
	if err != nil {
		return LogQL{}, apierr.InvalidQuery("invalid LogQL: %v", err)
	}
	expr.Walk(func(e syntax.Expr) bool {
		if me, ok := e.(*syntax.MatchersExpr); ok {
			me.Mts = withScope(me.Mts, matchers)
		}
		return true
	})
	scoped := expr.String()
	if err := verifyLogQL(scoped, matchers); err != nil {
		return LogQL{}, err
	}
	_, isLogQuery := expr.(syntax.LogSelectorExpr)
	return LogQL{expr: scoped, metric: !isLogQuery}, nil
}

func verifyLogQL(query string, matchers []*labels.Matcher) error {
	expr, err := syntax.ParseExpr(query)
	if err != nil {
		return fmt.Errorf("scoped LogQL does not parse: %w", err)
	}
	var unscoped bool
	expr.Walk(func(e syntax.Expr) bool {
		if me, ok := e.(*syntax.MatchersExpr); ok && !containsAll(me.Mts, matchers) {
			unscoped = true
		}
		return true
	})
	if unscoped {
		return fmt.Errorf("scoped LogQL has a selector without scope matchers: %s", query)
	}
	return nil
}

// LogSearchQuery builds a log query from line filters and an optional pipeline.
func LogSearchQuery(scope authz.SelectorScope, contains []string, pipeline string) (LogQL, error) {
	var b strings.Builder
	b.WriteString(scope.Selector())
	for _, text := range contains {
		b.WriteString(" |= ")
		b.WriteString(strconv.Quote(text))
	}
	if pipeline = strings.TrimSpace(pipeline); pipeline != "" {
		b.WriteString(" ")
		b.WriteString(pipeline)
	}
	q, err := ScopeLogQL(scope, b.String())
	if err != nil {
		return LogQL{}, err
	}
	if q.metric {
		return LogQL{}, apierr.InvalidQuery("the pipeline must keep a log query; use logs query for metric queries")
	}
	return q, nil
}

// LogCountQuery counts the lines of a log query over the whole range, as one instant query.
func LogCountQuery(scope authz.SelectorScope, q LogQL, rangeLength time.Duration) (LogQL, error) {
	if q.metric {
		return LogQL{}, apierr.InvalidQuery("cannot count a metric query")
	}
	seconds := max(int64(rangeLength.Seconds()), 1)
	return ScopeLogQL(scope, fmt.Sprintf("sum(count_over_time(%s [%ds]))", q.expr, seconds))
}

// withScope appends the scope matchers the selector does not already contain.
func withScope(selector, scope []*labels.Matcher) []*labels.Matcher {
	for _, m := range scope {
		if !slices.ContainsFunc(selector, sameMatcher(m)) {
			selector = append(selector, m)
		}
	}
	return selector
}

func containsAll(have, want []*labels.Matcher) bool {
	for _, w := range want {
		if !slices.ContainsFunc(have, sameMatcher(w)) {
			return false
		}
	}
	return true
}

func sameMatcher(m *labels.Matcher) func(*labels.Matcher) bool {
	return func(other *labels.Matcher) bool {
		return other.Type == m.Type && other.Name == m.Name && other.Value == m.Value
	}
}

// Range resolves a window into an absolute range. It never reaches into the future and
// rejects ranges longer than maxRange instead of silently shortening them.
func Range(w api.Window, now time.Time, maxRange, defaultSince time.Duration) (api.TimeRange, error) {
	to := now
	if w.To != nil {
		to = *w.To
	}
	if to.After(now) {
		to = now
	}
	var from time.Time
	switch {
	case w.From != nil:
		from = *w.From
	case w.Since != "":
		since, err := model.ParseDuration(w.Since)
		if err != nil || since <= 0 {
			return api.TimeRange{}, apierr.InvalidRequest("invalid since %q, expected a duration like 30m, 6h or 2d", w.Since)
		}
		from = to.Add(-time.Duration(since))
	default:
		from = to.Add(-defaultSince)
	}
	if !from.Before(to) {
		return api.TimeRange{}, apierr.InvalidRequest("from must be before to")
	}
	if to.Sub(from) > maxRange {
		return api.TimeRange{}, apierr.New(api.CodeLimitExceeded, "range %s exceeds the limit of %s",
			model.Duration(to.Sub(from)), model.Duration(maxRange))
	}
	return api.TimeRange{From: from.UTC(), To: to.UTC()}, nil
}

// ParseStep parses a step, or picks one that yields at most maxPoints points.
func ParseStep(raw string, r api.TimeRange, maxPoints int) (time.Duration, error) {
	minimum := max(r.To.Sub(r.From)/time.Duration(maxPoints), time.Second)
	if raw == "" {
		return roundStep(minimum), nil
	}
	step, err := model.ParseDuration(raw)
	if err != nil || step <= 0 {
		return 0, apierr.InvalidRequest("invalid step %q", raw)
	}
	return max(time.Duration(step), roundStep(minimum)), nil
}

func roundStep(d time.Duration) time.Duration {
	for _, s := range []time.Duration{
		15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute,
		10 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour,
		3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
	} {
		if d <= s {
			return s
		}
	}
	return d.Truncate(time.Hour) + time.Hour
}
