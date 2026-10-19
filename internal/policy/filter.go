package policy

import (
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
)

// Where is one field=value or field!=value condition from a structured search.
type Where struct {
	Field  string
	Value  string
	Negate bool
}

var whereField = regexp.MustCompile(`^[A-Za-z_@$.][A-Za-z0-9_@$.\-]*$`)

// ParseWhere splits each condition on the first "!=" or "=". The value may be empty.
func ParseWhere(raw []string) ([]Where, error) {
	conditions := make([]Where, 0, len(raw))
	for _, condition := range raw {
		eq := strings.Index(condition, "=")
		if eq < 0 {
			return nil, apierr.InvalidRequest("invalid where %q, expected field=value or field!=value", condition)
		}
		w := Where{Field: condition[:eq], Value: condition[eq+1:]}
		if field, negated := strings.CutSuffix(w.Field, "!"); negated {
			w.Field, w.Negate = field, true
		}
		if !whereField.MatchString(w.Field) {
			return nil, apierr.InvalidRequest("invalid where %q: field %q is not a valid field name", condition, w.Field)
		}
		conditions = append(conditions, w)
	}
	return conditions, nil
}

// LogFilter is a backend-neutral log search. Pipeline is LogQL and applies to Loki only.
type LogFilter struct {
	Contains []string
	Where    []Where
	Pipeline string
}

// TraceFilter is a backend-neutral trace search. Zero durations are unset.
type TraceFilter struct {
	MinDuration time.Duration
	MaxDuration time.Duration
	Errors      bool
	Name        string
	Where       []Where
}

func ParseTraceFilter(req api.TraceSearchRequest) (TraceFilter, error) {
	where, err := ParseWhere(req.Where)
	if err != nil {
		return TraceFilter{}, err
	}
	f := TraceFilter{Errors: req.Errors, Name: req.Name, Where: where}
	if f.MinDuration, err = spanDuration("minDuration", req.MinDuration); err != nil {
		return TraceFilter{}, err
	}
	if f.MaxDuration, err = spanDuration("maxDuration", req.MaxDuration); err != nil {
		return TraceFilter{}, err
	}
	if f.MinDuration > 0 && f.MaxDuration > 0 && f.MinDuration > f.MaxDuration {
		return TraceFilter{}, apierr.InvalidRequest("minDuration %s is greater than maxDuration %s", req.MinDuration, req.MaxDuration)
	}
	return f, nil
}

// spanDuration accepts Go durations like 1.5s and Prometheus durations like 1m30s.
func spanDuration(name, raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		var promDuration model.Duration
		promDuration, err = model.ParseDuration(raw)
		d = time.Duration(promDuration)
	}
	if err != nil || d <= 0 {
		return 0, apierr.InvalidRequest("invalid %s %q, expected a positive duration like 500ms or 2s", name, raw)
	}
	return d, nil
}
