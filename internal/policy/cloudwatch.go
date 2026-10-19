package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/insights"
	"github.com/contember/sonda/internal/telemetry"
)

// maxInsightsQueryLength is the StartQuery limit of the query string.
const maxInsightsQueryLength = 10000

// maxCloudWatchDimensions is the GetMetricData limit of dimensions per metric.
const maxCloudWatchDimensions = 30

// InsightsQuery is a Logs Insights query that cannot select log groups by itself.
type InsightsQuery struct {
	text      string
	aggregate bool
}

func (q InsightsQuery) String() string { return q.text }

// Aggregates reports whether the query has a stats stage, so its rows are statistics, not events.
func (q InsightsQuery) Aggregates() bool { return q.aggregate }

// insightsCommands are the commands that read only the rows of the query's own log groups.
// Every other command is rejected: SOURCE, join and appendcols read other log groups, lookup
// and cidrlookup read account-wide tables, and unmask reveals masked data.
var insightsCommands = []string{
	"anomaly", "dedup", "diff", "display", "fields", "filter", "filterindex", "limit", "parse",
	"pattern", "sort", "stats", "unnest", "where",
}

// insightsBannedWords are rejected as bare words anywhere, because the first stage of a
// subquery follows '(' and the lexer cannot tell it from an expression. unmask is also a
// function.
var insightsBannedWords = []string{"source", "unmask", "lookup", "cidrlookup", "join", "appendcols"}

// ScopeInsights accepts a query whose stages use only allowed commands. The log groups come
// only from the scope, which the connector passes to StartQuery.
func ScopeInsights(scope authz.LogGroupScope, text string) (InsightsQuery, error) {
	if utf8.RuneCountInString(text) > maxInsightsQueryLength {
		return InsightsQuery{}, apierr.InvalidQuery("query is longer than %d characters", maxInsightsQueryLength)
	}
	parsed, err := insights.Parse(text)
	if err != nil {
		return InsightsQuery{}, apierr.InvalidQuery("invalid Logs Insights query: %v", err)
	}
	for _, command := range append(parsed.Commands(), parsed.NestedCommands()...) {
		if command == "source" {
			return InsightsQuery{}, errSourceNotAllowed
		}
		if !slices.Contains(insightsCommands, command) {
			return InsightsQuery{}, apierr.InvalidQuery("command %s is not allowed; allowed commands: %s", command, strings.Join(insightsCommands, ", "))
		}
	}
	for _, word := range parsed.Words() {
		if word == "source" {
			return InsightsQuery{}, errSourceNotAllowed
		}
		if slices.Contains(insightsBannedWords, word) {
			return InsightsQuery{}, apierr.InvalidQuery("%s is not allowed anywhere in the query; quote a field of that name in backticks", word)
		}
	}
	return InsightsQuery{text: text, aggregate: slices.Contains(parsed.Commands(), "stats")}, nil
}

var errSourceNotAllowed = apierr.InvalidQuery("SOURCE is not allowed; the service's log groups are selected by Sonda (quote a field named source in backticks)")

// InsightsSearch builds a query that returns the newest matching events of the scope.
func InsightsSearch(scope authz.LogGroupScope, f LogFilter, limit int) (InsightsQuery, error) {
	if strings.TrimSpace(f.Pipeline) != "" {
		return InsightsQuery{}, apierr.InvalidRequest("pipeline is supported only for Loki sources")
	}
	stages := []string{"fields @timestamp, @message, @logStream"}
	for _, text := range f.Contains {
		literal, err := insightsString(text)
		if err != nil {
			return InsightsQuery{}, apierr.InvalidRequest("contains %q: %v", text, err)
		}
		stages = append(stages, "filter @message like "+literal)
	}
	for _, w := range f.Where {
		field, err := insightsField(w.Field)
		if err != nil {
			return InsightsQuery{}, apierr.InvalidRequest("where field %q: %v", w.Field, err)
		}
		literal, err := insightsString(w.Value)
		if err != nil {
			return InsightsQuery{}, apierr.InvalidRequest("where %s value %q: %v", w.Field, w.Value, err)
		}
		operator := "="
		if w.Negate {
			operator = "!="
		}
		stages = append(stages, "filter "+field+" "+operator+" "+literal)
	}
	stages = append(stages, "sort @timestamp desc", "limit "+strconv.Itoa(min(limit, insights.MaxRows)))
	return ScopeInsights(scope, strings.Join(stages, " | "))
}

// insightsString quotes a value with whichever quote it does not contain, because the lexer
// rejects escaped quotes.
func insightsString(value string) (string, error) {
	quote := `"`
	if strings.Contains(value, `"`) {
		quote = `'`
		if strings.Contains(value, `'`) {
			return "", errors.New("cannot contain both ' and \"")
		}
	}
	var b strings.Builder
	b.WriteString(quote)
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("control character %q is not supported", r)
			}
			b.WriteRune(r)
		}
	}
	b.WriteString(quote)
	return b.String(), nil
}

var (
	insightsPlainField  = regexp.MustCompile(`^@?[A-Za-z_][A-Za-z0-9_.]*$`)
	insightsReservedKey = map[string]bool{
		"and": true, "or": true, "not": true, "like": true, "in": true, "as": true, "by": true,
		"asc": true, "desc": true, "source": true,
	}
)

// insightsField writes a field name bare when it is a plain identifier without reserved words,
// and in backticks otherwise. A leading @ stays outside the backticks, as AWS requires.
func insightsField(name string) (string, error) {
	if strings.ContainsAny(name, "`\\\n") {
		return "", fmt.Errorf("backticks, backslashes and line breaks are not supported")
	}
	if insightsPlainField.MatchString(name) && !hasReservedPart(name) {
		return name, nil
	}
	if rest, ok := strings.CutPrefix(name, "@"); ok {
		return "@`" + rest + "`", nil
	}
	return "`" + name + "`", nil
}

func hasReservedPart(name string) bool {
	return slices.ContainsFunc(strings.Split(strings.TrimPrefix(name, "@"), "."), func(part string) bool {
		return insightsReservedKey[strings.ToLower(part)]
	})
}

// CloudWatchMetric is one metric of the scope's namespace, with the scope dimensions and the
// agent's additional dimensions.
type CloudWatchMetric struct {
	namespace  string
	metric     string
	stat       string
	dimensions map[string]string
}

func (m CloudWatchMetric) Namespace() string { return m.namespace }
func (m CloudWatchMetric) Metric() string    { return m.metric }
func (m CloudWatchMetric) Stat() string      { return m.stat }

// Dimensions returns a copy, so callers cannot change the metric.
func (m CloudWatchMetric) Dimensions() map[string]string { return maps.Clone(m.dimensions) }

// String renders the metric as the JSON of the query that runs, with the scope applied.
func (m CloudWatchMetric) String() string {
	encoded, err := json.Marshal(struct {
		Namespace  string            `json:"namespace"`
		Metric     string            `json:"metric"`
		Stat       string            `json:"stat"`
		Dimensions map[string]string `json:"dimensions"`
	}{m.namespace, m.metric, m.stat, m.dimensions})
	if err != nil {
		return fmt.Sprintf("%s %s %s %v", m.namespace, m.metric, m.stat, m.dimensions)
	}
	return string(encoded)
}

// ScopeCloudWatchMetric adds the scope's namespace and dimensions to a metric query. A metric
// is identified by its exact dimension set, so extra dimensions only narrow the scope, and an
// agent dimension that names a scope dimension must keep its value.
func ScopeCloudWatchMetric(scope authz.CloudWatchMetricScope, text string) (CloudWatchMetric, error) {
	q, err := telemetry.DecodeCloudWatchMetricQuery(text)
	if err != nil {
		return CloudWatchMetric{}, apierr.InvalidQuery("invalid %s query: %v", api.DialectCloudWatchMetric, err)
	}
	dimensions := scope.Dimensions()
	for name, value := range q.Dimensions {
		if scoped, ok := dimensions[name]; ok && scoped != value {
			return CloudWatchMetric{}, apierr.InvalidQuery("dimension %s is fixed to %q for this service", name, scoped)
		}
		if name == "" || value == "" {
			return CloudWatchMetric{}, apierr.InvalidQuery("dimension names and values must not be empty")
		}
		dimensions[name] = value
	}
	if len(dimensions) > maxCloudWatchDimensions {
		return CloudWatchMetric{}, apierr.InvalidQuery("a metric has at most %d dimensions", maxCloudWatchDimensions)
	}
	return CloudWatchMetric{namespace: scope.Namespace(), metric: q.Metric, stat: q.Stat, dimensions: dimensions}, nil
}
