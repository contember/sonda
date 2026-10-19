package query

import (
	"context"
	"sort"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/loki"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

const maxLabelValues = 20

type lokiLogs struct {
	scope   authz.SelectorScope
	client  *loki.Client
	grafana *config.Grafana
}

func newLokiLogs(scope authz.SelectorScope, client *loki.Client, grafana *config.Grafana) logBackend {
	return &lokiLogs{scope: scope, client: client, grafana: grafana}
}

func (b *lokiLogs) dialect() api.Dialect { return api.DialectLogQL }

// search counts the matching lines with one instant query over the whole range, then
// fetches the newest lines.
func (b *lokiLogs) search(ctx context.Context, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error) {
	q, err := policy.LogSearchQuery(b.scope, f.Contains, f.Pipeline, f.Where)
	if err != nil {
		return logSearch{}, err
	}
	countQuery, err := policy.LogCountQuery(b.scope, q, r.To.Sub(r.From))
	if err != nil {
		return logSearch{}, err
	}

	recordQuery(ctx, b.scope.Target, countQuery.String())
	vector, err := b.client.Instant(ctx, countQuery, r.To)
	if err != nil {
		return logSearch{}, err
	}
	var total int64
	for _, sample := range vector {
		total += int64(sample.Value)
	}

	recordQuery(ctx, b.scope.Target, q.String())
	streams, err := b.client.Lines(ctx, q, r, limit)
	if err != nil {
		return logSearch{}, err
	}
	return logSearch{query: q.String(), total: total, streams: streams, source: b.sourceRef(q, r)}, nil
}

// query runs LogQL. Log queries return lines; metric queries return series.
func (b *lokiLogs) query(ctx context.Context, r api.TimeRange, text string, limit int, step string) (logQuery, error) {
	q, err := policy.ScopeLogQL(b.scope, text)
	if err != nil {
		return logQuery{}, err
	}
	result := logQuery{query: q.String(), source: b.sourceRef(q, r)}
	recordQuery(ctx, b.scope.Target, q.String())

	if q.IsMetric() {
		parsedStep, err := policy.ParseStep(step, r, maxPoints)
		if err != nil {
			return logQuery{}, err
		}
		matrix, err := b.client.Matrix(ctx, q, r, parsedStep)
		if err != nil {
			return logQuery{}, err
		}
		result.series = matrix
		if result.series == nil {
			result.series = model.Matrix{}
		}
		return result, nil
	}

	result.streams, err = b.client.Lines(ctx, q, r, limit)
	if err != nil {
		return logQuery{}, err
	}
	return result, nil
}

func (b *lokiLogs) fields(ctx context.Context, r api.TimeRange) (api.LogFields, error) {
	var result api.LogFields
	series, err := b.client.Series(ctx, b.scope, r)
	if err != nil {
		return result, err
	}
	fields, err := b.client.DetectedFields(ctx, b.scope, r)
	if err != nil {
		return result, err
	}

	values := map[string]map[string]bool{}
	for _, labels := range series {
		for name, value := range labels {
			if values[name] == nil {
				values[name] = map[string]bool{}
			}
			values[name][value] = true
		}
	}
	for name, set := range values {
		label := api.LogLabel{Name: name}
		for value := range set {
			label.Values = append(label.Values, value)
		}
		sort.Strings(label.Values)
		if len(label.Values) > maxLabelValues {
			label.Values, label.MoreValues = label.Values[:maxLabelValues], true
		}
		result.Labels = append(result.Labels, label)
	}
	sort.Slice(result.Labels, func(i, j int) bool { return result.Labels[i].Name < result.Labels[j].Name })
	for _, f := range fields {
		result.Fields = append(result.Fields, api.LogField{Name: f.Label, Type: f.Type, Cardinality: f.Cardinality, Parsers: f.Parsers})
	}
	return result, nil
}

func (b *lokiLogs) sourceRef(q policy.LogQL, r api.TimeRange) api.SourceRef {
	return shape.SourceRef(b.grafana, b.scope.Source(), q.String(), r)
}
