package query

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/loki"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

const (
	defaultLogQueryLines = 100
	maxLogGroups         = 30
	maxLabelValues       = 20
	resultTTL            = 30 * time.Minute
	resultKindLogs       = "logs"
)

// logResult is the payload behind a result handle.
type logResult struct {
	Sample shape.LogSample `json:"sample"`
	// Groups holds the group index of each line, or nil when the lines were not grouped.
	Groups []int `json:"groups,omitempty"`
}

func (s *Service) logScope(identity *authz.Identity, service, env string) (authz.SelectorScope, *loki.Client, error) {
	scope, err := s.authz.LogScope(identity, service, env)
	if err != nil {
		return authz.SelectorScope{}, nil, err
	}
	return scope, s.connectors.Loki[scope.Source().Name], nil
}

// SearchLogs counts all matching lines exactly, then groups a sample of the newest lines
// into patterns.
func (s *Service) SearchLogs(ctx context.Context, identity *authz.Identity, service string, req api.LogSearchRequest) (api.Response[api.LogSearchResult], error) {
	var resp api.Response[api.LogSearchResult]
	scope, client, err := s.logScope(identity, service, req.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return resp, err
	}
	q, err := policy.LogSearchQuery(scope, req.Contains, req.Pipeline)
	if err != nil {
		return resp, err
	}
	countQuery, err := policy.LogCountQuery(scope, q, r.To.Sub(r.From))
	if err != nil {
		return resp, err
	}

	recordQuery(ctx, scope.Target, countQuery.String())
	vector, err := client.Instant(ctx, countQuery, r.To)
	if err != nil {
		return resp, err
	}
	var total int64
	for _, sample := range vector {
		total += int64(sample.Value)
	}

	recordQuery(ctx, scope.Target, q.String())
	streams, err := client.Lines(ctx, q, r, lineLimit(req.Limit, identity.Limits.MaxLogLines, identity.Limits.MaxLogLines))
	if err != nil {
		return resp, err
	}
	sample := shape.Flatten(streams, s.redactor)
	groups := shape.GroupLines(sample.Lines, total)
	resultID, err := s.saveLogResult(ctx, identity, logResult{Sample: sample, Groups: groups.Assignment})
	if err != nil {
		return resp, err
	}

	resp.Data = api.LogSearchResult{
		Query:      q.String(),
		Total:      total,
		SampleSize: len(sample.Lines),
		Groups:     groups.Groups,
		Ungrouped:  groups.Ungrouped,
	}
	if n := len(sample.Lines); n > 0 {
		resp.Data.SampleRange = &api.TimeRange{From: sample.Lines[n-1].Time, To: sample.Lines[0].Time}
	}
	resp.Meta = metaFor(scope.Target, r)
	if len(resp.Data.Groups) > maxLogGroups {
		resp.Data.Groups, resp.Meta.Truncated = resp.Data.Groups[:maxLogGroups], true
	}
	resp.Meta.Sampled = int64(len(sample.Lines)) < total
	resp.Meta.ResultID = resultID
	resp.Meta.Sources = []api.SourceRef{shape.SourceRef(s.cfg.Grafana, scope.Source(), q.String(), r)}
	resp.Meta.Untrusted = []string{"data.groups[].pattern", "data.groups[].example"}
	return resp, nil
}

// QueryLogs runs native LogQL. Log queries return lines; metric queries return series.
func (s *Service) QueryLogs(ctx context.Context, identity *authz.Identity, service string, req api.LogQueryRequest) (api.Response[api.LogQueryResult], error) {
	var resp api.Response[api.LogQueryResult]
	scope, client, err := s.logScope(identity, service, req.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return resp, err
	}
	q, err := policy.ScopeLogQL(scope, req.Query)
	if err != nil {
		return resp, err
	}
	resp.Meta = metaFor(scope.Target, r)
	resp.Meta.Sources = []api.SourceRef{shape.SourceRef(s.cfg.Grafana, scope.Source(), q.String(), r)}
	resp.Data.Query = q.String()
	recordQuery(ctx, scope.Target, q.String())

	if q.IsMetric() {
		step, err := policy.ParseStep(req.Step, r, maxPoints)
		if err != nil {
			return resp, err
		}
		matrix, err := client.Matrix(ctx, q, r, step)
		if err != nil {
			return resp, err
		}
		resp.Data.Series, resp.Meta.Truncated = shape.Series(matrix, maxSeries, true)
		resp.Meta.Untrusted = []string{"data.series[].labels"}
		return resp, nil
	}

	streams, err := client.Lines(ctx, q, r, lineLimit(req.Limit, defaultLogQueryLines, identity.Limits.MaxLogLines))
	if err != nil {
		return resp, err
	}
	sample := shape.Flatten(streams, s.redactor)
	lines, truncated := shape.FitLines(sample.Lines, s.lineBudget(identity))
	if truncated {
		// Store all lines, so the agent can page through the rest.
		resultID, err := s.saveLogResult(ctx, identity, logResult{Sample: sample})
		if err != nil {
			return resp, err
		}
		resp.Meta.ResultID, resp.Meta.Truncated = resultID, true
	}
	resp.Data.Streams, resp.Data.Lines = subset(sample.Streams, lines)
	resp.Meta.Untrusted = []string{"data.lines[].line", "data.streams[]"}
	return resp, nil
}

func (s *Service) LogFields(ctx context.Context, identity *authz.Identity, service string, w api.Window) (api.Response[api.LogFields], error) {
	var resp api.Response[api.LogFields]
	scope, client, err := s.logScope(identity, service, w.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return resp, err
	}
	series, err := client.Series(ctx, scope, r)
	if err != nil {
		return resp, err
	}
	fields, err := client.DetectedFields(ctx, scope, r)
	if err != nil {
		return resp, err
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
		resp.Data.Labels = append(resp.Data.Labels, label)
	}
	sort.Slice(resp.Data.Labels, func(i, j int) bool { return resp.Data.Labels[i].Name < resp.Data.Labels[j].Name })
	for _, f := range fields {
		resp.Data.Fields = append(resp.Data.Fields, api.LogField{Name: f.Label, Type: f.Type, Cardinality: f.Cardinality, Parsers: f.Parsers})
	}
	resp.Meta = metaFor(scope.Target, r)
	resp.Meta.Untrusted = []string{"data.labels[].values"}
	return resp, nil
}

// Result pages through the lines behind a result handle, optionally of one group.
func (s *Service) Result(ctx context.Context, identity *authz.Identity, id string, group *int, offset, limit int) (api.Response[api.ResultPage], error) {
	var resp api.Response[api.ResultPage]
	_, payload, err := s.store.LoadResult(ctx, identity.Name, id)
	if err != nil {
		return resp, err
	}
	var result logResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return resp, err
	}
	lines := result.Sample.Lines
	if group != nil {
		lines = nil
		for i, g := range result.Groups {
			if g == *group {
				lines = append(lines, result.Sample.Lines[i])
			}
		}
	}
	page := api.ResultPage{Kind: resultKindLogs, Group: group, Total: len(lines), Offset: offset}
	end := min(offset+lineLimit(limit, defaultLogQueryLines, identity.Limits.MaxLogLines), len(lines))
	if offset < end {
		pageLines, truncated := shape.FitLines(lines[offset:end], s.lineBudget(identity))
		if truncated || end < len(lines) {
			next := offset + len(pageLines)
			page.NextOffset = &next
		}
		page.Streams, page.Lines = subset(result.Sample.Streams, pageLines)
	}
	resp.Data = page
	resp.Meta = api.Meta{ResultID: id, Untrusted: []string{"data.lines[].line", "data.streams[]"}}
	return resp, nil
}

func (s *Service) saveLogResult(ctx context.Context, identity *authz.Identity, result logResult) (string, error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return s.store.SaveResult(ctx, identity.Name, resultKindLogs, payload, resultTTL)
}

// lineBudget leaves room in the response for metadata.
func (s *Service) lineBudget(identity *authz.Identity) int {
	return identity.Limits.MaxResponseBytes * 3 / 4
}

// subset keeps only the streams the lines refer to and renumbers the references.
func subset(streams []map[string]string, lines []api.LogLine) ([]map[string]string, []api.LogLine) {
	index := map[int]int{}
	var kept []map[string]string
	out := make([]api.LogLine, len(lines))
	for i, line := range lines {
		n, ok := index[line.Stream]
		if !ok {
			n = len(kept)
			index[line.Stream] = n
			kept = append(kept, streams[line.Stream])
		}
		line.Stream = n
		out[i] = line
	}
	return kept, out
}

func lineLimit(requested, fallback, maximum int) int {
	if requested <= 0 {
		return min(fallback, maximum)
	}
	return min(requested, maximum)
}
