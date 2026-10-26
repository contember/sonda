package query

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

const (
	defaultLogQueryLines = 100
	maxLogGroups         = 30
	resultTTL            = 30 * time.Minute
	resultKindLogs       = "logs"
)

// logResult is the payload behind a result handle.
type logResult struct {
	Sample shape.LogSample `json:"sample"`
	// Groups holds the group index of each line, or nil when the lines were not grouped.
	Groups []int `json:"groups,omitempty"`
}

func (s *Service) logScope(identity *authz.Identity, service, env string) (authz.LogScope, logBackend, error) {
	scope, err := s.authz.LogScope(identity, service, env)
	if err != nil {
		return authz.LogScope{}, nil, err
	}
	backend, err := s.logBackend(scope)
	if err != nil {
		return authz.LogScope{}, nil, err
	}
	return scope, backend, nil
}

// SearchLogs counts all matching lines exactly, then groups a sample of the newest lines
// into patterns.
func (s *Service) SearchLogs(ctx context.Context, identity *authz.Identity, service string, req api.LogSearchRequest) (api.Response[api.LogSearchResult], error) {
	var resp api.Response[api.LogSearchResult]
	scope, backend, err := s.logScope(identity, service, req.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return resp, err
	}
	where, err := policy.ParseWhere(req.Where)
	if err != nil {
		return resp, err
	}
	if strings.TrimSpace(req.Pipeline) != "" && backend.dialect() != api.DialectLogQL {
		return resp, apierr.InvalidRequest("pipeline is supported only for Loki sources; service %q uses %s", service, backend.dialect())
	}
	filter := policy.LogFilter{Contains: req.Contains, Where: where, Pipeline: req.Pipeline}
	found, err := backend.search(ctx, r, filter, capLimit(req.Limit, identity.Limits.MaxLogLines, identity.Limits.MaxLogLines))
	if err != nil {
		return resp, err
	}
	sample := shape.Flatten(found.streams, s.redactor)
	groups := shape.GroupLines(sample.Lines, found.total)
	resultID, err := s.saveLogResult(ctx, identity, logResult{Sample: sample, Groups: groups.Assignment})
	if err != nil {
		return resp, err
	}

	resp.Data = api.LogSearchResult{
		Query:           found.query,
		Total:           found.total,
		TotalLowerBound: found.totalLowerBound,
		SampleSize:      len(sample.Lines),
		Groups:          groups.Groups,
		Ungrouped:       groups.Ungrouped,
	}
	if n := len(sample.Lines); n > 0 {
		resp.Data.SampleRange = &api.TimeRange{From: sample.Lines[n-1].Time, To: sample.Lines[0].Time}
	}
	resp.Meta = metaFor(scope.Target, r)
	if len(resp.Data.Groups) > maxLogGroups {
		resp.Data.Groups, resp.Meta.Truncated = resp.Data.Groups[:maxLogGroups], true
	}
	resp.Meta.Sampled = int64(len(sample.Lines)) < found.total
	resp.Meta.ResultID = resultID
	resp.Meta.Sources = []api.SourceRef{found.source}
	resp.Meta.Untrusted = []string{"data.groups[].pattern", "data.groups[].example"}
	return resp, nil
}

// QueryLogs runs a native query in the dialect of the service's log source. A query returns
// either lines or series.
func (s *Service) QueryLogs(ctx context.Context, identity *authz.Identity, service string, req api.LogQueryRequest) (api.Response[api.LogQueryResult], error) {
	var resp api.Response[api.LogQueryResult]
	scope, backend, err := s.logScope(identity, service, req.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(req.Window, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return resp, err
	}
	result, err := backend.query(ctx, r, req.Query, capLimit(req.Limit, defaultLogQueryLines, identity.Limits.MaxLogLines), req.Step)
	if err != nil {
		return resp, err
	}
	resp.Meta = metaFor(scope.Target, r)
	resp.Meta.Sources = []api.SourceRef{result.source}
	resp.Data.Query = result.query

	if result.series != nil {
		resp.Data.Series, resp.Meta.Truncated = shape.Series(result.series, maxSeries, true)
		resp.Meta.Untrusted = []string{"data.series[].labels"}
		return resp, nil
	}

	sample := shape.Flatten(result.streams, s.redactor)
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
	scope, backend, err := s.logScope(identity, service, w.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultSince)
	if err != nil {
		return resp, err
	}
	fields, err := backend.fields(ctx, r)
	if err != nil {
		return resp, err
	}
	resp.Data = fields
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
	end := min(offset+capLimit(limit, defaultLogQueryLines, identity.Limits.MaxLogLines), len(lines))
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

func capLimit(requested, fallback, maximum int) int {
	if requested <= 0 {
		return min(fallback, maximum)
	}
	return min(requested, maximum)
}
