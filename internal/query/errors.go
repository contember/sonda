package query

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/sentry"
	"github.com/contember/sonda/internal/policy"
)

const (
	defaultErrorsSince = 24 * time.Hour
	defaultIssueLimit  = 25
	maxIssueLimit      = 100
	defaultIssueQuery  = "is:unresolved"
	maxFrames          = 20
	maxReleases        = 10
)

var issueUntrusted = []string{"data[].title", "data[].culprit"}

func (s *Service) errorScope(identity *authz.Identity, service, env string) (authz.ErrorScope, *sentry.Client, error) {
	scope, err := s.authz.ErrorScope(identity, service, env)
	if err != nil {
		return authz.ErrorScope{}, nil, err
	}
	return scope, s.connectors.Sentry[scope.Source().Name], nil
}

// ListErrors returns issues seen in the range, most frequent first.
func (s *Service) ListErrors(ctx context.Context, identity *authz.Identity, service string, w api.Window, query string, limit int) (api.Response[[]api.Issue], error) {
	var resp api.Response[[]api.Issue]
	scope, client, err := s.errorScope(identity, service, w.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultErrorsSince)
	if err != nil {
		return resp, err
	}
	if query == "" {
		query = defaultIssueQuery
	}
	if limit <= 0 {
		limit = defaultIssueLimit
	}
	recordQuery(ctx, scope.Target, "sentry issues: "+query)
	issues, err := client.ListIssues(ctx, scope, r, query, "freq", min(limit, maxIssueLimit))
	if err != nil {
		return resp, err
	}
	resp.Data = make([]api.Issue, 0, len(issues))
	for _, issue := range issues {
		resp.Data = append(resp.Data, s.issue(issue, r))
	}
	resp.Meta = metaFor(scope.Target, r)
	resp.Meta.Sources = []api.SourceRef{{Kind: string(config.SourceSentry), Query: query}}
	resp.Meta.Untrusted = issueUntrusted
	return resp, nil
}

func (s *Service) GetError(ctx context.Context, identity *authz.Identity, service, env, id string) (api.Response[api.IssueDetail], error) {
	var resp api.Response[api.IssueDetail]
	scope, client, err := s.errorScope(identity, service, env)
	if err != nil {
		return resp, err
	}
	recordQuery(ctx, scope.Target, "sentry issue: "+id)
	issue, err := client.GetIssue(ctx, scope, id)
	if err != nil {
		return resp, err
	}
	event, err := client.LatestEvent(ctx, scope, id)
	if err != nil {
		return resp, err
	}
	// Count and users of a single issue are totals; the range only marks "new".
	resp.Data = api.IssueDetail{Issue: s.issue(issue, api.TimeRange{}), LatestEvent: s.event(event)}
	resp.Meta = api.Meta{Service: scope.Service(), Environment: scope.Environment()}
	resp.Meta.Sources = []api.SourceRef{{Kind: string(config.SourceSentry), URL: issue.Permalink}}
	resp.Meta.Untrusted = []string{"data.issue.title", "data.issue.culprit", "data.latestEvent"}
	return resp, nil
}

func (s *Service) Releases(ctx context.Context, identity *authz.Identity, service string, w api.Window) (api.Response[[]api.Release], error) {
	var resp api.Response[[]api.Release]
	scope, client, err := s.errorScope(identity, service, w.Environment)
	if err != nil {
		return resp, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultErrorsSince)
	if err != nil {
		return resp, err
	}
	releases, err := s.releases(ctx, scope, client, r)
	if err != nil {
		return resp, err
	}
	resp.Data = releases
	resp.Meta = metaFor(scope.Target, r)
	return resp, nil
}

// releases returns releases created or deployed inside the range, newest first.
func (s *Service) releases(ctx context.Context, scope authz.ErrorScope, client *sentry.Client, r api.TimeRange) ([]api.Release, error) {
	recordQuery(ctx, scope.Target, "sentry releases")
	raw, err := client.Releases(ctx, scope, maxReleases)
	if err != nil {
		return nil, err
	}
	releases := []api.Release{}
	for _, rel := range raw {
		inRange := !rel.DateCreated.Before(r.From) && !rel.DateCreated.After(r.To)
		release := api.Release{Version: rel.Version, Created: rel.DateCreated}
		if rel.LastDeploy != nil {
			release.LastDeploy = &api.Deploy{Environment: rel.LastDeploy.Environment, Finished: rel.LastDeploy.DateFinished}
			inRange = inRange || !rel.LastDeploy.DateFinished.Before(r.From)
		}
		if inRange {
			releases = append(releases, release)
		}
	}
	return releases, nil
}

func (s *Service) issue(issue sentry.Issue, r api.TimeRange) api.Issue {
	count, _ := strconv.ParseInt(issue.Count, 10, 64)
	return api.Issue{
		ID:        issue.ID,
		ShortID:   issue.ShortID,
		Title:     s.redactor.Redact(issue.Title),
		Culprit:   s.redactor.Redact(issue.Culprit),
		Level:     issue.Level,
		Count:     count,
		Users:     issue.UserCount,
		FirstSeen: issue.FirstSeen,
		LastSeen:  issue.LastSeen,
		New:       !r.From.IsZero() && !issue.FirstSeen.Before(r.From),
		Link:      issue.Permalink,
	}
}

func (s *Service) event(e sentry.Event) *api.Event {
	event := &api.Event{
		ID:        e.EventID,
		Timestamp: e.DateCreated,
		Message:   s.redactor.Redact(e.Message),
		TraceID:   e.Contexts.Trace.TraceID,
		Tags:      map[string]string{},
	}
	if e.Release != nil {
		event.Release = e.Release.Version
	}
	for _, tag := range e.Tags {
		event.Tags[tag.Key] = s.redactor.Redact(tag.Value)
	}
	for _, entry := range e.Entries {
		if entry.Type != "exception" {
			continue
		}
		var data sentry.ExceptionData
		if json.Unmarshal(entry.Data, &data) != nil {
			continue
		}
		for _, v := range data.Values {
			exception := api.Exception{Type: v.Type, Value: s.redactor.Redact(v.Value)}
			if v.Stacktrace != nil {
				exception.Frames = frames(v.Stacktrace.Frames)
			}
			event.Exceptions = append(event.Exceptions, exception)
		}
	}
	return event
}

// frames returns the frames newest first. When the stack has in-app frames, library
// frames are dropped to save space.
func frames(raw []sentry.Frame) []api.Frame {
	hasInApp := slices.ContainsFunc(raw, func(f sentry.Frame) bool { return f.InApp })
	var out []api.Frame
	for i := len(raw) - 1; i >= 0 && len(out) < maxFrames; i-- {
		f := raw[i]
		if hasInApp && !f.InApp {
			continue
		}
		file := f.Filename
		if file == "" {
			file = f.AbsPath
		}
		out = append(out, api.Frame{File: file, Function: f.Function, Line: f.LineNo, Column: f.ColNo, InApp: f.InApp})
	}
	return out
}
