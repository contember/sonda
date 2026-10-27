// Package sentry reads issues, events, releases and spans from the Sentry REST API.
// Issue search sends the project ID as a parameter, which Sentry ANDs with the query, so a
// free-text query cannot reach other projects; spans use the organization events endpoint
// and are checked against the scope.
package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
)

type Client struct {
	source *config.Source
	http   *http.Client

	mu         sync.Mutex
	projectIDs map[string]string // slug → numeric ID
}

func New(src *config.Source, client *http.Client) *Client {
	return &Client{source: src, http: client, projectIDs: map[string]string{}}
}

type Issue struct {
	ID        string    `json:"id"`
	ShortID   string    `json:"shortId"`
	Title     string    `json:"title"`
	Culprit   string    `json:"culprit"`
	Level     string    `json:"level"`
	Count     string    `json:"count"`
	UserCount int64     `json:"userCount"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Permalink string    `json:"permalink"`
	Project   struct {
		Slug string `json:"slug"`
	} `json:"project"`
}

type Event struct {
	EventID     string    `json:"eventID"`
	DateCreated time.Time `json:"dateCreated"`
	Message     string    `json:"message"`
	Release     *struct {
		Version string `json:"version"`
	} `json:"release"`
	Tags []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
	Contexts struct {
		Trace struct {
			TraceID string `json:"trace_id"`
		} `json:"trace"`
	} `json:"contexts"`
	Entries []struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	} `json:"entries"`
}

type ExceptionData struct {
	Values []struct {
		Type       string `json:"type"`
		Value      string `json:"value"`
		Stacktrace *struct {
			Frames []Frame `json:"frames"`
		} `json:"stacktrace"`
	} `json:"values"`
}

type Frame struct {
	Filename string `json:"filename"`
	AbsPath  string `json:"absPath"`
	Function string `json:"function"`
	LineNo   int    `json:"lineNo"`
	ColNo    int    `json:"colNo"`
	InApp    bool   `json:"inApp"`
}

type Release struct {
	Version     string    `json:"version"`
	DateCreated time.Time `json:"dateCreated"`
	LastDeploy  *struct {
		Environment  string    `json:"environment"`
		DateFinished time.Time `json:"dateFinished"`
	} `json:"lastDeploy"`
}

var issueID = regexp.MustCompile(`^[0-9]+$`)

// ListIssues returns issues of the scope's project and environment that were seen in the
// range. Count and user count cover the range. The project issues endpoint ignores the
// range, so this uses the organization one.
func (c *Client) ListIssues(ctx context.Context, scope authz.ErrorScope, r api.TimeRange, query, sort string, limit int) ([]Issue, error) {
	projectID, err := c.projectID(ctx, scope)
	if err != nil {
		return nil, err
	}
	params := url.Values{
		"project":     {projectID},
		"start":       {formatTime(r.From)},
		"end":         {formatTime(r.To)},
		"environment": {scope.SentryEnvironment()},
		"query":       {scopedQuery(scope, query)},
		"sort":        {sort},
		"limit":       {strconv.Itoa(limit)},
	}
	var issues []Issue
	if err := c.get(ctx, c.orgPath("issues/"), params, &issues); err != nil {
		return nil, err
	}
	scoped := issues[:0]
	for _, issue := range issues {
		if issue.Project.Slug == scope.Project() {
			scoped = append(scoped, issue)
		}
	}
	return scoped, nil
}

// GetIssue returns not_found for issues of other projects, so IDs cannot be probed.
func (c *Client) GetIssue(ctx context.Context, scope authz.ErrorScope, id string) (Issue, error) {
	if !issueID.MatchString(id) {
		return Issue{}, apierr.InvalidRequest("issue id must be numeric, got %q", id)
	}
	var issue Issue
	err := c.fetch(ctx, c.orgPath("issues/"+id+"/"), nil, &issue)
	if upstream.IsNotFound(err) || (err == nil && issue.Project.Slug != scope.Project()) {
		return Issue{}, apierr.NotFound("issue %s not found in %s/%s", id, scope.Service(), scope.Environment())
	}
	if err != nil {
		return Issue{}, upstream.Wrap(c.source.Name, err)
	}
	return issue, nil
}

// LatestEvent returns the newest event of the issue in the scope's environment that matches
// the scope's query. An issue without such events is reported as not found.
func (c *Client) LatestEvent(ctx context.Context, scope authz.ErrorScope, id string) (Event, error) {
	if !issueID.MatchString(id) {
		return Event{}, apierr.InvalidRequest("issue id must be numeric, got %q", id)
	}
	var events []Event
	params := url.Values{
		"environment": {scope.SentryEnvironment()},
		"query":       {scope.SentryQuery()},
		"full":        {"true"},
		"per_page":    {"1"},
	}
	err := c.fetch(ctx, c.orgPath("issues/"+id+"/events/"), params, &events)
	if upstream.IsNotFound(err) || (err == nil && len(events) == 0) {
		return Event{}, apierr.NotFound("issue %s has no events in %s/%s", id, scope.Service(), scope.Environment())
	}
	if err != nil {
		return Event{}, upstream.Wrap(c.source.Name, err)
	}
	return events[0], nil
}

// Releases returns the newest releases of the scope's project.
func (c *Client) Releases(ctx context.Context, scope authz.ErrorScope, limit int) ([]Release, error) {
	var releases []Release
	params := url.Values{"per_page": {strconv.Itoa(limit)}}
	if err := c.get(ctx, c.projectPath(scope, "releases/"), params, &releases); err != nil {
		return nil, err
	}
	return releases, nil
}

// scopedQuery puts the scope's terms before the agent's query. Issue search has no OR, so
// every term is ANDed; going first, the scope's terms cannot end up inside an agent's quote.
func scopedQuery(scope authz.ErrorScope, query string) string {
	return strings.TrimSpace(scope.SentryQuery() + " " + query)
}

// projectID resolves the project slug of the scope once per client.
func (c *Client) projectID(ctx context.Context, scope authz.ErrorScope) (string, error) {
	c.mu.Lock()
	id, ok := c.projectIDs[scope.Project()]
	c.mu.Unlock()
	if ok {
		return id, nil
	}
	var project struct {
		ID string `json:"id"`
	}
	if err := c.get(ctx, c.projectPath(scope, ""), nil, &project); err != nil {
		return "", err
	}
	if !issueID.MatchString(project.ID) {
		return "", apierr.Upstream("source %s returned project ID %q for %s", c.source.Name, project.ID, scope.Project())
	}
	c.mu.Lock()
	c.projectIDs[scope.Project()] = project.ID
	c.mu.Unlock()
	return project.ID, nil
}

func (c *Client) projectPath(scope authz.ErrorScope, suffix string) string {
	return "/api/0/projects/" + url.PathEscape(c.source.SentryOrg) + "/" + url.PathEscape(scope.Project()) + "/" + suffix
}

func (c *Client) orgPath(suffix string) string {
	return "/api/0/organizations/" + url.PathEscape(c.source.SentryOrg) + "/" + suffix
}

func (c *Client) get(ctx context.Context, path string, params url.Values, out any) error {
	err := c.fetch(ctx, path, params, out)
	var se *upstream.StatusError
	if errors.As(err, &se) && se.Status == http.StatusBadRequest {
		return apierr.InvalidQuery("source %s rejected the query: %s", c.source.Name, se.Body)
	}
	if err != nil {
		return upstream.Wrap(c.source.Name, err)
	}
	return nil
}

// fetch returns 404 as an upstream.StatusError, so callers can turn it into not_found.
func (c *Client) fetch(ctx context.Context, path string, params url.Values, out any) error {
	target := strings.TrimRight(c.source.URL, "/") + path
	if len(params) > 0 {
		target += "?" + params.Encode()
	}
	return upstream.GetJSON(ctx, c.http, c.source.Name, target, out)
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05")
}
