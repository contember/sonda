// Package contember is a client for the Contember Content API (GraphQL). It runs only
// introspection and queries checked by policy; it never sends mutations.
package contember

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
	"github.com/contember/sonda/internal/policy"
)

type Client struct {
	http   *http.Client
	source *config.Source
}

func New(src *config.Source) *Client {
	return &Client{http: upstream.HTTPClient(src), source: src}
}

// Introspect returns the introspection result of the project stage as the API key's role
// sees it.
func (c *Client) Introspect(ctx context.Context, scope authz.ContemberScope) ([]byte, error) {
	data, err := c.post(ctx, scope, introspectionQuery, false, 0)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Relations returns the relation model of the project stage as the role sees it, from the
// Content API's schema root field.
func (c *Client) Relations(ctx context.Context, scope authz.ContemberScope) ([]byte, error) {
	return c.post(ctx, scope, relationsQuery, false, 0)
}

const relationsQuery = `query { schema { entities { name fields { name ... on _Relation { targetEntity ownedBy inversedBy } } } } }`

// Query runs a checked query and returns its data object. The response is read up to
// readBytes; a larger one is limit_exceeded and reports maxResponseBytes, the limit the agent
// has to fit, since the response is not read further.
func (c *Client) Query(ctx context.Context, q policy.ContemberGraphQL, readBytes, maxResponseBytes int) (json.RawMessage, error) {
	data, err := c.post(ctx, q.Scope(), q.String(), true, readBytes)
	var tooLarge *upstream.TooLargeError
	if errors.As(err, &tooLarge) && tooLarge.Status >= 200 && tooLarge.Status < 300 {
		return nil, apierr.New(api.CodeLimitExceeded, "the response is larger than %d bytes, the limit is %d; lower the limits or select fewer fields", tooLarge.Limit, maxResponseBytes)
	}
	return data, err
}

// ContentURL is the Content API endpoint of a project stage.
func (c *Client) ContentURL(scope authz.ContemberScope) string {
	return strings.TrimRight(c.source.URL, "/") + "/content/" + url.PathEscape(scope.Project()) + "/" + url.PathEscape(scope.Stage())
}

type response struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// post sends the query without variables: policy inlines them. Response extensions are
// dropped, because a debug engine puts SQL with bound values there.
// agentQuery reports GraphQL errors as invalid_query, because the agent can fix its query;
// errors of Sonda's own schema queries are upstream errors.
func (c *Client) post(ctx context.Context, scope authz.ContemberScope, query string, agentQuery bool, maxBytes int) (json.RawMessage, error) {
	status, body, err := upstream.PostJSON(ctx, c.http, c.source.Name, c.ContentURL(scope), map[string]string{"query": query}, maxBytes)
	var tooLarge *upstream.TooLargeError
	if errors.As(err, &tooLarge) {
		// Only the agent's own successful query can be made smaller; Query maps that case.
		if agentQuery && status >= 200 && status < 300 {
			return nil, err
		}
		return nil, apierr.Upstream("%s", tooLarge.Error())
	}
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, apierr.Upstream("source %s rejected the API key for project %s (HTTP %d)", c.source.Name, scope.Project(), status)
	case status == http.StatusNotFound:
		return nil, apierr.Upstream("source %s has no project %s with stage %s", c.source.Name, scope.Project(), scope.Stage())
	case status >= 500:
		return nil, upstream.Wrap(c.source.Name, upstream.NewStatusError(c.source.Name, status, body))
	}
	var resp response
	if err := json.Unmarshal(body, &resp); err != nil {
		if status < 200 || status >= 300 {
			return nil, upstream.Wrap(c.source.Name, upstream.NewStatusError(c.source.Name, status, body))
		}
		return nil, apierr.Upstream("source %s returned invalid JSON: %v", c.source.Name, err)
	}
	if len(resp.Errors) > 0 {
		messages := make([]string, 0, min(len(resp.Errors), 3))
		for _, e := range resp.Errors[:min(len(resp.Errors), 3)] {
			messages = append(messages, truncate(e.Message, 300))
		}
		if !agentQuery {
			return nil, apierr.Upstream("source %s rejected the schema query: %s", c.source.Name, strings.Join(messages, "; "))
		}
		return nil, apierr.InvalidQuery("Contember rejected the query: %s", strings.Join(messages, "; "))
	}
	if status < 200 || status >= 300 {
		return nil, upstream.Wrap(c.source.Name, upstream.NewStatusError(c.source.Name, status, body))
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, apierr.Upstream("source %s returned no data", c.source.Name)
	}
	return resp.Data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// introspectionQuery is the standard introspection query without descriptions and
// directives, which the guard does not use.
const introspectionQuery = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
  }
}
fragment FullType on __Type {
  kind
  name
  fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
}`
