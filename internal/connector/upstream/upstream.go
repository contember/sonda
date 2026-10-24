// Package upstream builds HTTP clients that apply a source's auth and headers, so
// connectors do not know how a source authenticates.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
)

const maxBodyBytes = 32 << 20

func HTTPClient(src *config.Source) *http.Client {
	return &http.Client{Transport: &authTransport{source: src, base: http.DefaultTransport}}
}

type authTransport struct {
	source *config.Source
	base   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for name, value := range t.source.Headers {
		req.Header.Set(name, value)
	}
	switch t.source.Auth.Type {
	case config.AuthBearer:
		req.Header.Set("Authorization", "Bearer "+t.source.Auth.Token)
	case config.AuthBasic:
		req.SetBasicAuth(t.source.Auth.Username, t.source.Auth.Password)
	}
	return t.base.RoundTrip(req)
}

// StatusError is returned for non-2xx responses, so callers can react to 404.
type StatusError struct {
	Source string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("source %s returned HTTP %d: %s", e.Source, e.Status, e.Body)
}

func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}

// GetJSON fetches a URL and decodes the JSON body into out.
func GetJSON(ctx context.Context, client *http.Client, source, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Wrap(source, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return Wrap(source, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{Source: source, Status: resp.StatusCode, Body: truncate(strings.TrimSpace(string(body)), 300)}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return apierr.Upstream("source %s returned invalid JSON: %v", source, err)
	}
	return nil
}

// Wrap converts a transport or status error into a client-visible error. Context errors
// pass through, so the HTTP layer can report timeouts.
func Wrap(source string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	if _, ok := apierr.As(err); ok {
		return err
	}
	var se *StatusError
	if errors.As(err, &se) {
		return apierr.Upstream("%s", se.Error())
	}
	return apierr.Upstream("source %s is unreachable: %v", source, err)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// PostJSON sends body as JSON and returns the status and the body of the response, so the
// caller can read errors that come with a non-2xx status (GraphQL does that).
func PostJSON(ctx context.Context, client *http.Client, source, url string, body any) (int, []byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, Wrap(source, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return 0, nil, Wrap(source, err)
	}
	// A cut body would only fail as invalid JSON; the agent can fix this by asking for less.
	if len(data) > maxBodyBytes {
		return 0, nil, apierr.New(api.CodeLimitExceeded, "source %s returned more than %d MB; lower the limits", source, maxBodyBytes>>20)
	}
	return resp.StatusCode, data, nil
}

// NewStatusError builds the error of a non-2xx response with a shortened body.
func NewStatusError(source string, status int, body []byte) *StatusError {
	return &StatusError{Source: source, Status: status, Body: truncate(strings.TrimSpace(string(body)), 300)}
}
