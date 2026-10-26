// Package upstream builds HTTP clients that apply a source's auth and headers, so
// connectors do not know how a source authenticates.
package upstream

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
)

const maxBodyBytes = 32 << 20

func HTTPClient(src *config.Source) *http.Client {
	base := http.DefaultTransport
	if src.RootCAs != nil {
		// The settings of http.DefaultTransport, with the source's roots.
		base = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			TLSClientConfig:       &tls.Config{RootCAs: src.RootCAs, MinVersion: tls.VersionTLS12},
		}
	}
	// The config validates the URL; an unparsable one leaves origin nil and sends no credentials.
	origin, _ := url.Parse(src.URL)
	return &http.Client{Transport: &authTransport{source: src, origin: origin, base: base}}
}

type authTransport struct {
	source *config.Source
	origin *url.URL
	base   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirects pass through the transport too; credentials and headers go only to the
	// source's own origin, never to a host a response redirected to.
	if t.origin == nil || req.URL.Scheme != t.origin.Scheme || req.URL.Host != t.origin.Host {
		return t.base.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	for name, value := range t.source.Headers {
		req.Header.Set(name, value)
	}
	switch t.source.Auth.Type {
	case config.AuthBearer:
		token := t.source.Auth.Token
		if t.source.Auth.TokenFile != "" {
			data, err := os.ReadFile(t.source.Auth.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("read token: %w", err)
			}
			token = strings.TrimSpace(string(data))
		}
		req.Header.Set("Authorization", "Bearer "+token)
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
