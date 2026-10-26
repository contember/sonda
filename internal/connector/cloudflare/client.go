// Package cloudflare queries the Cloudflare Workers Observability and GraphQL Analytics APIs.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
)

const (
	maxBodyBytes   = 32 << 20
	maxErrorLength = 300
)

type Client struct {
	source *config.Source
	http   *http.Client
}

func New(src *config.Source, client *http.Client) *Client {
	return &Client{source: src, http: client}
}

// envelope is the response of every Cloudflare v4 API call.
type envelope[T any] struct {
	Success bool       `json:"success"`
	Errors  []apiError `json:"errors"`
	Result  T          `json:"result"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// call posts body to an account endpoint and returns the result of a successful envelope.
func call[T any](ctx context.Context, c *Client, path string, body []byte) (T, error) {
	var resp envelope[T]
	target := strings.TrimRight(c.source.URL, "/") + "/accounts/" + url.PathEscape(c.source.CloudflareAccountID) + path
	if err := c.post(ctx, target, body, &resp); err != nil {
		return resp.Result, err
	}
	if !resp.Success {
		return resp.Result, apierr.Upstream("source %s failed: %s", c.source.Name, errorMessage(resp.Errors, "no error message"))
	}
	return resp.Result, nil
}

// post sends a JSON body and decodes the JSON response. HTTP 400 means Cloudflare rejected
// the query, so it is reported as a query error with Cloudflare's message.
func (c *Client) post(ctx context.Context, target string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return upstream.Wrap(c.source.Name, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return upstream.Wrap(c.source.Name, err)
	}
	if resp.StatusCode == http.StatusBadRequest {
		return apierr.InvalidQuery("source %s rejected the query: %s", c.source.Name, responseError(data))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return upstream.Wrap(c.source.Name, &upstream.StatusError{Source: c.source.Name, Status: resp.StatusCode, Body: responseError(data)})
	}
	if err := json.Unmarshal(data, out); err != nil {
		return apierr.Upstream("source %s returned invalid JSON: %v", c.source.Name, err)
	}
	return nil
}

// responseError prefers the messages of a Cloudflare error envelope over the raw body.
func responseError(data []byte) string {
	var resp envelope[json.RawMessage]
	if json.Unmarshal(data, &resp) == nil && len(resp.Errors) > 0 {
		return errorMessage(resp.Errors, "")
	}
	text := strings.TrimSpace(string(data))
	if len(text) > maxErrorLength {
		return text[:maxErrorLength] + "…"
	}
	return text
}

func errorMessage(errors []apiError, fallback string) string {
	if len(errors) == 0 {
		return fallback
	}
	return errors[0].Message
}
