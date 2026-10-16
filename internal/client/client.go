// Package client is the HTTP client for the Sonda API used by the CLI.
// It imports only the api package, so the CLI does not link server dependencies.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/contember/sonda/api"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 2 * time.Minute},
	}
}

// Error is an API error response, or a transport failure with Code empty.
type Error struct {
	Status  int
	Code    api.ErrorCode
	Message string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Get returns the raw JSON body, so the CLI can pass it through unchanged.
func (c *Client) Get(path string, params url.Values) ([]byte, error) {
	target := c.baseURL + path
	if len(params) > 0 {
		target += "?" + params.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) Post(path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	if resp.StatusCode >= 300 {
		var errResp api.ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Code != "" {
			return nil, &Error{Status: resp.StatusCode, Code: errResp.Error.Code, Message: errResp.Error.Message}
		}
		return nil, &Error{Status: resp.StatusCode, Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	return body, nil
}
