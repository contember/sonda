package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
)

const maxRequestBytes = 64 << 10

// windowFromQuery reads env, from, to and since query parameters.
func windowFromQuery(r *http.Request) (api.Window, error) {
	q := r.URL.Query()
	w := api.Window{Environment: q.Get("env"), Since: q.Get("since")}
	for name, target := range map[string]**time.Time{"from": &w.From, "to": &w.To} {
		raw := q.Get(name)
		if raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return api.Window{}, apierr.InvalidRequest("%s must be an RFC 3339 time, got %q", name, raw)
		}
		*target = &t
	}
	return w, nil
}

func intParam(r *http.Request, name string, fallback int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, apierr.InvalidRequest("%s must be a non-negative integer, got %q", name, raw)
	}
	return v, nil
}

func boolParam(r *http.Request, name string, fallback bool) (bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, apierr.InvalidRequest("%s must be true or false, got %q", name, raw)
	}
	return v, nil
}

func decodeBody(r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return apierr.InvalidRequest("request body exceeds %d bytes", maxRequestBytes)
		}
		return apierr.InvalidRequest("invalid JSON body: %v", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return apierr.InvalidRequest("request body must contain a single JSON object")
	}
	return nil
}
