package upstream

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostJSONRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte(" "), maxBodyBytes+1))
	}))
	defer srv.Close()
	status, _, err := PostJSON(context.Background(), srv.Client(), "test", srv.URL, map[string]string{}, 0)
	var tooLarge *TooLargeError
	if !errors.As(err, &tooLarge) || status != http.StatusOK || tooLarge.Limit != maxBodyBytes {
		t.Fatalf("status = %d, err = %v", status, err)
	}
}

func TestPostJSONLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte(" "), 101))
	}))
	defer srv.Close()
	var tooLarge *TooLargeError
	if _, _, err := PostJSON(context.Background(), srv.Client(), "test", srv.URL, nil, 100); !errors.As(err, &tooLarge) || tooLarge.Limit != 100 {
		t.Fatalf("err = %v", err)
	}
	if _, body, err := PostJSON(context.Background(), srv.Client(), "test", srv.URL, nil, 101); err != nil || len(body) != 101 {
		t.Fatalf("len = %d, err = %v", len(body), err)
	}
}
