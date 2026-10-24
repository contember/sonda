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
	status, _, err := PostJSON(context.Background(), srv.Client(), "test", srv.URL, map[string]string{})
	var tooLarge *TooLargeError
	if !errors.As(err, &tooLarge) || status != http.StatusOK {
		t.Fatalf("status = %d, err = %v", status, err)
	}
}
