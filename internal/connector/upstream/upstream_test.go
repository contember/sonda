package upstream

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
)

func TestPostJSONRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte(" "), maxBodyBytes+1))
	}))
	defer srv.Close()
	_, _, err := PostJSON(context.Background(), srv.Client(), "test", srv.URL, map[string]string{})
	if e, ok := apierr.As(err); !ok || e.Code != api.CodeLimitExceeded {
		t.Fatalf("err = %v", err)
	}
}
