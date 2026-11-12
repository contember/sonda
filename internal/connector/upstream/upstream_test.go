package upstream

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
)

func TestCredentialsStayOnSourceOrigin(t *testing.T) {
	type seen struct{ auth, header string }
	var foreign, own []seen
	foreignServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreign = append(foreign, seen{r.Header.Get("Authorization"), r.Header.Get("X-Secret")})
	}))
	defer foreignServer.Close()
	ownServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		own = append(own, seen{r.Header.Get("Authorization"), r.Header.Get("X-Secret")})
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/away":
			http.Redirect(w, r, foreignServer.URL+"/target", http.StatusFound)
		}
	}))
	defer ownServer.Close()

	client := HTTPClient(&config.Source{
		Name:    "test",
		URL:     ownServer.URL,
		Auth:    config.Auth{Type: config.AuthBearer, Token: "secret-token"},
		Headers: map[string]string{"X-Secret": "secret-header"},
	}, nil)
	for _, path := range []string{"/same", "/away"} {
		resp, err := client.Get(ownServer.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	want := seen{"Bearer secret-token", "secret-header"}
	if len(own) != 3 {
		t.Fatalf("own origin got %d requests, want 3", len(own))
	}
	for i, s := range own {
		if s != want {
			t.Errorf("own origin request %d got %+v, want %+v", i, s, want)
		}
	}
	if len(foreign) != 1 {
		t.Fatalf("foreign origin got %d requests, want 1", len(foreign))
	}
	if foreign[0] != (seen{}) {
		t.Errorf("foreign origin got credentials %+v", foreign[0])
	}
}

type fakeTokens struct {
	token string
	err   error
}

func (f fakeTokens) Token(context.Context) (string, error) { return f.token, f.err }

func TestEKSAuth(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer server.Close()
	src := &config.Source{Name: "eks", URL: server.URL, Auth: config.Auth{Type: config.AuthEKS}}

	resp, err := HTTPClient(src, fakeTokens{token: "k8s-aws-v1.abc"}).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "Bearer k8s-aws-v1.abc" {
		t.Errorf("Authorization = %q", got)
	}

	// A credential failure is not shown to clients: its message can name principals.
	_, err = HTTPClient(src, fakeTokens{err: errors.New("AccessDenied for arn:aws:iam::1:role/sonda")}).Get(server.URL)
	wrapped := Wrap("eks", err)
	if _, ok := apierr.As(wrapped); ok {
		t.Errorf("credential failure became a client-visible error: %v", wrapped)
	}
	if !strings.Contains(wrapped.Error(), "AccessDenied") {
		t.Errorf("credential failure lost its cause: %v", wrapped)
	}
}

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
