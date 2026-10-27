package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contember/sonda/internal/client"
)

func sondaServer(t *testing.T, validToken string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+validToken {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"code":"unauthenticated","message":"invalid token"}}`))
			return
		}
		w.Write([]byte(`{"data":[],"meta":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runLogin(t *testing.T, stdin string, args ...string) error {
	t.Helper()
	cmd := newRootCmd()
	cmd.SetArgs(append([]string{"auth", "login"}, args...))
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd.Execute()
}

func TestLoginSavesConfigWithPrivateMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("SONDA_URL", "")
	t.Setenv("SONDA_TOKEN", "")
	srv := sondaServer(t, "sonda_good")
	path := filepath.Join(home, "sonda", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("token: sonda_old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runLogin(t, "sonda_good\n", "--url", srv.URL); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != (fileConfig{URL: srv.URL, Token: "sonda_good"}) {
		t.Errorf("config = %+v", got)
	}
}

func TestLoginRejectsInvalidToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	srv := sondaServer(t, "sonda_good")

	err := runLogin(t, "sonda_bad\n", "--url", srv.URL)
	var apiErr *client.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "unauthenticated" {
		t.Fatalf("err = %v, want unauthenticated", err)
	}
	if _, err := os.Stat(filepath.Join(home, "sonda", "config.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config was written: %v", err)
	}
}

func TestCheckConfigMode(t *testing.T) {
	tests := []struct {
		name        string
		interactive bool
		answer      string
		want        os.FileMode
	}{
		{name: "non-interactive only warns", want: 0o644},
		{name: "accepted by default", interactive: true, answer: "\n", want: 0o600},
		{name: "declined", interactive: true, answer: "n\n", want: 0o644},
		{name: "no answer", interactive: true, want: 0o644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			checkConfigMode(path, 0o644, strings.NewReader(tt.answer), &out, tt.interactive)

			if !strings.Contains(out.String(), "accessible by other users") {
				t.Errorf("no warning in %q", out.String())
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != tt.want {
				t.Errorf("mode = %04o, want %04o", perm, tt.want)
			}
		})
	}
}
