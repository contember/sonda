package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/store"
)

const adminToken = "admin-token-admin-token-admin-token"

type testEnv struct {
	server *httptest.Server
	client *http.Client
	store  *store.Store
	authz  *authz.Authorizer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg, err := config.Parse([]byte(`
admin:
  token: `+adminToken+`
sources:
  loki: { type: loki, url: "http://loki:3100" }
projects:
  api:
    services:
      api:
        environments:
          production:
            logs: { source: loki, selector: '{app="api"}' }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "sonda.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	handler, err := New(cfg, st, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &testEnv{server: server, client: client, store: st, authz: authz.New(cfg, st)}
}

func (e *testEnv) post(t *testing.T, path string, form url.Values) (int, string) {
	t.Helper()
	resp, err := e.client.PostForm(e.server.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (e *testEnv) login(t *testing.T) {
	t.Helper()
	if status, _ := e.post(t, "/admin/login", url.Values{"token": {adminToken}}); status != http.StatusSeeOther {
		t.Fatalf("login: status %d", status)
	}
}

var tokenPattern = regexp.MustCompile(`<code id="token">(sonda_[A-Z0-9]+)</code>`)

func shownToken(t *testing.T, body string) string {
	t.Helper()
	m := tokenPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no token in page:\n%s", body)
	}
	return m[1]
}

func logsGrant() string {
	return grantValue(identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityLogs})
}

func TestRequiresSession(t *testing.T) {
	env := newTestEnv(t)
	resp, err := env.client.Get(env.server.URL + "/admin/identities")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin/login" {
		t.Errorf("status %d, location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if status, _ := env.post(t, "/admin/login", url.Values{"token": {"wrong"}}); status != http.StatusUnauthorized {
		t.Errorf("wrong admin token: status %d", status)
	}
	if status, _ := env.post(t, "/admin/identities", url.Values{"name": {"agent"}, "grant": {logsGrant()}}); status != http.StatusSeeOther {
		t.Errorf("create without session: status %d", status)
	}
}

func TestCreateRotateAndDeleteIdentity(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.login(t)

	status, body := env.post(t, "/admin/identities", url.Values{
		"name":                {"agent"},
		"grant":               {logsGrant()},
		"requests_per_minute": {"30"},
	})
	if status != http.StatusOK {
		t.Fatalf("create: status %d\n%s", status, body)
	}
	first := shownToken(t, body)
	identity, err := env.authz.Authenticate(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.authz.LogScope(identity, "api", "production"); err != nil {
		t.Errorf("granted scope: %v", err)
	}
	if identity.Limits.RequestsPerMinute != 30 {
		t.Errorf("requests_per_minute = %d", identity.Limits.RequestsPerMinute)
	}

	status, body = env.post(t, "/admin/identities/agent/token", nil)
	if status != http.StatusOK {
		t.Fatalf("rotate: status %d", status)
	}
	second := shownToken(t, body)
	if _, err := env.authz.Authenticate(ctx, first); err == nil {
		t.Error("old token still works after rotation")
	}
	if _, err := env.authz.Authenticate(ctx, second); err != nil {
		t.Errorf("new token: %v", err)
	}

	if status, _ := env.post(t, "/admin/identities/agent/delete", nil); status != http.StatusSeeOther {
		t.Fatalf("delete: status %d", status)
	}
	if _, err := env.authz.Authenticate(ctx, second); err == nil {
		t.Error("token works after delete")
	}

	records, err := env.store.ListAudit(ctx, store.AuditFilter{Identity: auditIdentity, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range records {
		paths = append(paths, r.Path)
	}
	want := "/admin/identities/agent/delete /admin/identities/agent/token /admin/identities /admin/login"
	if got := strings.Join(paths, " "); got != want {
		t.Errorf("audited admin actions: %s\nwant: %s", got, want)
	}
}

func TestRejectsInvalidInput(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	unconfigured := grantValue(identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityMetrics})
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{"unconfigured capability", url.Values{"name": {"agent"}, "grant": {unconfigured}}, "invalid grant"},
		{"no grant", url.Values{"name": {"agent"}}, "select at least one grant"},
		{"bad name", url.Values{"name": {"Agent!"}, "grant": {logsGrant()}}, "name must be"},
		{"bad limit", url.Values{"name": {"agent"}, "grant": {logsGrant()}, "max_range": {"soon"}}, "invalid duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := env.post(t, "/admin/identities", tt.form)
			if status != http.StatusUnprocessableEntity || !strings.Contains(body, tt.want) {
				t.Errorf("status %d, body does not contain %q", status, tt.want)
			}
		})
	}
	if list, _ := env.store.List(context.Background()); len(list) != 0 {
		t.Errorf("identities created from invalid input: %+v", list)
	}
}

func TestRejectsCrossOriginPost(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/admin/identities", strings.NewReader(url.Values{"name": {"agent"}, "grant": {logsGrant()}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := env.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d", resp.StatusCode)
	}
}
