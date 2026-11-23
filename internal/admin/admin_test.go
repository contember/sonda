package admin

import (
	"context"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/issuer"
	"github.com/contember/sonda/internal/store"
)

const adminToken = "admin-token-admin-token-admin-token"

type testEnv struct {
	server *httptest.Server
	client *http.Client
	store  *store.Store
	authz  *authz.Authorizer
	cfg    *config.Config
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg, err := config.Parse([]byte(`
admin:
  token: `+adminToken+`
sources:
  loki: { type: loki, url: "http://loki:3100" }
  prom: { type: prometheus, url: "http://prom:9090" }
  sentry:
    type: sentry
    org: acme
    url: "https://sentry.example.com/tenant-path?key=url-secret"
    auth: { type: bearer, token: "${SENTRY_TOKEN}" }
    headers: { X-Scope-OrgID: header-secret }
  content: { type: contember, url: "http://engine:4000", auth: { type: bearer, token: t } }
projects:
  api:
    services:
      api:
        environments:
          production:
            logs: { source: loki, selector: '{app="api"}' }
            data: { source: content, project: api }
      worker:
        environments:
          production:
            alerts: { source: prom, selector: '{service="worker"}' }
`), func(name string) (string, bool) {
		if name == "SENTRY_TOKEN" {
			return "token-secret", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "sonda.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	env := &testEnv{store: st, authz: authz.New(cfg, st), cfg: cfg}
	env.start(t)
	return env
}

// start serves the admin UI with a freshly opened issuer, as a (re)started Sonda does, and
// signs in a new client.
func (e *testEnv) start(t *testing.T) {
	t.Helper()
	iss, err := issuer.Open(context.Background(), "https://sonda.example.com", e.store)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(e.cfg, e.store, e.store, iss, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.server = httptest.NewServer(handler)
	t.Cleanup(e.server.Close)
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (e *testEnv) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := e.client.Get(e.server.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
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
		{"project data grant", url.Values{"name": {"agent"}, "grant": {grantValue(identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityData})}}, "invalid grant"},
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

func TestDataIsGrantedPerService(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	resp, err := env.client.Get(env.server.URL + "/admin/identities/new")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := string(raw)
	data := grantValue(identities.Grant{Service: "api", Environment: "production", Capability: api.CapabilityData})
	if !strings.Contains(form, `value="`+template.HTMLEscapeString(data)+`"`) {
		t.Fatalf("form lacks the service data grant %q:\n%s", data, form)
	}
	if strings.Contains(form, `value="`+template.HTMLEscapeString(grantValue(identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityData}))+`"`) {
		t.Error("form offers a project data grant")
	}
	status, body := env.post(t, "/admin/identities", url.Values{"name": {"agent"}, "grant": {data}})
	if status != http.StatusOK {
		t.Fatalf("create: status %d\n%s", status, body)
	}
	identity, err := env.authz.Authenticate(context.Background(), shownToken(t, body))
	if err != nil {
		t.Fatal(err)
	}
	want := []identities.Grant{{Service: "api", Environment: "production", Capability: api.CapabilityData}}
	if !slices.Equal(identity.Grants, want) {
		t.Errorf("grants = %+v", identity.Grants)
	}
	if _, err := env.authz.DataScope(identity, "api", "production"); err != nil {
		t.Errorf("granted data scope: %v", err)
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

func TestServicesPageHidesCredentials(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	resp, err := env.client.Get(env.server.URL + "/admin/services")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"production", "{app=&#34;api&#34;}", "{service=&#34;worker&#34;}", "https://sentry.example.com", "X-Scope-OrgID", "unused", "api / production", "worker / production"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, secret := range []string{"token-secret", "header-secret", "url-secret", "tenant-path"} {
		if strings.Contains(body, secret) {
			t.Errorf("page shows %q", secret)
		}
	}
}

func TestServicesPageCountsOnlyConfiguredGrants(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	ctx := context.Background()
	stale := identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityTraces}
	logs := identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityLogs}
	for i, id := range []identities.Identity{
		{Name: "stale", Grants: []identities.Grant{stale}},
		{Name: "valid", Grants: []identities.Grant{logs}},
		{Name: "both", Grants: []identities.Grant{stale, logs}},
		{Name: "data", Grants: []identities.Grant{{Service: "api", Environment: "production", Capability: api.CapabilityData}}},
	} {
		id.TokenSHA256 = [32]byte{byte(i + 1)}
		if err := env.store.Create(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := env.client.Get(env.server.URL + "/admin/services")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	// valid, both and data count for api; stale has no effective grant. The logs grant of the
	// project does not reach worker, which configures only alerts, and neither does the data
	// grant, which names api.
	body := string(raw)
	start := strings.Index(body, ">api</h3>")
	if start < 0 {
		t.Fatalf("page lacks the api service:\n%s", body)
	}
	api, worker, ok := strings.Cut(body[start:], ">worker</h3>")
	if !ok {
		t.Fatalf("page lacks the api and worker services:\n%s", body)
	}
	if !strings.Contains(api, `rowspan="2">3</td>`) {
		t.Errorf("want 3 identities for api:\n%s", api)
	}
	if !strings.Contains(worker, `<span class="subtle">0</span>`) {
		t.Errorf("want 0 identities for worker:\n%s", worker)
	}
}

func keyIDs(t *testing.T, st *store.Store) []string {
	t.Helper()
	keys, err := st.SigningKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, key := range keys {
		ids = append(ids, key.ID)
	}
	return ids
}

func TestRotateSigningKey(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	old := keyIDs(t, env.store)[0]
	if status, body := env.get(t, "/admin/signing-keys"); status != http.StatusOK || !strings.Contains(body, old) || strings.Contains(body, "/delete") {
		t.Fatalf("status %d; want the key without a remove button:\n%s", status, body)
	}
	if status, _ := env.post(t, "/admin/signing-keys", nil); status != http.StatusSeeOther {
		t.Fatalf("add: status %d", status)
	}
	ids := keyIDs(t, env.store)
	if len(ids) != 2 || ids[0] != old {
		t.Fatalf("keys after add = %v", ids)
	}
	added := ids[1]
	// Neither key can go: this process signs with the old one, the new one is the newest.
	for _, id := range ids {
		if status, body := env.post(t, "/admin/signing-keys/"+id+"/delete", nil); status != http.StatusUnprocessableEntity || !strings.Contains(body, "is in use") {
			t.Errorf("remove %s before restart: status %d", id, status)
		}
	}

	env.start(t)
	env.login(t)
	if status, _ := env.post(t, "/admin/signing-keys/"+old+"/delete", nil); status != http.StatusSeeOther {
		t.Fatalf("remove the old key after restart: status %d", status)
	}
	if ids := keyIDs(t, env.store); !slices.Equal(ids, []string{added}) {
		t.Errorf("keys after removal = %v, want [%s]", ids, added)
	}

	records, err := env.store.ListAudit(context.Background(), store.AuditFilter{Identity: auditIdentity, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Path != "/admin/signing-keys/"+old+"/delete" {
		t.Errorf("last audited admin action = %+v", records)
	}
}

func TestSigningKeysPageNeedsIssuer(t *testing.T) {
	env := newTestEnv(t)
	handler, err := New(env.cfg, env.store, env.store, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	env.server = httptest.NewServer(handler)
	t.Cleanup(env.server.Close)
	env.login(t)
	if status, _ := env.get(t, "/admin/signing-keys"); status != http.StatusNotFound {
		t.Errorf("status %d without identity.issuer", status)
	}
	if _, body := env.get(t, "/admin/identities"); strings.Contains(body, "Signing keys") {
		t.Error("navigation links the signing keys page without identity.issuer")
	}
}

func TestWildcardGrant(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.login(t)
	production := identities.Grant{Project: identities.Wildcard, Environment: "production", Capability: identities.AnyCapability}

	_, form := env.get(t, "/admin/identities/new")
	for _, g := range []identities.Grant{
		production,
		{Project: identities.Wildcard, Environment: identities.Wildcard, Capability: identities.AnyCapability},
		{Project: identities.Wildcard, Environment: identities.Wildcard, Capability: api.CapabilityMetrics},
		{Project: "api", Environment: identities.Wildcard, Capability: api.CapabilityLogs},
		{Project: "api", Environment: "production", Capability: identities.AnyCapability},
	} {
		if !strings.Contains(form, `value="`+template.HTMLEscapeString(grantValue(g))+`"`) {
			t.Errorf("form lacks the wildcard grant %s", grantName(g))
		}
	}

	status, body := env.post(t, "/admin/identities", url.Values{"name": {"agent"}, "grant": {grantValue(production)}})
	if status != http.StatusOK {
		t.Fatalf("create: status %d\n%s", status, body)
	}
	identity, err := env.authz.Authenticate(ctx, shownToken(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.authz.LogScope(identity, "api", "production"); err != nil {
		t.Errorf("logs of api: %v", err)
	}
	if _, err := env.authz.AlertScope(identity, "worker", "production"); err != nil {
		t.Errorf("alerts of worker: %v", err)
	}
	if _, err := env.authz.DataScope(identity, "api", "production"); err == nil {
		t.Error("a wildcard grant opened data")
	}

	_, edit := env.get(t, "/admin/identities/agent")
	for _, want := range []string{
		"What the wildcard grants cover today",
		`<code>* / production / *</code>`,
		`api / production</span> <span class="pills pills-inline"><span class="pill pill-accent">logs</span></span>`,
		`worker / production</span> <span class="pills pills-inline"><span class="pill pill-accent">alerts</span></span>`,
		`aria-label="api / production / logs (covered by every project / production / every capability)"`,
		`aria-label="api / every environment / metrics"`,
	} {
		if !strings.Contains(edit, want) {
			t.Errorf("edit page lacks %q", want)
		}
	}
	if strings.Contains(edit, "pill-accent\">data") {
		t.Error("edit page shows data as covered")
	}
	_, list := env.get(t, "/admin/identities")
	if !strings.Contains(list, "covers 2 service environments today") {
		t.Errorf("list lacks the coverage count:\n%s", list)
	}
	_, services := env.get(t, "/admin/services")
	if _, worker, _ := strings.Cut(services, ">worker</h3>"); !strings.Contains(worker, `rowspan="1">1</td>`) {
		t.Errorf("want 1 identity for worker:\n%s", worker)
	}
}

func TestRejectsInvalidWildcardGrants(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	for _, value := range []string{
		grantValue(identities.Grant{Project: "nope", Environment: identities.Wildcard, Capability: identities.AnyCapability}),
		grantValue(identities.Grant{Project: identities.Wildcard, Environment: "staging", Capability: identities.AnyCapability}),
		grantValue(identities.Grant{Project: "api", Environment: identities.Wildcard, Capability: api.CapabilityData}),
		grantValue(identities.Grant{Service: identities.Wildcard, Environment: "production", Capability: api.CapabilityData}),
		grantValue(identities.Grant{Service: "api", Environment: identities.Wildcard, Capability: api.CapabilityData}),
		grantValue(identities.Grant{Project: "a*", Environment: "production", Capability: api.CapabilityLogs}),
	} {
		status, body := env.post(t, "/admin/identities", url.Values{"name": {"agent"}, "grant": {value}})
		if status != http.StatusUnprocessableEntity || !strings.Contains(body, "invalid grant") {
			t.Errorf("%s: status %d", value, status)
		}
	}
	if list, _ := env.store.List(context.Background()); len(list) != 0 {
		t.Errorf("identities created from invalid grants: %+v", list)
	}
}
