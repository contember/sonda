package admin

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/signin"
	"github.com/contember/sonda/internal/signin/signintest"
	"github.com/contember/sonda/internal/store"
)

// newSignInEnv serves the admin UI with admin.oauth pointing at a test authorization server.
func newSignInEnv(t *testing.T) (*testEnv, *signintest.Server) {
	t.Helper()
	env := newTestEnv(t)
	idp := signintest.New(t)
	server := httptest.NewUnstartedServer(nil)
	env.cfg.Admin.OAuth = &config.AdminOAuth{Issuer: idp.URL, URL: "http://" + server.Listener.Addr().String()}
	handler, err := newHandler(env.cfg, env.store, env.store, nil, signin.New(*env.cfg.Admin.OAuth, idp.Client()), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	t.Cleanup(server.Close)
	env.server = server
	jar, _ := cookiejar.New(nil)
	env.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return env, idp
}

// signIn walks the browser through the sign-in and returns the callback's status and page.
func (e *testEnv) signIn(t *testing.T) (int, string) {
	t.Helper()
	location := e.startSignIn(t)
	callback := e.redirect(t, location, http.StatusFound)
	resp, err := e.client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// startSignIn posts the login page's sign-in form and returns the authorization server's URL.
func (e *testEnv) startSignIn(t *testing.T) string {
	t.Helper()
	resp, err := e.client.PostForm(e.server.URL+"/admin/oauth/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("start sign-in: status %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func (e *testEnv) redirect(t *testing.T, from string, status int) string {
	t.Helper()
	resp, err := e.client.Get(from)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != status {
		t.Fatalf("GET %s: status %d, want %d", from, resp.StatusCode, status)
	}
	return resp.Header.Get("Location")
}

func (e *testEnv) addPerson(t *testing.T, name, subject string, admin bool, grants ...identities.Grant) {
	t.Helper()
	ctx := context.Background()
	_, hash := identities.NewToken()
	if err := e.store.Create(ctx, identities.Identity{Name: name, TokenSHA256: hash, Grants: grants, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.LinkPerson(ctx, store.Person{Identity: name, Issuer: e.cfg.Admin.OAuth.Issuer, Subject: subject, Admin: admin, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) auditIdentities(t *testing.T) []string {
	t.Helper()
	records, err := e.store.ListAudit(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range records {
		out = append(out, r.Identity+" "+r.Method+" "+r.Path)
	}
	return out
}

func TestPersonSeesOnlyWhatTheirGrantsOpen(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", false, identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityLogs})
	idp.SignIn("principal-alice", "alice@example.com")

	if status, body := env.signIn(t); status != http.StatusOK || !strings.Contains(body, `url=/admin/`) {
		t.Fatalf("callback: status %d\n%s", status, body)
	}
	if location := env.redirect(t, env.server.URL+"/admin/", http.StatusSeeOther); location != "/admin/me" {
		t.Errorf("home of a person redirects to %q", location)
	}
	status, body := env.get(t, "/admin/me")
	if status != http.StatusOK {
		t.Fatalf("my access: status %d", status)
	}
	if !strings.Contains(body, "api / production") || strings.Contains(body, "worker / production") || !strings.Contains(body, "alice@example.com (alice)") {
		t.Errorf("my access page shows other than the grants:\n%s", body)
	}
	for _, path := range []string{"/admin/identities", "/admin/services", "/admin/audit", "/admin/identities/alice"} {
		if status, _ := env.get(t, path); status != http.StatusForbidden {
			t.Errorf("GET %s by a person who is not an administrator: status %d", path, status)
		}
	}
	if status, _ := env.post(t, "/admin/identities", url.Values{"name": {"mine"}, "grant": {logsGrant()}}); status != http.StatusForbidden {
		t.Errorf("create identity by a person who is not an administrator: status %d", status)
	}
	got := strings.Join(env.auditIdentities(t), "\n")
	if !strings.Contains(got, "person:alice GET /admin/oauth/callback") || !strings.Contains(got, "person:alice POST /admin/identities") {
		t.Errorf("audit:\n%s", got)
	}
}

func TestAdministratorPersonManagesSonda(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "bob", "principal-bob", true, identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityLogs})
	idp.SignIn("principal-bob", "bob@example.com")
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d", status)
	}
	if status, _ := env.get(t, "/admin/identities"); status != http.StatusOK {
		t.Errorf("identities: status %d", status)
	}
	if status, _ := env.post(t, "/admin/identities", url.Values{"name": {"agent"}, "grant": {logsGrant()}}); status != http.StatusOK {
		t.Errorf("create identity: status %d", status)
	}
	records, err := env.store.ListAudit(context.Background(), store.AuditFilter{Identity: "person:bob", Limit: 10})
	if err != nil || len(records) != 2 || records[0].Path != "/admin/identities" {
		t.Errorf("audit of bob: %+v, %v", records, err)
	}
}

func TestRefusesAnUnknownSubject(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", true)
	idp.SignIn("principal-mallory", "mallory@example.com")

	status, body := env.signIn(t)
	if status != http.StatusForbidden || !strings.Contains(body, `<code id="subject">principal-mallory</code>`) {
		t.Fatalf("callback: status %d\n%s", status, body)
	}
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("refused person got a session: redirect to %q", location)
	}
	if got := env.auditIdentities(t); len(got) != 2 || got[0] != "(refused) principal-mallory GET /admin/oauth/callback" || got[1] != "(sign-in) POST /admin/oauth/start" {
		t.Errorf("audit: %q", got)
	}
}

func TestRefusesATokenThatDoesNotVerify(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", true)
	idp.SignIn("principal-alice", "")
	idp.Tamper(func(_, claims map[string]any) { claims["aud"] = "https://other.example.com/mcp" })
	if status, _ := env.signIn(t); status != http.StatusUnauthorized {
		t.Fatalf("callback: status %d", status)
	}
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("session from a token for another resource: redirect to %q", location)
	}
}

// signInWithRoles makes the test server put the roles claim into its tokens, as fabrika IAM does
// for an external application that declares roles.
func signInWithRoles(idp *signintest.Server, subject, label string, roles ...string) {
	idp.SignIn(subject, label)
	idp.Tamper(func(_, claims map[string]any) { claims["roles"] = roles })
}

func TestAdminRoleManagesSondaWithoutALink(t *testing.T) {
	env, idp := newSignInEnv(t)
	signInWithRoles(idp, "principal-carol", "carol@example.com", signin.AdminRoleKey)
	if status, body := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d\n%s", status, body)
	}
	if location := env.redirect(t, env.server.URL+"/admin/", http.StatusSeeOther); location != "/admin/identities" {
		t.Errorf("home of an administrator by role redirects to %q", location)
	}
	status, body := env.get(t, "/admin/identities")
	if status != http.StatusOK || !strings.Contains(body, "Signed in as carol@example.com") {
		t.Errorf("identities: status %d\n%s", status, body)
	}
	if status, _ := env.post(t, "/admin/identities", url.Values{"name": {"agent"}, "grant": {logsGrant()}}); status != http.StatusOK {
		t.Errorf("create identity: status %d", status)
	}
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/identities" {
		t.Errorf("my access of an administrator without an identity redirects to %q", location)
	}
	got := strings.Join(env.auditIdentities(t), "\n")
	if !strings.Contains(got, "(unlinked) principal-carol GET /admin/oauth/callback") || !strings.Contains(got, "(unlinked) principal-carol POST /admin/identities") {
		t.Errorf("audit:\n%s", got)
	}
}

func TestRolesDecideOverTheLinkAdminFlag(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", true, identities.Grant{Project: "api", Environment: "production", Capability: api.CapabilityLogs})
	env.addPerson(t, "bob", "principal-bob", false)

	// A viewer by role does not manage Sonda, even with a link marked Administrator.
	signInWithRoles(idp, "principal-alice", "alice@example.com", signin.ViewerRoleKey)
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("viewer callback: status %d", status)
	}
	if location := env.redirect(t, env.server.URL+"/admin/", http.StatusSeeOther); location != "/admin/me" {
		t.Errorf("home of a viewer redirects to %q", location)
	}
	if status, body := env.get(t, "/admin/me"); status != http.StatusOK || !strings.Contains(body, "api / production") || strings.Contains(body, "administrator</span>") {
		t.Errorf("my access of a viewer: status %d\n%s", status, body)
	}
	if status, _ := env.get(t, "/admin/identities"); status != http.StatusForbidden {
		t.Errorf("identities by a viewer: status %d", status)
	}

	// An administrator by role manages Sonda, even with a link that is not marked.
	signInWithRoles(idp, "principal-bob", "bob@example.com", signin.AdminRoleKey)
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("admin callback: status %d", status)
	}
	if status, _ := env.get(t, "/admin/identities"); status != http.StatusOK {
		t.Errorf("identities by an administrator by role: status %d", status)
	}
	if status, body := env.get(t, "/admin/me"); status != http.StatusOK || !strings.Contains(body, "<code>bob</code>") || !strings.Contains(body, "administrator</span>") {
		t.Errorf("my access of a linked administrator: status %d\n%s", status, body)
	}
	got := strings.Join(env.auditIdentities(t), "\n")
	if !strings.Contains(got, "person:alice GET /admin/oauth/callback") || !strings.Contains(got, "person:bob GET /admin/oauth/callback") {
		t.Errorf("audit:\n%s", got)
	}
}

func TestViewerRoleNeedsALink(t *testing.T) {
	env, idp := newSignInEnv(t)
	signInWithRoles(idp, "principal-dave", "", signin.ViewerRoleKey)
	status, body := env.signIn(t)
	if status != http.StatusForbidden || !strings.Contains(body, `<code id="subject">principal-dave</code>`) {
		t.Fatalf("callback: status %d\n%s", status, body)
	}
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("refused viewer got a session: redirect to %q", location)
	}
}

func TestRefusesATokenWithoutASondaRole(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", true)
	signInWithRoles(idp, "principal-alice", "", "billing-admin")
	status, body := env.signIn(t)
	if status != http.StatusForbidden || !strings.Contains(body, "holds no Sonda role") {
		t.Fatalf("callback: status %d\n%s", status, body)
	}
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("person without a Sonda role got a session: redirect to %q", location)
	}
	if got := env.auditIdentities(t); len(got) != 2 || got[0] != "(refused) principal-alice GET /admin/oauth/callback" || got[1] != "(sign-in) POST /admin/oauth/start" {
		t.Errorf("audit: %q", got)
	}
}

func TestUnlinkingEndsAViewerSessionButNotAnAdministrators(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", false)
	signInWithRoles(idp, "principal-alice", "", signin.ViewerRoleKey)
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d", status)
	}
	if err := env.store.UnlinkPerson(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("viewer after unlinking: redirect to %q", location)
	}

	env.addPerson(t, "bob", "principal-bob", false)
	signInWithRoles(idp, "principal-bob", "", signin.AdminRoleKey)
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d", status)
	}
	if err := env.store.UnlinkPerson(context.Background(), "bob"); err != nil {
		t.Fatal(err)
	}
	if status, _ := env.get(t, "/admin/identities"); status != http.StatusOK {
		t.Errorf("administrator by role after unlinking: status %d", status)
	}
}

func TestNewSignInRetiresTheCurrentSession(t *testing.T) {
	env, idp := newSignInEnv(t)
	signInWithRoles(idp, "principal-carol", "", signin.AdminRoleKey)
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d", status)
	}
	serverURL, _ := url.Parse(env.server.URL)
	adminURL := &url.URL{Scheme: "http", Host: serverURL.Host, Path: "/admin/"}
	adminCookies := env.client.Jar.Cookies(adminURL)

	// The role was removed at the authorization server; the next sign-in is refused.
	signInWithRoles(idp, "principal-carol", "", "billing-admin")
	if status, _ := env.signIn(t); status != http.StatusForbidden {
		t.Fatalf("callback without a Sonda role: status %d", status)
	}
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(adminURL, adminCookies)
	env.client.Jar = jar
	if location := env.redirect(t, env.server.URL+"/admin/identities", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("the session from before the new sign-in still works: redirect to %q", location)
	}
}

func TestAnotherSiteCannotStartASignIn(t *testing.T) {
	env, idp := newSignInEnv(t)
	signInWithRoles(idp, "principal-carol", "", signin.AdminRoleKey)
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d", status)
	}
	// A cross-site navigation must not reach the handler, which ends the current session.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, _ := http.NewRequest(method, env.server.URL+"/admin/oauth/start", nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, err := env.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusSeeOther || len(resp.Header.Values("Set-Cookie")) != 0 {
			t.Errorf("%s from another site: status %d, cookies %q", method, resp.StatusCode, resp.Header.Values("Set-Cookie"))
		}
	}
	if status, _ := env.get(t, "/admin/identities"); status != http.StatusOK {
		t.Errorf("session after cross-site starts: status %d", status)
	}
}

func TestEndsSessionsWrittenWithoutReadingRoles(t *testing.T) {
	env, _ := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", true)
	// An older Sonda wrote kind "person" for any token, a viewer's included.
	cookieValue := "legacy-session-cookie"
	session := store.AdminSession{Kind: "person", Issuer: env.cfg.Admin.OAuth.Issuer, Subject: "principal-alice", ExpiresAt: time.Now().Add(time.Hour)}
	if err := env.store.CreateAdminSession(context.Background(), sha256.Sum256([]byte(cookieValue)), session); err != nil {
		t.Fatal(err)
	}
	serverURL, _ := url.Parse(env.server.URL)
	env.client.Jar.SetCookies(&url.URL{Scheme: "http", Host: serverURL.Host, Path: "/admin/"}, []*http.Cookie{{Name: "sonda_admin", Value: cookieValue, Path: "/admin"}})
	if location := env.redirect(t, env.server.URL+"/admin/identities", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("legacy person session: redirect to %q", location)
	}
}

func TestCallbackNeedsTheAttemptOfThisBrowser(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", true)
	idp.SignIn("principal-alice", "")
	location := env.startSignIn(t)
	callback := env.redirect(t, location, http.StatusFound)

	// Another browser, e.g. a victim lured to the attacker's callback URL, has no attempt.
	jar, _ := cookiejar.New(nil)
	env.client.Jar = jar
	resp, err := env.client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback without the attempt cookie: status %d", resp.StatusCode)
	}
	if got := env.auditIdentities(t); len(got) != 2 || got[0] != "(refused) GET /admin/oauth/callback" || got[1] != "(sign-in) POST /admin/oauth/start" {
		t.Errorf("audit: %q", got)
	}
}

func TestUnlinkingEndsTheSession(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", false)
	idp.SignIn("principal-alice", "")
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d", status)
	}
	if status, _ := env.get(t, "/admin/me"); status != http.StatusOK {
		t.Fatalf("my access: status %d", status)
	}
	if err := env.store.UnlinkPerson(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("after unlinking: redirect to %q", location)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	env, idp := newSignInEnv(t)
	env.addPerson(t, "alice", "principal-alice", false)
	idp.SignIn("principal-alice", "")
	if status, _ := env.signIn(t); status != http.StatusOK {
		t.Fatalf("callback: status %d", status)
	}
	serverURL, _ := url.Parse(env.server.URL)
	cookies := env.client.Jar.Cookies(&url.URL{Scheme: "http", Host: serverURL.Host, Path: "/admin/"})
	if status, _ := env.post(t, "/admin/logout", nil); status != http.StatusSeeOther {
		t.Fatalf("logout: status %d", status)
	}
	// A copy of the cookie taken before the logout no longer opens a session.
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(&url.URL{Scheme: "http", Host: serverURL.Host, Path: "/admin/"}, cookies)
	env.client.Jar = jar
	if location := env.redirect(t, env.server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("after logout: redirect to %q", location)
	}
}

func TestLinkPersonForm(t *testing.T) {
	env, _ := newSignInEnv(t)
	env.login(t)
	for _, name := range []string{"alice", "bob"} {
		if status, _ := env.post(t, "/admin/identities", url.Values{"name": {name}, "grant": {logsGrant()}}); status != http.StatusOK {
			t.Fatalf("create %s: status %d", name, status)
		}
	}
	if status, _ := env.post(t, "/admin/identities/alice/person", url.Values{"subject": {"principal-alice"}, "admin": {"on"}}); status != http.StatusSeeOther {
		t.Fatalf("link: status %d", status)
	}
	person, err := env.store.PersonBySubject(context.Background(), env.cfg.Admin.OAuth.Issuer, "principal-alice")
	if err != nil || person.Identity != "alice" || !person.Admin {
		t.Errorf("person %+v, %v", person, err)
	}
	if status, body := env.post(t, "/admin/identities/bob/person", url.Values{"subject": {"principal-alice"}}); status != http.StatusUnprocessableEntity || !strings.Contains(body, "already linked") {
		t.Errorf("subject of another identity: status %d", status)
	}
	if status, _ := env.post(t, "/admin/identities/bob/person", url.Values{"subject": {"has space"}}); status != http.StatusUnprocessableEntity {
		t.Errorf("subject with a space: status %d", status)
	}
	if _, body := env.get(t, "/admin/identities/alice"); !strings.Contains(body, `value="principal-alice"`) {
		t.Errorf("edit page does not show the link")
	}
	if status, _ := env.post(t, "/admin/identities/alice/person/delete", nil); status != http.StatusSeeOther {
		t.Fatalf("unlink: status %d", status)
	}
	if _, err := env.store.PersonByIdentity(context.Background(), "alice"); err != store.ErrPersonNotFound {
		t.Errorf("after unlink: %v", err)
	}
}

func TestBreakGlassIsAuditedOnEveryUse(t *testing.T) {
	env := newTestEnv(t)
	if status, _ := env.post(t, "/admin/login", url.Values{"token": {"wrong-wrong-wrong-wrong-wrong-wrong"}}); status != http.StatusUnauthorized {
		t.Fatalf("wrong token: status %d", status)
	}
	env.login(t)
	if status, _ := env.get(t, "/admin/identities"); status != http.StatusOK {
		t.Fatalf("identities: status %d", status)
	}
	if status, _ := env.get(t, "/admin/audit"); status != http.StatusOK {
		t.Fatalf("audit: status %d", status)
	}
	records, err := env.store.ListAudit(context.Background(), store.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range records {
		got = append(got, r.Identity+" "+r.Method+" "+r.Path+" "+http.StatusText(r.Status))
	}
	want := []string{
		"(break-glass) GET /admin/audit OK",
		"(break-glass) GET /admin/identities OK",
		"(break-glass) POST /admin/login See Other",
		"(break-glass) POST /admin/login Unauthorized",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestBreakGlassSessionEndsWhenTheTokenChanges(t *testing.T) {
	env := newTestEnv(t)
	env.login(t)
	env.cfg.Admin.Token = strings.Repeat("n", 40)
	if location := env.redirect(t, env.server.URL+"/admin/identities", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("session of the old token: redirect to %q", location)
	}
}

func TestOAuthOnlyHasNoTokenSignIn(t *testing.T) {
	env, _ := newSignInEnv(t)
	env.cfg.Admin.Token = ""
	handler, err := newHandler(env.cfg, env.store, env.store, nil, signin.New(*env.cfg.Admin.OAuth, http.DefaultClient), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	env.server = server
	if status, body := env.get(t, "/admin/login"); status != http.StatusOK || strings.Contains(body, `name="token"`) || !strings.Contains(body, "/admin/oauth/start") {
		t.Errorf("login page: status %d\n%s", status, body)
	}
	env.post(t, "/admin/login", url.Values{"token": {""}})
	if location := env.redirect(t, server.URL+"/admin/me", http.StatusSeeOther); location != "/admin/login" {
		t.Errorf("an empty admin token opened a session: redirect to %q", location)
	}
}

func TestServesClientMetadata(t *testing.T) {
	env, _ := newSignInEnv(t)
	status, body := env.get(t, "/admin/oauth/client")
	base := env.cfg.Admin.OAuth.URL
	if status != http.StatusOK || !strings.Contains(body, `"client_id":"`+base+`/admin/oauth/client"`) || !strings.Contains(body, `"redirect_uris":["`+base+`/admin/oauth/callback"]`) {
		t.Errorf("status %d\n%s", status, body)
	}
}
