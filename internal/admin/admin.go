// Package admin serves the admin UI under /admin: identity management, a read-only view of the
// configured services and sources, and the audit log. Sources and services stay in the config
// file and are not editable here, so provider credentials never reach the database.
package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/issuer"
	"github.com/contember/sonda/internal/signin"
	"github.com/contember/sonda/internal/store"
)

//go:embed templates static
var assets embed.FS

const (
	sessionCookie = "sonda_admin"
	// sessionTTL is short because a session outlives what the authorization server revokes;
	// unlinking a person in Sonda ends their sessions at once.
	sessionTTL = time.Hour
	// breakGlassIdentity marks the requests of a session opened with the admin token. Identity
	// names cannot contain parentheses or ':', so these never collide with an agent.
	breakGlassIdentity = "(break-glass)"
	// legacyAdminIdentity marked admin actions before people signed in through OAuth.
	legacyAdminIdentity = "(admin)"
	refusedIdentity     = "(refused) "
	personIdentity      = "person:"
	// signInIdentity marks the start of a sign-in in a browser without a session.
	signInIdentity = "(sign-in)"
	// unlinkedIdentity marks an administrator by role whose subject is linked to no identity.
	unlinkedIdentity = "(unlinked) "
)

type Handler struct {
	cfg        *config.Config
	identities identities.Store
	store      *store.Store
	// issuer is nil without identity.issuer; the signing keys page is then absent.
	issuer *issuer.Issuer
	// signin is nil without admin.oauth; only the admin token signs in then.
	signin *signin.Client
	log    *slog.Logger
	pages  map[string]*template.Template
	now    func() time.Time
}

func New(cfg *config.Config, ids identities.Store, st *store.Store, iss *issuer.Issuer, log *slog.Logger) (http.Handler, error) {
	var client *signin.Client
	if cfg.Admin.OAuth != nil {
		client = signin.New(*cfg.Admin.OAuth, &http.Client{Timeout: 10 * time.Second})
	}
	return newHandler(cfg, ids, st, iss, client, log)
}

func newHandler(cfg *config.Config, ids identities.Store, st *store.Store, iss *issuer.Issuer, client *signin.Client, log *slog.Logger) (http.Handler, error) {
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	h := &Handler{cfg: cfg, identities: ids, store: st, issuer: iss, signin: client, log: log, pages: pages, now: time.Now}

	static, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	// Pages every signed-in person may see.
	authed := http.NewServeMux()
	authed.HandleFunc("GET /admin/{$}", h.home)
	authed.HandleFunc("POST /admin/logout", h.logout)
	authed.HandleFunc("GET /admin/me", h.myAccess)
	// Everything else manages Sonda and needs an administrator.
	managed := http.NewServeMux()
	managed.HandleFunc("GET /admin/identities", h.listIdentities)
	managed.HandleFunc("GET /admin/identities/new", h.newIdentity)
	managed.HandleFunc("POST /admin/identities", h.createIdentity)
	managed.HandleFunc("GET /admin/identities/{name}", h.editIdentity)
	managed.HandleFunc("POST /admin/identities/{name}", h.updateIdentity)
	managed.HandleFunc("POST /admin/identities/{name}/token", h.rotateToken)
	managed.HandleFunc("POST /admin/identities/{name}/delete", h.deleteIdentity)
	if client != nil {
		managed.HandleFunc("POST /admin/identities/{name}/person", h.linkPerson)
		managed.HandleFunc("POST /admin/identities/{name}/person/delete", h.unlinkPerson)
	}
	managed.HandleFunc("GET /admin/services", h.listServices)
	managed.HandleFunc("GET /admin/audit", h.auditLog)
	if iss != nil {
		managed.HandleFunc("GET /admin/signing-keys", h.listSigningKeys)
		managed.HandleFunc("POST /admin/signing-keys", h.addSigningKey)
		managed.HandleFunc("POST /admin/signing-keys/{id}/delete", h.removeSigningKey)
	}
	authed.Handle("/admin/", h.requireAdmin(managed))

	mux := http.NewServeMux()
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /admin/login", h.loginForm)
	if cfg.Admin.Token != "" {
		mux.HandleFunc("POST /admin/login", h.breakGlassLogin)
	}
	if client != nil {
		mux.HandleFunc("GET "+signin.ClientPath, h.clientMetadata)
		// POST, so cross-origin protection keeps other sites from ending a session through it.
		mux.HandleFunc("POST /admin/oauth/start", h.startSignIn)
		mux.HandleFunc("GET "+signin.CallbackPath, h.signInCallback)
	}
	mux.Handle("/admin/", h.requireSession(authed))

	// Rejects cross-origin form posts, which together with SameSite cookies prevents CSRF.
	return http.NewCrossOriginProtection().Handler(h.audited(mux)), nil
}

// actor is who makes a request of a signed-in session.
type actor struct {
	breakGlass bool
	// person is set for a person's session; its Identity is empty for an administrator by role
	// whose subject is linked to no identity.
	person store.Person
	label  string
	// administrator is the person's role, from the token's roles or else from the link.
	administrator bool
}

func (a actor) admin() bool { return a.breakGlass || a.administrator }

func (a actor) auditIdentity() string {
	switch {
	case a.breakGlass:
		return breakGlassIdentity
	case a.person.Identity == "":
		return unlinkedIdentity + a.person.Subject
	}
	return personIdentity + a.person.Identity
}

type actorKey struct{}

func actorFrom(ctx context.Context) actor {
	a, _ := ctx.Value(actorKey{}).(actor)
	return a
}

// auditNote is filled while a request is handled and read by audited afterwards.
type auditNote struct {
	identity string
	// always records the request even when it is a GET.
	always bool
}

type auditNoteKey struct{}

func noteAudit(r *http.Request, identity string, always bool) {
	if note, ok := r.Context().Value(auditNoteKey{}).(*auditNote); ok {
		note.identity, note.always = identity, always
	}
}

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	if actorFrom(r.Context()).admin() {
		http.Redirect(w, r, "/admin/identities", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/me", http.StatusSeeOther)
}

type loginPage struct {
	// Issuer is the authorization server's host, empty without admin.oauth.
	Issuer     string
	BreakGlass bool
}

func (h *Handler) loginForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.session(r); ok {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
	h.renderLogin(w, r, http.StatusOK, "")
}

func (h *Handler) renderLogin(w http.ResponseWriter, r *http.Request, status int, message string) {
	page := loginPage{BreakGlass: h.cfg.Admin.Token != ""}
	if h.signin != nil {
		if u, err := url.Parse(h.signin.Issuer()); err == nil {
			page.Issuer = u.Host
		}
	}
	h.render(w, r, status, "login", view{Title: "Sign in", Error: message, Data: page})
}

// breakGlassLogin signs in with the admin token. Every attempt and every request of the
// session it opens is audited as break-glass, including reads.
func (h *Handler) breakGlassLogin(w http.ResponseWriter, r *http.Request) {
	noteAudit(r, breakGlassIdentity, true)
	given := sha256.Sum256([]byte(r.PostFormValue("token")))
	want := sha256.Sum256([]byte(h.cfg.Admin.Token))
	if subtle.ConstantTimeCompare(given[:], want[:]) != 1 {
		h.renderLogin(w, r, http.StatusUnauthorized, "Invalid admin token.")
		return
	}
	h.log.Warn("admin signed in with the break-glass admin token")
	if err := h.startSession(w, r, store.AdminSession{Kind: store.SessionBreakGlass, Credential: h.breakGlassCredential()}); err != nil {
		h.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/admin/identities", http.StatusSeeOther)
}

// breakGlassCredential binds a break-glass session to the admin token: changing the token ends
// every such session.
func (h *Handler) breakGlassCredential() []byte {
	sum := sha256.Sum256([]byte("sonda-break-glass-session:" + h.cfg.Admin.Token))
	return sum[:]
}

func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, session store.AdminSession) error {
	value := make([]byte, 32)
	_, _ = rand.Read(value)
	cookieValue := base64.RawURLEncoding.EncodeToString(value)
	session.ExpiresAt = h.now().Add(sessionTTL)
	if err := h.store.CreateAdminSession(r.Context(), sha256.Sum256([]byte(cookieValue)), session); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    cookieValue,
		Path:     "/admin",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.endSession(w, r); err != nil {
		h.serverError(w, err)
		return
	}
	redirect(w, r, "/admin/login")
}

// endSession deletes the browser's session, if any, and its cookie.
func (h *Handler) endSession(w http.ResponseWriter, r *http.Request) error {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if err := h.store.DeleteAdminSession(r.Context(), sha256.Sum256([]byte(cookie.Value))); err != nil {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode})
	return nil
}

func (h *Handler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := h.session(r)
		if !ok {
			redirect(w, r, "/admin/login")
			return
		}
		noteAudit(r, a.auditIdentity(), a.breakGlass)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, a)))
	})
}

func (h *Handler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !actorFrom(r.Context()).admin() {
			http.Error(w, "Only Sonda administrators may open this page.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// session resolves the request's session. A person's link is looked up on every request, so
// unlinking them or deleting their identity ends their sessions, except an administrator's by
// role, which needs no link.
func (h *Handler) session(r *http.Request) (actor, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return actor{}, false
	}
	session, err := h.store.AdminSession(r.Context(), sha256.Sum256([]byte(cookie.Value)))
	if err != nil {
		if !errors.Is(err, store.ErrSessionNotFound) {
			h.log.Error("read admin session", "error", err)
		}
		return actor{}, false
	}
	switch session.Kind {
	case store.SessionBreakGlass:
		valid := h.cfg.Admin.Token != "" && subtle.ConstantTimeCompare(session.Credential, h.breakGlassCredential()) == 1
		return actor{breakGlass: true}, valid
	case store.SessionPersonLink, store.SessionPersonAdmin, store.SessionPersonViewer:
		if h.signin == nil || session.Issuer != h.signin.Issuer() {
			return actor{}, false
		}
		person, err := h.store.PersonBySubject(r.Context(), session.Issuer, session.Subject)
		switch {
		case err == nil:
		case errors.Is(err, store.ErrPersonNotFound) && session.Kind == store.SessionPersonAdmin:
			person = store.Person{Issuer: session.Issuer, Subject: session.Subject}
		default:
			if !errors.Is(err, store.ErrPersonNotFound) {
				h.log.Error("read admin person", "error", err)
			}
			return actor{}, false
		}
		a := actor{person: person, label: session.Label}
		switch session.Kind {
		case store.SessionPersonLink:
			a.administrator = person.Admin
		case store.SessionPersonAdmin:
			a.administrator = true
		}
		return a, true
	}
	return actor{}, false
}

// audited records every state-changing admin request, including failed sign-ins, every
// sign-in, and every request of a break-glass session.
func (h *Handler) audited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		note := &auditNote{}
		r = r.WithContext(context.WithValue(r.Context(), auditNoteKey{}, note))
		start := h.now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !note.always {
			return
		}
		entry := store.AuditEntry{
			Time:     start,
			Identity: note.identity,
			Method:   r.Method,
			Path:     r.URL.Path,
			Status:   recorder.status,
			Duration: h.now().Sub(start),
		}
		if err := h.store.WriteAudit(context.WithoutCancel(r.Context()), entry); err != nil {
			h.log.Error("audit write failed", "error", err)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

// redirect also works for htmx requests, which would otherwise swap the target page into
// the current one without changing the URL.
func redirect(w http.ResponseWriter, r *http.Request, location string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", location)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// view is the data every page gets; Data holds the page's own model.
type view struct {
	// Admin shows the pages that manage Sonda in the navigation.
	Admin bool
	// SignedInAs names who is signed in, shown above the sign-out button.
	SignedInAs string
	Title      string
	// Lead is a one-line description under the title.
	Lead string
	// Back is the parent page's URL, shown as a back link above the title.
	Back  string
	Nav   string
	Error string
	Data  any
	// SigningKeys shows the signing keys page in the navigation.
	SigningKeys bool
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, page string, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	a := actorFrom(r.Context())
	v.Admin = a.admin()
	v.SigningKeys = h.issuer != nil && v.Admin
	switch {
	case a.breakGlass:
		v.SignedInAs = "break-glass admin token"
	case a.person.Identity != "":
		v.SignedInAs = a.person.Identity
		if a.label != "" {
			v.SignedInAs = a.label + " (" + a.person.Identity + ")"
		}
	case a.person.Subject != "":
		v.SignedInAs = a.person.Subject
		if a.label != "" {
			v.SignedInAs = a.label
		}
	}
	if err := h.pages[page].ExecuteTemplate(w, "layout", v); err != nil {
		h.log.Error("render admin page", "page", page, "error", err)
	}
}

func (h *Handler) serverError(w http.ResponseWriter, err error) {
	h.log.Error("admin request failed", "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

var pageNames = []string{"login", "refused", "me", "identities", "identity", "token", "services", "audit", "signing-keys"}

func parsePages() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"time": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") },
	}
	pages := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return pages, nil
}
