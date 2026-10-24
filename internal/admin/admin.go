// Package admin serves the admin UI under /admin: identity management, a read-only view of the
// configured services and sources, and the audit log. Sources and services stay in the config
// file and are not editable here, so provider credentials never reach the database.
package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/store"
)

//go:embed templates static
var assets embed.FS

const (
	sessionCookie = "sonda_admin"
	sessionTTL    = 12 * time.Hour
	// auditIdentity marks admin actions in the audit log. Identity names cannot contain
	// parentheses, so it never collides with an agent.
	auditIdentity = "(admin)"
)

type Handler struct {
	cfg        *config.Config
	identities identities.Store
	store      *store.Store
	log        *slog.Logger
	pages      map[string]*template.Template
	now        func() time.Time
}

func New(cfg *config.Config, ids identities.Store, st *store.Store, log *slog.Logger) (http.Handler, error) {
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	h := &Handler{cfg: cfg, identities: ids, store: st, log: log, pages: pages, now: time.Now}

	static, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	authed := http.NewServeMux()
	authed.HandleFunc("GET /admin/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/identities", http.StatusSeeOther)
	})
	authed.HandleFunc("POST /admin/logout", h.logout)
	authed.HandleFunc("GET /admin/identities", h.listIdentities)
	authed.HandleFunc("GET /admin/identities/new", h.newIdentity)
	authed.HandleFunc("POST /admin/identities", h.createIdentity)
	authed.HandleFunc("GET /admin/identities/{name}", h.editIdentity)
	authed.HandleFunc("POST /admin/identities/{name}", h.updateIdentity)
	authed.HandleFunc("POST /admin/identities/{name}/token", h.rotateToken)
	authed.HandleFunc("POST /admin/identities/{name}/delete", h.deleteIdentity)
	authed.HandleFunc("GET /admin/services", h.listServices)
	authed.HandleFunc("GET /admin/audit", h.auditLog)

	mux := http.NewServeMux()
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /admin/login", h.loginForm)
	mux.HandleFunc("POST /admin/login", h.login)
	mux.Handle("/admin/", h.requireSession(authed))

	// Rejects cross-origin form posts, which together with SameSite cookies prevents CSRF.
	return http.NewCrossOriginProtection().Handler(h.audited(mux)), nil
}

func (h *Handler) loginForm(w http.ResponseWriter, r *http.Request) {
	if h.validSession(r) {
		http.Redirect(w, r, "/admin/identities", http.StatusSeeOther)
		return
	}
	h.render(w, http.StatusOK, "login", view{Title: "Sign in"})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	given := sha256.Sum256([]byte(r.PostFormValue("token")))
	want := sha256.Sum256([]byte(h.cfg.Admin.Token))
	if subtle.ConstantTimeCompare(given[:], want[:]) != 1 {
		h.render(w, http.StatusUnauthorized, "login", view{Title: "Sign in", Error: "Invalid admin token."})
		return
	}
	expires := h.now().Add(sessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    h.signSession(expires),
		Path:     "/admin",
		Expires:  expires,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/admin/identities", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode})
	redirect(w, r, "/admin/login")
}

func (h *Handler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.validSession(r) {
			redirect(w, r, "/admin/login")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// A session cookie is its expiry signed with the admin token. Changing the token ends all
// sessions; nothing is stored on the server.
func (h *Handler) signSession(expires time.Time) string {
	unix := strconv.FormatInt(expires.Unix(), 10)
	return unix + "." + h.sessionSignature(unix)
}

func (h *Handler) sessionSignature(unix string) string {
	mac := hmac.New(sha256.New, []byte(h.cfg.Admin.Token))
	mac.Write([]byte("sonda-admin-session:" + unix))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *Handler) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	unix, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok || !hmac.Equal([]byte(signature), []byte(h.sessionSignature(unix))) {
		return false
	}
	expires, err := strconv.ParseInt(unix, 10, 64)
	return err == nil && h.now().Unix() < expires
}

// audited records every state-changing admin request, including failed sign-ins.
func (h *Handler) audited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		start := h.now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		entry := store.AuditEntry{
			Time:     start,
			Identity: auditIdentity,
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
	Title string
	// Lead is a one-line description under the title.
	Lead string
	// Back is the parent page's URL, shown as a back link above the title.
	Back  string
	Nav   string
	Error string
	Data  any
}

func (h *Handler) render(w http.ResponseWriter, status int, page string, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := h.pages[page].ExecuteTemplate(w, "layout", v); err != nil {
		h.log.Error("render admin page", "page", page, "error", err)
	}
}

func (h *Handler) serverError(w http.ResponseWriter, err error) {
	h.log.Error("admin request failed", "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

var pageNames = []string{"login", "identities", "identity", "token", "services", "audit"}

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
