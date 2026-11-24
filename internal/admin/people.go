package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/signin"
	"github.com/contember/sonda/internal/store"
)

const (
	// signInCookie carries the state and the PKCE verifier of a sign-in in flight. Lax, because
	// the authorization server redirects back with a cross-site navigation.
	signInCookie = "sonda_admin_signin"
	signInTTL    = 10 * 60
	maxSubject   = 200
)

func (h *Handler) clientMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(h.signin.ClientMetadata())
}

func (h *Handler) startSignIn(w http.ResponseWriter, r *http.Request) {
	attempt := signin.NewAttempt()
	target, err := h.signin.AuthorizationURL(r.Context(), attempt)
	if err != nil {
		h.log.Error("start admin sign-in", "error", err)
		h.renderLogin(w, r, http.StatusBadGateway, "The sign-in service is unavailable. Try again later, or use the break-glass admin token.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     signInCookie,
		Value:    attempt.State + "." + attempt.Verifier,
		Path:     "/admin/oauth",
		MaxAge:   signInTTL,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// signInCallback finishes a sign-in. When the token names roles, they decide the person's role:
// sonda-admin manages Sonda, linked or not, and sonda-viewer needs a link; a token without a
// Sonda role is refused. Without a roles claim, the link decides as before. Data grants always
// come from the linked identity, never from the token.
func (h *Handler) signInCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: signInCookie, Path: "/admin/oauth", MaxAge: -1, HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode})
	query := r.URL.Query()
	var attempt signin.Attempt
	if cookie, err := r.Cookie(signInCookie); err == nil {
		attempt.State, attempt.Verifier, _ = strings.Cut(cookie.Value, ".")
	}
	if !attempt.Matches(query.Get("state")) || attempt.Verifier == "" {
		noteAudit(r, strings.TrimSpace(refusedIdentity), true)
		h.renderLogin(w, r, http.StatusBadRequest, "The sign-in expired or was started in another browser. Sign in again.")
		return
	}
	if code := query.Get("error"); code != "" {
		noteAudit(r, strings.TrimSpace(refusedIdentity), true)
		h.renderLogin(w, r, http.StatusUnauthorized, "The sign-in service did not sign you in ("+code+").")
		return
	}
	person, err := h.signin.Exchange(r.Context(), signin.Callback{Code: query.Get("code"), Issuer: query.Get("iss")}, attempt)
	if err != nil {
		noteAudit(r, strings.TrimSpace(refusedIdentity), true)
		h.log.Warn("admin sign-in failed", "error", err)
		h.renderLogin(w, r, http.StatusUnauthorized, "The sign-in could not be verified. Sign in again.")
		return
	}
	if person.Role == signin.RoleNone {
		noteAudit(r, refusedIdentity+person.Subject, true)
		h.log.Warn("admin sign-in refused: the token names no Sonda role", "subject", person.Subject)
		h.render(w, r, http.StatusForbidden, "refused", view{Title: "No access to Sonda", Data: refusedPage{Person: person, NoRole: true}})
		return
	}
	link, err := h.store.PersonBySubject(r.Context(), h.signin.Issuer(), person.Subject)
	linked := err == nil
	if err != nil && !errors.Is(err, store.ErrPersonNotFound) {
		h.serverError(w, err)
		return
	}
	if !linked && person.Role != signin.RoleAdmin {
		noteAudit(r, refusedIdentity+person.Subject, true)
		h.log.Warn("admin sign-in refused: subject is not linked to an identity", "subject", person.Subject)
		h.render(w, r, http.StatusForbidden, "refused", view{Title: "No access to Sonda", Data: refusedPage{Person: person}})
		return
	}
	kind := map[signin.Role]store.AdminSessionKind{
		signin.RoleUnset:  store.SessionPerson,
		signin.RoleAdmin:  store.SessionPersonAdmin,
		signin.RoleViewer: store.SessionPersonViewer,
	}[person.Role]
	session := store.AdminSession{Kind: kind, Issuer: h.signin.Issuer(), Subject: person.Subject, Label: person.Label}
	if err := h.startSession(w, r, session); err != nil {
		h.serverError(w, err)
		return
	}
	if linked {
		noteAudit(r, personIdentity+link.Identity, true)
	} else {
		noteAudit(r, unlinkedIdentity+person.Subject, true)
	}
	h.log.Info("admin signed in", "identity", link.Identity, "role", string(person.Role))
	// The session cookie is SameSite=Strict, so a redirect that is still part of the server's
	// cross-site navigation would not carry it. A page of this origin that navigates does.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/admin/"><title>Signed in · Sonda admin</title></head><body><p><a href="/admin/">Continue to Sonda admin</a></p></body></html>`))
}

// refusedPage tells a refused person why: no Sonda role at the sign-in service, or no link.
type refusedPage struct {
	Person signin.Person
	NoRole bool
}

// linkPerson lets the person with the subject sign in as the identity.
func (h *Handler) linkPerson(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	subject := strings.TrimSpace(r.PostFormValue("subject"))
	if subject == "" || len(subject) > maxSubject || strings.ContainsFunc(subject, unicode.IsSpace) {
		h.renderIdentityError(w, r, name, errors.New("subject must be 1-200 characters without spaces: the subject the sign-in service shows to a refused person"))
		return
	}
	err := h.store.LinkPerson(r.Context(), store.Person{
		Identity:  name,
		Issuer:    h.signin.Issuer(),
		Subject:   subject,
		Admin:     r.PostFormValue("admin") == "on",
		CreatedAt: h.now(),
	})
	if errors.Is(err, store.ErrIdentityNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, store.ErrSubjectTaken) {
		h.renderIdentityError(w, r, name, errors.New("this subject is already linked to another identity"))
		return
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	h.log.Info("person linked", "identity", name)
	redirect(w, r, "/admin/identities/"+name)
}

func (h *Handler) unlinkPerson(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.UnlinkPerson(r.Context(), name); err != nil {
		h.serverError(w, err)
		return
	}
	h.log.Info("person unlinked", "identity", name)
	redirect(w, r, "/admin/identities/"+name)
}

func (h *Handler) renderIdentityError(w http.ResponseWriter, r *http.Request, name string, err error) {
	identity, getErr := h.identities.Get(r.Context(), name)
	if errors.Is(getErr, identities.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if getErr != nil {
		h.serverError(w, getErr)
		return
	}
	h.renderFormError(w, r, h.identityForm(false, name, identity.Grants, identity.Limits), err)
}

// accessPage shows a person what their identity's grants open with the current configuration.
type accessPage struct {
	Identity string
	Admin    bool
	Grants   []grantSummary
	Access   []grantSummary
}

func (h *Handler) myAccess(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r.Context())
	// Only an administrator has no identity: break-glass, or by role without a link.
	if a.breakGlass || a.person.Identity == "" {
		http.Redirect(w, r, "/admin/identities", http.StatusSeeOther)
		return
	}
	identity, err := h.identities.Get(r.Context(), a.person.Identity)
	if err != nil {
		h.serverError(w, err)
		return
	}
	page := accessPage{Identity: identity.Name, Admin: a.admin(), Grants: h.summarizeGrants(identity.Grants), Access: h.coverage(identity.Grants)}
	h.render(w, r, http.StatusOK, "me", view{Title: "My access", Lead: "What your Sonda identity may query. An administrator changes it.", Nav: "me", Data: page})
}

// coverage lists the capabilities the grants open with the current configuration, by service
// environment.
func (h *Handler) coverage(grants []identities.Grant) []grantSummary {
	byTarget := map[string][]string{}
	for _, svcName := range sortedKeys(h.cfg.Services) {
		svc := h.cfg.Services[svcName]
		for _, envName := range sortedKeys(svc.Environments) {
			for _, capability := range svc.Environments[envName].Capabilities() {
				if slices.ContainsFunc(grants, func(g identities.Grant) bool { return g.Covers(svc.Project.Name, svcName, envName, capability) }) {
					target := svcName + " / " + envName
					byTarget[target] = append(byTarget[target], string(capability))
				}
			}
		}
	}
	summary := make([]grantSummary, 0, len(byTarget))
	for _, target := range sortedKeys(byTarget) {
		summary = append(summary, grantSummary{Target: target, Capabilities: byTarget[target]})
	}
	return summary
}
