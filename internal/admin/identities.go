package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/identities"
)

var capabilities = []api.Capability{api.CapabilityErrors, api.CapabilityLogs, api.CapabilityMetrics, api.CapabilityTraces}

type identityRow struct {
	Name      string
	CreatedAt time.Time
	Grants    []string
	Limits    []string
}

func (h *Handler) listIdentities(w http.ResponseWriter, r *http.Request) {
	list, err := h.identities.List(r.Context())
	if err != nil {
		h.serverError(w, err)
		return
	}
	rows := make([]identityRow, 0, len(list))
	for _, identity := range list {
		rows = append(rows, identityRow{
			Name:      identity.Name,
			CreatedAt: identity.CreatedAt,
			Grants:    summarizeGrants(identity.Grants),
			Limits:    summarizeLimits(identity.Limits),
		})
	}
	h.render(w, http.StatusOK, "identities", view{Title: "Identities", Nav: "identities", Data: rows})
}

// identityForm is the model of the create and edit page.
type identityForm struct {
	IsNew        bool
	Name         string
	Capabilities []api.Capability
	Matrix       []matrixRow
	Limits       []limitField
	// Stale lists stored grants for services or capabilities that are no longer configured.
	Stale []string
}

type matrixRow struct {
	Service     string
	Environment string
	Cells       []matrixCell
}

type matrixCell struct {
	Available bool
	Checked   bool
	Value     string
}

type limitField struct {
	Name    string
	Label   string
	Value   string
	Default string
}

func (h *Handler) newIdentity(w http.ResponseWriter, _ *http.Request) {
	form := h.identityForm(true, "", nil, identities.LimitOverrides{})
	h.render(w, http.StatusOK, "identity", view{Title: "New identity", Nav: "identities", Data: form})
}

func (h *Handler) createIdentity(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	grants, limits, err := h.parseIdentityForm(r)
	if err == nil {
		err = identities.ValidateName(name)
	}
	if err != nil {
		h.renderFormError(w, h.identityForm(true, name, grants, limits), err)
		return
	}
	token, hash := identities.NewToken()
	err = h.identities.Create(r.Context(), identities.Identity{
		Name:        name,
		TokenSHA256: hash,
		Grants:      grants,
		Limits:      limits,
		CreatedAt:   h.now(),
	})
	if errors.Is(err, identities.ErrExists) {
		h.renderFormError(w, h.identityForm(true, name, grants, limits), fmt.Errorf("identity %q already exists", name))
		return
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	h.log.Info("identity created", "identity", name)
	h.renderToken(w, r, name, token)
}

func (h *Handler) editIdentity(w http.ResponseWriter, r *http.Request) {
	identity, err := h.identities.Get(r.Context(), r.PathValue("name"))
	if errors.Is(err, identities.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	form := h.identityForm(false, identity.Name, identity.Grants, identity.Limits)
	h.render(w, http.StatusOK, "identity", view{Title: identity.Name, Nav: "identities", Data: form})
}

func (h *Handler) updateIdentity(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	grants, limits, err := h.parseIdentityForm(r)
	if err != nil {
		h.renderFormError(w, h.identityForm(false, name, grants, limits), err)
		return
	}
	err = h.identities.Update(r.Context(), name, grants, limits)
	if errors.Is(err, identities.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	h.log.Info("identity updated", "identity", name)
	redirect(w, r, "/admin/identities")
}

func (h *Handler) rotateToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	token, hash := identities.NewToken()
	err := h.identities.SetTokenHash(r.Context(), name, hash)
	if errors.Is(err, identities.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	h.log.Info("identity token rotated", "identity", name)
	h.renderToken(w, r, name, token)
}

func (h *Handler) deleteIdentity(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := h.identities.Delete(r.Context(), name)
	if err != nil && !errors.Is(err, identities.ErrNotFound) {
		h.serverError(w, err)
		return
	}
	h.log.Info("identity deleted", "identity", name)
	redirect(w, r, "/admin/identities")
}

type tokenPage struct {
	Name  string
	Token string
	URL   string
}

// renderToken shows the token once; only its hash is stored.
func (h *Handler) renderToken(w http.ResponseWriter, r *http.Request, name, token string) {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	page := tokenPage{Name: name, Token: token, URL: scheme + "://" + r.Host}
	// Keep the form's URL; the POST-only action URL would fail on reload.
	w.Header().Set("HX-Push-Url", "false")
	h.render(w, http.StatusOK, "token", view{Title: "Token for " + name, Nav: "identities", Data: page})
}

func (h *Handler) renderFormError(w http.ResponseWriter, form identityForm, err error) {
	title := form.Name
	if form.IsNew {
		title = "New identity"
	}
	h.render(w, http.StatusUnprocessableEntity, "identity", view{Title: title, Nav: "identities", Error: err.Error(), Data: form})
}

func (h *Handler) identityForm(isNew bool, name string, grants []identities.Grant, limits identities.LimitOverrides) identityForm {
	form := identityForm{IsNew: isNew, Name: name, Capabilities: capabilities, Limits: h.limitFields(limits)}
	for _, svcName := range sortedKeys(h.cfg.Services) {
		svc := h.cfg.Services[svcName]
		for _, envName := range sortedKeys(svc.Environments) {
			configured := svc.Environments[envName].Capabilities()
			row := matrixRow{Service: svcName, Environment: envName}
			for _, capability := range capabilities {
				grant := identities.Grant{Service: svcName, Environment: envName, Capability: capability}
				row.Cells = append(row.Cells, matrixCell{
					Available: slices.Contains(configured, capability),
					Checked:   slices.Contains(grants, grant),
					Value:     grantValue(grant),
				})
			}
			form.Matrix = append(form.Matrix, row)
		}
	}
	for _, g := range grants {
		if !h.configured(g) {
			form.Stale = append(form.Stale, fmt.Sprintf("%s / %s: %s", g.Service, g.Environment, g.Capability))
		}
	}
	return form
}

// parseIdentityForm returns what it could parse also on error, so the form can be shown again.
func (h *Handler) parseIdentityForm(r *http.Request) ([]identities.Grant, identities.LimitOverrides, error) {
	if err := r.ParseForm(); err != nil {
		return nil, identities.LimitOverrides{}, err
	}
	var errs []error
	var grants []identities.Grant
	for _, value := range r.PostForm["grant"] {
		grant, err := parseGrantValue(value)
		if err != nil || !h.configured(grant) {
			errs = append(errs, fmt.Errorf("invalid grant %q", value))
			continue
		}
		grants = append(grants, grant)
	}
	if len(grants) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("select at least one grant"))
	}
	limits := identities.LimitOverrides{
		MaxRange:          parseDuration(r, "max_range", &errs),
		MaxLogLines:       parsePositive(r, "max_log_lines", &errs),
		MaxResponseBytes:  parsePositive(r, "max_response_bytes", &errs),
		QueryTimeout:      parseDuration(r, "query_timeout", &errs),
		ConcurrentQueries: parsePositive(r, "concurrent_queries", &errs),
		RequestsPerMinute: parsePositive(r, "requests_per_minute", &errs),
	}
	return grants, limits, errors.Join(errs...)
}

// configured reports whether the grant points at a configured capability. Grants for
// anything else would have no effect.
func (h *Handler) configured(g identities.Grant) bool {
	svc, ok := h.cfg.Services[g.Service]
	if !ok {
		return false
	}
	env, ok := svc.Environments[g.Environment]
	return ok && slices.Contains(env.Capabilities(), g.Capability)
}

// grantValue encodes a grant as a checkbox value. Service and environment names come from
// the config and may contain any character, so they are URL-encoded.
func grantValue(g identities.Grant) string {
	return url.Values{"s": {g.Service}, "e": {g.Environment}, "c": {string(g.Capability)}}.Encode()
}

func parseGrantValue(value string) (identities.Grant, error) {
	q, err := url.ParseQuery(value)
	if err != nil {
		return identities.Grant{}, err
	}
	capability, err := api.ParseCapability(q.Get("c"))
	if err != nil {
		return identities.Grant{}, err
	}
	return identities.Grant{Service: q.Get("s"), Environment: q.Get("e"), Capability: capability}, nil
}

func (h *Handler) limitFields(o identities.LimitOverrides) []limitField {
	d := h.cfg.Limits
	return []limitField{
		{Name: "max_range", Label: "Max time range", Value: formatDuration(o.MaxRange), Default: model.Duration(d.MaxRange).String()},
		{Name: "max_log_lines", Label: "Max log lines", Value: formatInt(o.MaxLogLines), Default: strconv.Itoa(d.MaxLogLines)},
		{Name: "max_response_bytes", Label: "Max response bytes", Value: formatInt(o.MaxResponseBytes), Default: strconv.Itoa(d.MaxResponseBytes)},
		{Name: "query_timeout", Label: "Query timeout", Value: formatDuration(o.QueryTimeout), Default: model.Duration(d.QueryTimeout).String()},
		{Name: "concurrent_queries", Label: "Concurrent queries", Value: formatInt(o.ConcurrentQueries), Default: strconv.Itoa(d.ConcurrentQueries)},
		{Name: "requests_per_minute", Label: "Requests per minute", Value: formatInt(o.RequestsPerMinute), Default: strconv.Itoa(d.RequestsPerMinute)},
	}
}

func parseDuration(r *http.Request, field string, errs *[]error) *time.Duration {
	raw := strings.TrimSpace(r.PostFormValue(field))
	if raw == "" {
		return nil
	}
	d, err := model.ParseDuration(raw)
	if err != nil || d <= 0 {
		*errs = append(*errs, fmt.Errorf("%s: invalid duration %q, e.g. 30s, 6h or 7d", field, raw))
		return nil
	}
	value := time.Duration(d)
	return &value
}

func parsePositive(r *http.Request, field string, errs *[]error) *int {
	raw := strings.TrimSpace(r.PostFormValue(field))
	if raw == "" {
		return nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		*errs = append(*errs, fmt.Errorf("%s: must be a positive integer, got %q", field, raw))
		return nil
	}
	return &n
}

func formatDuration(d *time.Duration) string {
	if d == nil {
		return ""
	}
	return model.Duration(*d).String()
}

func formatInt(n *int) string {
	if n == nil {
		return ""
	}
	return strconv.Itoa(*n)
}

// summarizeGrants groups grants by service environment, e.g. "api / production: errors, logs".
func summarizeGrants(grants []identities.Grant) []string {
	byTarget := map[string][]string{}
	for _, g := range grants {
		target := g.Service + " / " + g.Environment
		byTarget[target] = append(byTarget[target], string(g.Capability))
	}
	summary := make([]string, 0, len(byTarget))
	for _, target := range sortedKeys(byTarget) {
		summary = append(summary, target+": "+strings.Join(byTarget[target], ", "))
	}
	return summary
}

func summarizeLimits(o identities.LimitOverrides) []string {
	var summary []string
	add := func(name, value string) {
		if value != "" {
			summary = append(summary, name+" "+value)
		}
	}
	add("max_range", formatDuration(o.MaxRange))
	add("max_log_lines", formatInt(o.MaxLogLines))
	add("max_response_bytes", formatInt(o.MaxResponseBytes))
	add("query_timeout", formatDuration(o.QueryTimeout))
	add("concurrent_queries", formatInt(o.ConcurrentQueries))
	add("requests_per_minute", formatInt(o.RequestsPerMinute))
	return summary
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
