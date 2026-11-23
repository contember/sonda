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

type identityRow struct {
	Name      string
	CreatedAt time.Time
	Grants    []grantSummary
	Limits    []string
}

// grantSummary is the capabilities an identity has in one project environment.
type grantSummary struct {
	Target       string
	Capabilities []string
	// Wildcard is set when the target or a capability is a wildcard; Covers then counts the
	// service environments its grants open with the current configuration.
	Wildcard bool
	Covers   int
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
			Grants:    h.summarizeGrants(identity.Grants),
			Limits:    summarizeLimits(identity.Limits),
		})
	}
	h.render(w, http.StatusOK, "identities", view{Title: "Identities", Lead: "Agents and the services they may query. Changes apply to the next request.", Nav: "identities", Data: rows})
}

// identityForm is the model of the create and edit page.
type identityForm struct {
	IsNew bool
	Name  string
	// Capabilities are the columns of Matrix, granted per project.
	Capabilities []api.Capability
	Matrix       []matrixRow
	// ServiceMatrix holds the per-service capabilities, one row per service environment.
	ServiceCapabilities []api.Capability
	ServiceMatrix       []serviceMatrixRow
	Limits              []limitField
	// Stale lists stored grants for projects or capabilities that are no longer configured.
	Stale []string
	// Coverage lists what each stored wildcard grant opens with the current configuration.
	Coverage []wildcardCoverage
}

type matrixRow struct {
	Project     string
	Environment string
	// Services are the services that have the environment, which a grant of the row covers.
	Services []string
	// Wildcard is set when the project or the environment is a wildcard.
	Wildcard bool
	Cells    []matrixCell
}

type wildcardCoverage struct {
	Grant string
	// Covers are the capabilities the grant opens, by service environment.
	Covers []grantSummary
}

type serviceMatrixRow struct {
	Project     string
	Service     string
	Environment string
	Cells       []matrixCell
}

type matrixCell struct {
	Available bool
	Checked   bool
	Value     string
	Label     string
	// CoveredBy names a selected wildcard grant that already covers this unselected cell.
	CoveredBy string
}

type limitField struct {
	Name    string
	Label   string
	Value   string
	Default string
}

func (h *Handler) newIdentity(w http.ResponseWriter, _ *http.Request) {
	form := h.identityForm(true, "", nil, identities.LimitOverrides{})
	h.render(w, http.StatusOK, "identity", view{Title: "New identity", Back: "/admin/identities", Nav: "identities", Data: form})
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
	h.render(w, http.StatusOK, "identity", view{Title: identity.Name, Back: "/admin/identities", Nav: "identities", Data: form})
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
	h.render(w, http.StatusOK, "token", view{Title: "Token for " + name, Back: "/admin/identities", Nav: "identities", Data: page})
}

func (h *Handler) renderFormError(w http.ResponseWriter, form identityForm, err error) {
	title := form.Name
	if form.IsNew {
		title = "New identity"
	}
	h.render(w, http.StatusUnprocessableEntity, "identity", view{Title: title, Back: "/admin/identities", Nav: "identities", Error: err.Error(), Data: form})
}

func (h *Handler) identityForm(isNew bool, name string, grants []identities.Grant, limits identities.LimitOverrides) identityForm {
	form := identityForm{IsNew: isNew, Name: name, Limits: h.limitFields(limits)}
	for _, capability := range api.Capabilities {
		if identities.PerService(capability) {
			form.ServiceCapabilities = append(form.ServiceCapabilities, capability)
		} else {
			form.Capabilities = append(form.Capabilities, capability)
		}
	}
	form.Capabilities = append(form.Capabilities, identities.AnyCapability)
	servicesByEnv := map[string][]string{}
	var allServices []string
	for _, projectName := range sortedKeys(h.cfg.Projects) {
		project := h.cfg.Projects[projectName]
		projectServicesByEnv := map[string][]string{}
		for _, svcName := range sortedKeys(project.Services) {
			allServices = append(allServices, svcName)
			for envName := range project.Services[svcName].Environments {
				projectServicesByEnv[envName] = append(projectServicesByEnv[envName], svcName)
				servicesByEnv[envName] = append(servicesByEnv[envName], svcName)
			}
		}
		for _, envName := range sortedKeys(projectServicesByEnv) {
			form.Matrix = append(form.Matrix, h.matrixRow(projectName, envName, projectServicesByEnv[envName], form.Capabilities, grants))
		}
		form.Matrix = append(form.Matrix, h.matrixRow(projectName, identities.Wildcard, sortedKeys(project.Services), form.Capabilities, grants))
		for _, svcName := range sortedKeys(project.Services) {
			svc := project.Services[svcName]
			for _, envName := range sortedKeys(svc.Environments) {
				row := serviceMatrixRow{Project: projectName, Service: svcName, Environment: envName}
				offered := false
				for _, capability := range form.ServiceCapabilities {
					grant := identities.Grant{Service: svcName, Environment: envName, Capability: capability}
					available := slices.Contains(svc.Environments[envName].Capabilities(), capability)
					offered = offered || available
					row.Cells = append(row.Cells, matrixCell{Available: available, Checked: slices.Contains(grants, grant), Value: grantValue(grant), Label: grantLabel(grant)})
				}
				if offered {
					form.ServiceMatrix = append(form.ServiceMatrix, row)
				}
			}
		}
	}
	if len(h.cfg.Projects) > 0 {
		for _, envName := range sortedKeys(servicesByEnv) {
			services := servicesByEnv[envName]
			sort.Strings(services)
			form.Matrix = append(form.Matrix, h.matrixRow(identities.Wildcard, envName, services, form.Capabilities, grants))
		}
		sort.Strings(allServices)
		form.Matrix = append(form.Matrix, h.matrixRow(identities.Wildcard, identities.Wildcard, allServices, form.Capabilities, grants))
	}
	for _, g := range grants {
		if !h.configured(g) {
			form.Stale = append(form.Stale, grantName(g))
		} else if g.HasWildcard() {
			form.Coverage = append(form.Coverage, wildcardCoverage{Grant: grantName(g), Covers: h.coverage(g)})
		}
	}
	return form
}

// matrixRow builds the project grant cells of one project (or *) and environment (or *). A cell
// with a wildcard can always be selected: it also covers what the configuration adds later.
func (h *Handler) matrixRow(project, env string, services []string, capabilities []api.Capability, grants []identities.Grant) matrixRow {
	row := matrixRow{Project: project, Environment: env, Services: services, Wildcard: project == identities.Wildcard || env == identities.Wildcard}
	for _, capability := range capabilities {
		grant := identities.Grant{Project: project, Environment: env, Capability: capability}
		cell := matrixCell{
			Available: grant.HasWildcard() || h.cfg.Projects[project].Offers(env, capability),
			Checked:   slices.Contains(grants, grant),
			Value:     grantValue(grant),
			Label:     grantLabel(grant),
		}
		if !cell.Checked {
			for _, g := range grants {
				if g.HasWildcard() && g.Covers(project, "", env, capability) {
					cell.CoveredBy = grantLabel(g)
					break
				}
			}
		}
		row.Cells = append(row.Cells, cell)
	}
	return row
}

// coverage lists the capabilities a grant opens with the current configuration, by service
// environment.
func (h *Handler) coverage(g identities.Grant) []grantSummary {
	byTarget := map[string][]string{}
	for _, svcName := range sortedKeys(h.cfg.Services) {
		svc := h.cfg.Services[svcName]
		for _, envName := range sortedKeys(svc.Environments) {
			for _, capability := range svc.Environments[envName].Capabilities() {
				if g.Covers(svc.Project.Name, svcName, envName, capability) {
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
// anything else would have no effect. A wildcard grant must name configured values in its
// other positions; what it matches may be configured later.
func (h *Handler) configured(g identities.Grant) bool {
	if !g.Valid() {
		return false
	}
	if identities.PerService(g.Capability) {
		svc, ok := h.cfg.Services[g.Service]
		if !ok {
			return false
		}
		env, ok := svc.Environments[g.Environment]
		return ok && slices.Contains(env.Capabilities(), g.Capability)
	}
	if !g.HasWildcard() {
		project, ok := h.cfg.Projects[g.Project]
		return ok && project.Offers(g.Environment, g.Capability)
	}
	if _, ok := h.cfg.Projects[g.Project]; !ok && g.Project != identities.Wildcard {
		return false
	}
	if g.Environment == identities.Wildcard {
		return true
	}
	for _, svc := range h.cfg.Services {
		if _, ok := svc.Environments[g.Environment]; ok && (g.Project == identities.Wildcard || svc.Project.Name == g.Project) {
			return true
		}
	}
	return false
}

// grantTarget names what a grant covers: its project, or its service for a per-service grant.
func grantTarget(g identities.Grant) string {
	if g.Service != "" {
		return "service " + g.Service
	}
	return g.Project
}

// grantName shows a grant as target / environment / capability, e.g. "shop / * / metrics".
func grantName(g identities.Grant) string {
	return grantTarget(g) + " / " + g.Environment + " / " + string(g.Capability)
}

// grantLabel spells out the wildcards of grantName, because screen readers often skip "*".
func grantLabel(g identities.Grant) string {
	spell := func(value, words string) string {
		if value == identities.Wildcard {
			return words
		}
		return value
	}
	return spell(grantTarget(g), "every project") + " / " + spell(g.Environment, "every environment") + " / " + spell(string(g.Capability), "every capability")
}

// grantValue encodes a grant as a checkbox value. Names come from the config and may contain
// any character, so they are URL-encoded.
func grantValue(g identities.Grant) string {
	v := url.Values{"e": {g.Environment}, "c": {string(g.Capability)}}
	if g.Service != "" {
		v.Set("s", g.Service)
	} else {
		v.Set("p", g.Project)
	}
	return v.Encode()
}

func parseGrantValue(value string) (identities.Grant, error) {
	q, err := url.ParseQuery(value)
	if err != nil {
		return identities.Grant{}, err
	}
	capability, err := identities.ParseCapability(q.Get("c"))
	if err != nil {
		return identities.Grant{}, err
	}
	return identities.Grant{Project: q.Get("p"), Service: q.Get("s"), Environment: q.Get("e"), Capability: capability}, nil
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

// summarizeGrants groups grants by project environment, e.g. "shop / production" with
// errors and logs. A group with a wildcard counts the service environments it covers today.
func (h *Handler) summarizeGrants(grants []identities.Grant) []grantSummary {
	byTarget := map[string][]identities.Grant{}
	for _, g := range grants {
		target := grantTarget(g) + " / " + g.Environment
		byTarget[target] = append(byTarget[target], g)
	}
	summary := make([]grantSummary, 0, len(byTarget))
	for _, target := range sortedKeys(byTarget) {
		group := grantSummary{Target: target}
		covered := map[string]bool{}
		for _, g := range byTarget[target] {
			group.Capabilities = append(group.Capabilities, string(g.Capability))
			if g.HasWildcard() {
				group.Wildcard = true
				for _, c := range h.coverage(g) {
					covered[c.Target] = true
				}
			}
		}
		group.Covers = len(covered)
		summary = append(summary, group)
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
