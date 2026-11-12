package admin

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

// servicesPage is a read-only view of the configuration: what agents can be granted and
// where each capability reads from. It never shows credentials, header values or URL paths.
type servicesPage struct {
	Projects []projectView
	Sources  []sourceView
}

type projectView struct {
	Name        string
	Description string
	Services    []serviceView
}

type serviceView struct {
	Name        string
	Description string
	Repository  string
	// RepositoryURL is set when Repository is an http(s) URL, so it can be a link.
	RepositoryURL string
	Environments  []environmentView
	Signals       []string
}

type environmentView struct {
	Name     string
	Bindings []bindingView
	// Identities is the number of identities with a grant of the project that covers a
	// capability configured here.
	Identities int
}

type bindingView struct {
	Capability string
	Source     string
	SourceType string
	Scope      string
}

type sourceView struct {
	Name    string
	Type    string
	Host    string
	Auth    string
	Headers []string
	// UsedBy lists "service / environment" pairs that read from the source.
	UsedBy []string
}

func (h *Handler) listServices(w http.ResponseWriter, r *http.Request) {
	list, err := h.identities.List(r.Context())
	if err != nil {
		h.serverError(w, err)
		return
	}
	// A project grant reaches a service environment only for the capabilities it configures.
	granted := map[identities.Grant]map[string]bool{}
	for _, identity := range list {
		for _, g := range identity.Grants {
			if granted[g] == nil {
				granted[g] = map[string]bool{}
			}
			granted[g][identity.Name] = true
		}
	}

	page := servicesPage{}
	usedBy := map[string][]string{}
	for _, projectName := range sortedKeys(h.cfg.Projects) {
		project := h.cfg.Projects[projectName]
		pv := projectView{Name: projectName, Description: project.Description}
		for _, svcName := range sortedKeys(project.Services) {
			svc := project.Services[svcName]
			sv := serviceView{Name: svcName, Description: svc.Description, Repository: svc.Repository, RepositoryURL: repositoryURL(svc.Repository), Signals: sortedKeys(svc.Signals)}
			for _, envName := range sortedKeys(svc.Environments) {
				env := svc.Environments[envName]
				holders := map[string]bool{}
				for _, capability := range env.Capabilities() {
					for name := range granted[identities.Grant{Project: projectName, Environment: envName, Capability: capability}] {
						holders[name] = true
					}
				}
				ev := environmentView{Name: envName, Bindings: bindings(env), Identities: len(holders)}
				for _, b := range ev.Bindings {
					target := svcName + " / " + envName
					if !slices.Contains(usedBy[b.Source], target) {
						usedBy[b.Source] = append(usedBy[b.Source], target)
					}
				}
				sv.Environments = append(sv.Environments, ev)
			}
			pv.Services = append(pv.Services, sv)
		}
		page.Projects = append(page.Projects, pv)
	}
	for _, name := range sortedKeys(h.cfg.Sources) {
		src := h.cfg.Sources[name]
		page.Sources = append(page.Sources, sourceView{
			Name:    name,
			Type:    string(src.Type),
			Host:    sourceHost(src),
			Auth:    sourceAuth(src),
			Headers: sortedKeys(src.Headers),
			UsedBy:  usedBy[name],
		})
	}
	h.render(w, http.StatusOK, "services", view{Title: "Services", Lead: "What agents can be granted and where it is read from. Defined in the configuration file; read-only here.", Nav: "services", Data: page})
}

// bindings describes what each configured capability of an environment reads.
func bindings(env *config.Environment) []bindingView {
	var out []bindingView
	add := func(capability string, src *config.Source, scope string) {
		out = append(out, bindingView{Capability: capability, Source: src.Name, SourceType: string(src.Type), Scope: scope})
	}
	if b := env.Errors; b != nil {
		scope := "project " + b.Project
		if b.Environment != "" {
			scope += ", environment " + b.Environment
		}
		if b.Query != "" {
			scope += ", search " + b.Query
		}
		add("errors", b.Source, scope)
	}
	if b := env.Logs; b != nil {
		switch {
		case b.Selector != nil:
			add("logs", b.Source, b.Selector.Text)
		case b.Script != "":
			add("logs", b.Source, "script "+b.Script)
		case b.Project != "":
			add("logs", b.Source, "project "+b.Project+", environment "+b.Environment)
		default:
			add("logs", b.Source, "log groups "+strings.Join(b.LogGroups, ", "))
		}
	}
	if b := env.Metrics; b != nil {
		switch {
		case b.Selector != nil:
			add("metrics", b.Source, b.Selector.Text)
		case b.Script != "":
			scope := "script " + b.Script
			for _, kind := range slices.Sorted(maps.Keys(b.CloudflareResources)) {
				scope += ", " + string(kind) + " " + strings.Join(sortedKeys(b.CloudflareResources[kind]), ", ")
			}
			add("metrics", b.Source, scope)
		default:
			scope := "namespace " + b.Namespace
			for _, k := range sortedKeys(b.Dimensions) {
				scope += ", " + k + "=" + b.Dimensions[k]
			}
			add("metrics", b.Source, scope)
		}
	}
	if b := env.Traces; b != nil {
		switch {
		case b.Script != "":
			add("traces", b.Source, "script "+b.Script)
		case b.Project != "":
			scope := "project " + b.Project
			if b.Environment != "" {
				scope += ", environment " + b.Environment
			}
			add("traces", b.Source, scope)
		default:
			add("traces", b.Source, "service.name "+b.ServiceName)
		}
	}
	if b := env.Workloads; b != nil {
		scope := "namespace " + b.Namespace
		for _, k := range sortedKeys(b.Labels) {
			scope += ", " + k + "=" + b.Labels[k]
		}
		add("workloads", b.Source, scope)
	}
	if b := env.Alerts; b != nil {
		add("alerts", b.Source, b.Selector.Text)
	}
	return out
}

// sourceHost shows only the scheme and host: paths and query strings can carry tenant IDs or
// tokens.
func sourceHost(src *config.Source) string {
	if src.AWS != nil {
		return "AWS " + src.AWS.Region
	}
	u, err := url.Parse(src.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func sourceAuth(src *config.Source) string {
	switch {
	case src.AWS != nil && src.AWS.Credentials == config.AWSIdentity:
		return "Sonda identity, assume role"
	case src.AWS != nil && src.AWS.RoleARN != "":
		return "credential chain, assume role"
	case src.AWS != nil:
		return "credential chain"
	case src.Auth.EKS != nil:
		return "eks via " + src.Auth.EKS.AWS.Name
	case src.Auth.TokenFile != "":
		return "service account"
	}
	return string(src.Auth.Type)
}

// repositoryURL returns the repository as a link target only when it is an http(s) URL.
func repositoryURL(repo string) string {
	u, err := url.Parse(repo)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return repo
}
