package query

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/alerting"
)

const maxAlerts = 100

var alertsUntrusted = []string{"data[].labels", "data[].annotations", "data[].value"}

// alertStates maps the lowercased state to the reported one; states not listed (normal,
// inactive) mean the alert is not active.
var alertStates = map[string]string{
	"firing":     "firing",
	"alerting":   "firing",
	"pending":    "pending",
	"recovering": "recovering",
	"nodata":     "nodata",
	"error":      "error",
}

// alertOrder puts the alerts that need attention first.
var alertOrder = map[string]int{"firing": 0, "error": 1, "nodata": 2, "pending": 3, "recovering": 4}

// Alerts returns the service's active alerts. Alerts have no history in this API, so they
// show the current state regardless of a range.
func (s *Service) Alerts(ctx context.Context, identity *authz.Identity, service, env string) (api.Response[[]api.Alert], error) {
	scope, err := s.authz.AlertScope(identity, service, env)
	if err != nil {
		return api.Response[[]api.Alert]{}, err
	}
	recordQuery(ctx, scope.Target, scope.Selector())
	alerts, err := s.connectors.Alerting[scope.Source().Name].Alerts(ctx)
	if err != nil {
		return api.Response[[]api.Alert]{}, err
	}
	result := s.scopeAlerts(scope, alerts)
	meta := api.Meta{
		Service:     service,
		Environment: scope.Environment(),
		Sources:     []api.SourceRef{{Kind: string(scope.Source().Type), Query: scope.Selector()}},
		Untrusted:   alertsUntrusted,
		Truncated:   len(result) > maxAlerts,
	}
	return api.Response[[]api.Alert]{Data: result[:min(len(result), maxAlerts)], Meta: meta}, nil
}

// scopeAlerts keeps the active alerts whose labels match every matcher of the scope. The
// ruler returns the alerts of all services, so this filter is the scope itself.
func (s *Service) scopeAlerts(scope authz.SelectorScope, alerts []alerting.Alert) []api.Alert {
	matchers := scope.Matchers()
	result := []api.Alert{}
	for _, a := range alerts {
		if !slices.ContainsFunc(matchers, func(m *labels.Matcher) bool { return !m.Matches(a.Labels[m.Name]) }) {
			if alert, ok := s.shapeAlert(a); ok {
				result = append(result, alert)
			}
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if alertOrder[a.State] != alertOrder[b.State] {
			return alertOrder[a.State] < alertOrder[b.State]
		}
		if a.ActiveAt != nil && b.ActiveAt != nil && !a.ActiveAt.Equal(*b.ActiveAt) {
			return a.ActiveAt.After(*b.ActiveAt)
		}
		return a.Name < b.Name
	})
	return result
}

func (s *Service) shapeAlert(a alerting.Alert) (api.Alert, bool) {
	state, reason, _ := strings.Cut(a.State, " ")
	state, ok := alertStates[strings.ToLower(state)]
	if !ok {
		return api.Alert{}, false
	}
	alert := api.Alert{
		Name:        a.Labels["alertname"],
		State:       state,
		StateReason: strings.Trim(reason, "()"),
		ActiveAt:    a.ActiveAt,
		Value:       a.Value,
		Labels:      maps.Clone(a.Labels),
	}
	if alert.Labels == nil {
		alert.Labels = map[string]string{}
	}
	// Grafana keeps internal values such as __dashboardUid__ in __-prefixed annotations.
	for name, value := range a.Annotations {
		if strings.HasPrefix(name, "__") {
			continue
		}
		if alert.Annotations == nil {
			alert.Annotations = map[string]string{}
		}
		alert.Annotations[name] = s.redactor.Redact(value)
	}
	return alert, true
}
