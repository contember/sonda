package query

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/policy"
)

const (
	overviewIssues       = 5
	overviewAlerts       = 10
	overviewSignalSeries = 5
)

// Overview collects recent releases, top issues and signal summaries in one call. Each
// part loads independently; a failing source fills the part's error instead of failing all.
func (s *Service) Overview(ctx context.Context, identity *authz.Identity, service string, w api.Window) (api.Response[api.Overview], error) {
	var resp api.Response[api.Overview]
	svc, err := s.authz.Service(identity, service)
	if err != nil {
		return resp, err
	}
	env, err := s.overviewEnvironment(identity, svc, w.Environment)
	if err != nil {
		return resp, err
	}
	w.Environment = env.Name
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultErrorsSince)
	if err != nil {
		return resp, err
	}
	// Pin the range, so every part covers exactly the same window.
	w = api.Window{Environment: env.Name, From: &r.From, To: &r.To}

	var wg sync.WaitGroup
	if slices.Contains(env.Capabilities, api.CapabilityErrors) {
		resp.Data.Releases = &api.OverviewPart[[]api.Release]{}
		resp.Data.Issues = &api.OverviewPart[[]api.Issue]{}
		wg.Go(func() {
			releases, err := s.Releases(ctx, identity, service, w)
			resp.Data.Releases.Items, resp.Data.Releases.Error = releases.Data, partError(err)
		})
		wg.Go(func() {
			issues, err := s.ListErrors(ctx, identity, service, w, "", overviewIssues)
			resp.Data.Issues.Items, resp.Data.Issues.Error = issues.Data, partError(err)
		})
	}
	if slices.Contains(env.Capabilities, api.CapabilityWorkloads) {
		resp.Data.Workloads = &api.OverviewPart[*api.WorkloadSummary]{}
		wg.Go(func() {
			summary, err := s.WorkloadSummary(ctx, identity, service, w)
			resp.Data.Workloads.Items, resp.Data.Workloads.Error = summary, partError(err)
		})
	}
	if slices.Contains(env.Capabilities, api.CapabilityAlerts) {
		resp.Data.Alerts = &api.OverviewPart[[]api.Alert]{}
		wg.Go(func() {
			alerts, err := s.Alerts(ctx, identity, service, env.Name)
			resp.Data.Alerts.Items, resp.Data.Alerts.Error = alerts.Data[:min(len(alerts.Data), overviewAlerts)], partError(err)
		})
	}
	if slices.Contains(env.Capabilities, api.CapabilityMetrics) {
		names := make([]string, 0, len(svc.Signals))
		for name := range svc.Signals {
			names = append(names, name)
		}
		sort.Strings(names)
		resp.Data.Signals = make([]api.SignalOverview, len(names))
		for i, name := range names {
			wg.Go(func() {
				resp.Data.Signals[i] = s.signalOverview(ctx, identity, service, name, w)
			})
		}
	}
	wg.Wait()

	resp.Meta = api.Meta{Service: service, Environment: env.Name, Range: &r}
	resp.Meta.Untrusted = []string{"data.issues.items[].title", "data.issues.items[].culprit", "data.workloads.items.problems[]",
		"data.alerts.items[].labels", "data.alerts.items[].annotations", "data.alerts.items[].value",
	}
	return resp, nil
}

func (s *Service) overviewEnvironment(identity *authz.Identity, svc *config.Service, name string) (api.EnvironmentDetail, error) {
	envs := s.authz.Environments(identity, svc)
	if name == "" && len(envs) == 1 {
		return envs[0], nil
	}
	for _, env := range envs {
		if env.Name == name {
			return env, nil
		}
	}
	if name == "" {
		names := make([]string, len(envs))
		for i, env := range envs {
			names[i] = env.Name
		}
		return api.EnvironmentDetail{}, apierr.InvalidRequest("environment is required for service %q, one of: %s", svc.Name, strings.Join(names, ", "))
	}
	return api.EnvironmentDetail{}, apierr.NotFound("environment %q not found for service %q", name, svc.Name)
}

func (s *Service) signalOverview(ctx context.Context, identity *authz.Identity, service, name string, w api.Window) api.SignalOverview {
	overview := api.SignalOverview{Name: name}
	result, err := s.Signal(ctx, identity, service, name, w, "", false)
	if err != nil {
		overview.Error = partError(err)
		return overview
	}
	for _, series := range result.Data.Series {
		if len(overview.Series) == overviewSignalSeries {
			break
		}
		overview.Series = append(overview.Series, api.LabeledSummary{Labels: series.Labels, Summary: series.Summary})
	}
	return overview
}

func partError(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := apierr.As(err); ok {
		return e.Message
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return "internal error"
}
