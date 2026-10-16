// Package query implements the API use cases. Every method authorizes through authz
// before touching a source.
package query

import (
	"slices"
	"sort"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
)

type Service struct {
	cfg   *config.Config
	authz *authz.Authorizer
	now   func() time.Time
}

func New(cfg *config.Config, authorizer *authz.Authorizer) *Service {
	return &Service{cfg: cfg, authz: authorizer, now: time.Now}
}

func (s *Service) ListServices(identity *config.Identity) api.Response[[]api.ServiceSummary] {
	services := s.authz.Services(identity)
	summaries := make([]api.ServiceSummary, 0, len(services))
	for _, svc := range services {
		summary := api.ServiceSummary{Name: svc.Name, Description: svc.Description}
		for _, env := range s.authz.Environments(identity, svc) {
			summary.Environments = append(summary.Environments, env.Name)
		}
		summaries = append(summaries, summary)
	}
	return api.Response[[]api.ServiceSummary]{Data: summaries}
}

func (s *Service) DescribeService(identity *config.Identity, name string) (api.Response[api.ServiceDetail], error) {
	svc, err := s.authz.Service(identity, name)
	if err != nil {
		return api.Response[api.ServiceDetail]{}, err
	}
	detail := api.ServiceDetail{
		Name:         svc.Name,
		Description:  svc.Description,
		Repository:   svc.Repository,
		Environments: s.authz.Environments(identity, svc),
	}
	hasMetrics := slices.ContainsFunc(detail.Environments, func(env api.EnvironmentDetail) bool {
		return slices.Contains(env.Capabilities, api.CapabilityMetrics)
	})
	if hasMetrics {
		for signal := range svc.Signals {
			detail.Signals = append(detail.Signals, signal)
		}
		sort.Strings(detail.Signals)
	}
	return api.Response[api.ServiceDetail]{Data: detail, Meta: api.Meta{Service: svc.Name}}, nil
}
