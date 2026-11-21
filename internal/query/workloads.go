package query

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/policy"
)

const (
	defaultWorkloadsSince = time.Hour
	maxRollouts           = 10
	maxWorkloadEvents     = 50
)

var workloadsUntrusted = []string{
	"data.pods[].reason", "data.pods[].containers[].reason", "data.pods[].containers[].message",
	"data.pods[].containers[].lastTermination.reason", "data.pods[].containers[].lastTermination.message",
	"data.events[].reason", "data.events[].message", "data.nodes[].problems[]",
}

// workloadBackend reads the current workloads of one scope. Implementations bind the scope and
// the client and record their upstream queries with recordQuery.
type workloadBackend interface {
	// workloads returns the pods, all rollouts newest first and the events that overlap the
	// range newest first; the caller cuts the lists.
	workloads(ctx context.Context, r api.TimeRange) (workloadState, error)
	// objects returns the configuration of the objects that run the service.
	objects(ctx context.Context) (objectState, error)
}

type objectState struct {
	data      api.WorkloadObjects
	truncated bool
	source    api.SourceRef
}

type workloadState struct {
	data api.Workloads
	// truncated is true when an upstream list stopped before its end.
	truncated bool
	source    api.SourceRef
}

func (s *Service) workloadBackend(scope authz.WorkloadScope) (workloadBackend, error) {
	if k8s, ok := scope.Kubernetes(); ok {
		return kubernetesWorkloads{s: s, scope: k8s, client: s.connectors.Kubernetes[k8s.Source().Name]}, nil
	}
	if nodes, ok := scope.Nodes(); ok {
		return nodeWorkloads{s: s, scope: nodes, client: s.connectors.Kubernetes[nodes.Source().Name]}, nil
	}
	if tasks, ok := scope.ECS(); ok {
		return ecsWorkloads{redactor: s.redactor, scope: tasks, client: s.connectors.AWS[tasks.Source().Name]}, nil
	}
	return nil, unsupported("workloads", scope.Source())
}

// Workloads returns the current pods (or tasks) and rollouts of the service and the events of
// its objects in the range. Kubernetes keeps events for about an hour by default.
func (s *Service) Workloads(ctx context.Context, identity *authz.Identity, service string, w api.Window) (api.Response[api.Workloads], error) {
	scope, err := s.authz.WorkloadScope(identity, service, w.Environment)
	if err != nil {
		return api.Response[api.Workloads]{}, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultWorkloadsSince)
	if err != nil {
		return api.Response[api.Workloads]{}, err
	}
	backend, err := s.workloadBackend(scope)
	if err != nil {
		return api.Response[api.Workloads]{}, err
	}
	state, err := backend.workloads(ctx, r)
	if err != nil {
		return api.Response[api.Workloads]{}, err
	}
	data := state.data
	meta := metaFor(scope.Target, r)
	meta.Sources = []api.SourceRef{state.source}
	meta.Untrusted = workloadsUntrusted
	meta.Truncated = state.truncated || len(data.Rollouts) > maxRollouts || len(data.Events) > maxWorkloadEvents
	data.Rollouts = data.Rollouts[:min(len(data.Rollouts), maxRollouts)]
	data.Events = data.Events[:min(len(data.Events), maxWorkloadEvents)]
	return api.Response[api.Workloads]{Data: data, Meta: meta}, nil
}

// WorkloadSummary condenses Workloads for the overview.
func (s *Service) WorkloadSummary(ctx context.Context, identity *authz.Identity, service string, w api.Window) (*api.WorkloadSummary, error) {
	resp, err := s.Workloads(ctx, identity, service, w)
	if err != nil {
		return nil, err
	}
	return summarizeWorkloads(resp.Data, *resp.Meta.Range), nil
}

func summarizeWorkloads(w api.Workloads, r api.TimeRange) *api.WorkloadSummary {
	summary := &api.WorkloadSummary{Pods: len(w.Pods), Nodes: len(w.Nodes)}
	for _, node := range w.Nodes {
		if node.Ready {
			summary.NodesReady++
		}
		if len(node.Problems) > 0 {
			summary.Problems = append(summary.Problems, node.Name+": "+strings.Join(node.Problems, "; "))
		}
	}
	for _, pod := range w.Pods {
		summary.Restarts += pod.Restarts
		if pod.Ready {
			summary.Ready++
		}
		if problem := podProblem(pod, r); problem != "" {
			summary.Problems = append(summary.Problems, pod.Name+": "+problem)
		}
	}
	for _, e := range w.Events {
		if e.Type == "Warning" {
			summary.Warnings += e.Count
		}
	}
	for _, rollout := range w.Rollouts {
		if rollout.Replicas > 0 {
			summary.Rollout = &rollout
			break
		}
	}
	return summary
}

// podProblem names why a pod needs attention, or returns "" for a healthy or completed pod.
func podProblem(pod api.Pod, r api.TimeRange) string {
	if pod.Phase == "Succeeded" {
		return ""
	}
	var reasons []string
	for _, c := range pod.Containers {
		if c.State == "waiting" && c.Reason != "" && c.Reason != "ContainerCreating" {
			reasons = append(reasons, c.Name+" "+c.Reason)
		}
		if t := c.LastTermination; t != nil && t.Reason != "Completed" && !t.Finished.Before(r.From) {
			reasons = append(reasons, fmt.Sprintf("%s restarted after %s (exit %d)", c.Name, t.Reason, t.ExitCode))
		}
	}
	if len(reasons) == 0 && !pod.Ready {
		reasons = append(reasons, "not ready, "+strings.ToLower(pod.Phase))
		if pod.Reason != "" {
			reasons[0] += " (" + pod.Reason + ")"
		}
	}
	return strings.Join(reasons, "; ")
}
