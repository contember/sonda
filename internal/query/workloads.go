package query

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/kubernetes"
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
	"data.events[].reason", "data.events[].message",
}

// Workloads returns the current pods and rollouts of the service and the events of its
// objects in the range. Kubernetes keeps events for about an hour by default.
func (s *Service) Workloads(ctx context.Context, identity *authz.Identity, service string, w api.Window) (api.Response[api.Workloads], error) {
	scope, err := s.authz.WorkloadScope(identity, service, w.Environment)
	if err != nil {
		return api.Response[api.Workloads]{}, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultWorkloadsSince)
	if err != nil {
		return api.Response[api.Workloads]{}, err
	}
	client := s.connectors.Kubernetes[scope.Source().Name]
	query := workloadQuery(scope)
	recordQuery(ctx, scope.Target, query)

	var (
		wg                          sync.WaitGroup
		pods                        []kubernetes.Pod
		sets                        []kubernetes.ReplicaSet
		events                      []kubernetes.Event
		podsCut, setsCut, eventsCut bool
		podsErr, setsErr, eventsErr error
	)
	wg.Go(func() { pods, podsCut, podsErr = client.Pods(ctx, scope) })
	wg.Go(func() { sets, setsCut, setsErr = client.ReplicaSets(ctx, scope) })
	wg.Go(func() { events, eventsCut, eventsErr = client.Events(ctx, scope) })
	wg.Wait()
	for _, err := range []error{podsErr, setsErr, eventsErr} {
		if err != nil {
			return api.Response[api.Workloads]{}, err
		}
	}

	rollouts := shapeRollouts(sets)
	shownEvents := s.workloadEvents(events, pods, sets, r)
	meta := metaFor(scope.Target, r)
	meta.Sources = []api.SourceRef{{Kind: "kubernetes", Query: query}}
	meta.Untrusted = workloadsUntrusted
	meta.Truncated = podsCut || setsCut || eventsCut || len(rollouts) > maxRollouts || len(shownEvents) > maxWorkloadEvents
	return api.Response[api.Workloads]{
		Data: api.Workloads{
			Pods:     s.shapePods(pods),
			Rollouts: rollouts[:min(len(rollouts), maxRollouts)],
			Events:   shownEvents[:min(len(shownEvents), maxWorkloadEvents)],
		},
		Meta: meta,
	}, nil
}

// WorkloadSummary condenses Workloads for the overview.
func (s *Service) WorkloadSummary(ctx context.Context, identity *authz.Identity, service string, w api.Window) (*api.WorkloadSummary, error) {
	resp, err := s.Workloads(ctx, identity, service, w)
	if err != nil {
		return nil, err
	}
	return summarizeWorkloads(resp.Data, *resp.Meta.Range), nil
}

func workloadQuery(scope authz.WorkloadScope) string {
	labels := scope.Labels()
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, key := range keys {
		parts[i] = key + "=" + labels[key]
	}
	return fmt.Sprintf("namespace=%s labels=%s", scope.Namespace(), strings.Join(parts, ","))
}

func (s *Service) shapePods(pods []kubernetes.Pod) []api.Pod {
	result := make([]api.Pod, 0, len(pods))
	for _, p := range pods {
		pod := api.Pod{
			Name:    p.Metadata.Name,
			Phase:   p.Status.Phase,
			Ready:   conditionTrue(p.Status.Conditions, "Ready"),
			Node:    p.Spec.NodeName,
			Started: p.Status.StartTime,
			Reason:  p.Status.Reason,
		}
		if owner, ok := p.Metadata.Controller(); ok {
			pod.Owner = owner.Kind + "/" + owner.Name
		}
		for _, c := range p.Status.ContainerStatuses {
			pod.Restarts += c.RestartCount
			pod.Containers = append(pod.Containers, s.shapeContainer(c))
		}
		result = append(result, pod)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (s *Service) shapeContainer(c kubernetes.ContainerStatus) api.Container {
	container := api.Container{Name: c.Name, Image: c.Image, Ready: c.Ready, Restarts: c.RestartCount}
	switch {
	case c.State.Running != nil:
		container.State = "running"
	case c.State.Waiting != nil:
		container.State, container.Reason, container.Message = "waiting", c.State.Waiting.Reason, s.redactor.Redact(c.State.Waiting.Message)
	case c.State.Terminated != nil:
		container.State, container.Reason, container.Message = "terminated", c.State.Terminated.Reason, s.redactor.Redact(c.State.Terminated.Message)
	}
	if t := c.LastState.Terminated; t != nil {
		container.LastTermination = &api.Termination{Reason: t.Reason, ExitCode: t.ExitCode, Finished: t.FinishedAt, Message: s.redactor.Redact(t.Message)}
	}
	return container
}

func conditionTrue(conditions []kubernetes.Condition, kind string) bool {
	for _, c := range conditions {
		if c.Type == kind {
			return c.Status == "True"
		}
	}
	return false
}

// shapeRollouts returns all ReplicaSets, newest first; the caller cuts the list.
func shapeRollouts(sets []kubernetes.ReplicaSet) []api.Rollout {
	rollouts := make([]api.Rollout, 0, len(sets))
	for _, set := range sets {
		rollout := api.Rollout{
			Name:          set.Metadata.Name,
			Revision:      set.Metadata.Annotations["deployment.kubernetes.io/revision"],
			Created:       set.Metadata.CreationTimestamp,
			Replicas:      set.Status.Replicas,
			ReadyReplicas: set.Status.ReadyReplicas,
			Images:        []string{},
		}
		if owner, ok := set.Metadata.Controller(); ok {
			rollout.Owner = owner.Kind + "/" + owner.Name
		}
		for _, c := range set.Spec.Template.Spec.Containers {
			rollout.Images = append(rollout.Images, c.Image)
		}
		rollouts = append(rollouts, rollout)
	}
	sort.SliceStable(rollouts, func(i, j int) bool { return rollouts[i].Created.After(rollouts[j].Created) })
	return rollouts
}

// generatedPodSuffix is the random suffix Kubernetes appends to a ReplicaSet name for its pods.
var generatedPodSuffix = regexp.MustCompile(`^-[a-z0-9]{5}$`)

// workloadEvents keeps the events of the scope's pods, ReplicaSets and their Deployments that
// overlap the range, newest first. Pods of a scoped ReplicaSet count even when they no longer
// exist, so the events of crashed and replaced pods stay visible.
func (s *Service) workloadEvents(events []kubernetes.Event, pods []kubernetes.Pod, sets []kubernetes.ReplicaSet, r api.TimeRange) []api.WorkloadEvent {
	objects := map[string]bool{}
	for _, pod := range pods {
		objects["Pod/"+pod.Metadata.Name] = true
	}
	for _, set := range sets {
		objects["ReplicaSet/"+set.Metadata.Name] = true
		if owner, ok := set.Metadata.Controller(); ok && owner.Kind == "Deployment" {
			objects["Deployment/"+owner.Name] = true
		}
	}
	podOfSet := func(name string) bool {
		for _, set := range sets {
			if suffix, ok := strings.CutPrefix(name, set.Metadata.Name); ok && generatedPodSuffix.MatchString(suffix) {
				return true
			}
		}
		return false
	}

	var result []api.WorkloadEvent
	for _, e := range events {
		object := e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name
		if !objects[object] && !(e.InvolvedObject.Kind == "Pod" && podOfSet(e.InvolvedObject.Name)) {
			continue
		}
		first, last := e.FirstSeen(), e.LastSeen()
		if last.Before(r.From) || first.After(r.To) {
			continue
		}
		result = append(result, api.WorkloadEvent{
			Type:      e.Type,
			Reason:    e.Reason,
			Object:    object,
			Message:   s.redactor.Redact(e.Message),
			Count:     e.Occurrences(),
			FirstSeen: first,
			LastSeen:  last,
		})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result
}

func summarizeWorkloads(w api.Workloads, r api.TimeRange) *api.WorkloadSummary {
	summary := &api.WorkloadSummary{Pods: len(w.Pods)}
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
