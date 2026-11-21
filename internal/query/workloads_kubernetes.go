package query

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/kubernetes"
)

// kubernetesWorkloads reads the pods, ReplicaSets and events of one namespace and label set.
type kubernetesWorkloads struct {
	s      *Service
	scope  authz.KubernetesScope
	client *kubernetes.Client
}

func (b kubernetesWorkloads) workloads(ctx context.Context, r api.TimeRange) (workloadState, error) {
	query := workloadQuery(b.scope)
	recordQuery(ctx, b.scope.Target, query)

	var (
		wg                                      sync.WaitGroup
		pods                                    []kubernetes.Pod
		sets                                    []kubernetes.ReplicaSet
		events                                  []kubernetes.Event
		usage                                   []kubernetes.PodMetrics
		podsCut, setsCut, eventsCut             bool
		podsErr, setsErr, eventsErr, metricsErr error
	)
	wg.Go(func() { pods, podsCut, podsErr = b.client.Pods(ctx, b.scope) })
	wg.Go(func() { sets, setsCut, setsErr = b.client.ReplicaSets(ctx, b.scope) })
	wg.Go(func() { events, eventsCut, eventsErr = b.client.Events(ctx, b.scope) })
	wg.Go(func() { usage, _, metricsErr = b.client.PodMetrics(ctx, b.scope) })
	wg.Wait()
	for _, err := range []error{podsErr, setsErr, eventsErr, metricsErr} {
		if err != nil {
			return workloadState{}, err
		}
	}
	shaped := b.s.shapePods(pods)
	addPodUsage(shaped, usage)
	return workloadState{
		data: api.Workloads{
			Pods:     shaped,
			Rollouts: shapeRollouts(sets),
			Events:   b.s.workloadEvents(events, pods, sets, r),
		},
		truncated: podsCut || setsCut || eventsCut,
		source:    api.SourceRef{Kind: "kubernetes", Query: query},
	}, nil
}

func workloadQuery(scope authz.KubernetesScope) string {
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
	container := api.Container{Name: c.Name, Image: c.Image, Digest: imageDigest(c.ImageID), Ready: c.Ready, Restarts: c.RestartCount}
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

// addPodUsage sets the usage of each container from the metrics of its pod. Metrics are joined
// by pod name, so those of pods outside the scope are never used.
func addPodUsage(pods []api.Pod, metrics []kubernetes.PodMetrics) {
	byPod := map[string]kubernetes.PodMetrics{}
	for _, m := range metrics {
		byPod[m.Metadata.Name] = m
	}
	for i := range pods {
		m, ok := byPod[pods[i].Name]
		if !ok {
			continue
		}
		for j := range pods[i].Containers {
			for _, c := range m.Containers {
				if c.Name == pods[i].Containers[j].Name {
					pods[i].Containers[j].Usage = usageOf(c.Usage)
				}
			}
		}
	}
}

// usageOf converts metrics API quantities; an unparsable one leaves the usage out.
func usageOf(quantities map[string]string) *api.Usage {
	cpu, cpuOK := kubernetes.ParseCPU(quantities["cpu"])
	memory, memoryOK := kubernetes.ParseMemory(quantities["memory"])
	if !cpuOK || !memoryOK {
		return nil
	}
	return &api.Usage{CPUMillicores: cpu, MemoryBytes: memory}
}

// imageDigest returns the digest of an image reference that has one (repository@sha256:…,
// optionally prefixed by docker-pullable://). A bare sha256:… image ID is the ID of the image
// configuration, not a manifest digest a registry knows, so it yields "".
func imageDigest(ref string) string {
	_, digest, ok := strings.Cut(ref, "@")
	if !ok || !strings.HasPrefix(digest, "sha256:") {
		return ""
	}
	return digest
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
