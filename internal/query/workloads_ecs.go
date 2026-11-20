package query

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/shape"
)

// ecsWorkloads reads the running tasks of one ECS service as pods, its deployments as rollouts
// and its service events as events.
type ecsWorkloads struct {
	redactor *shape.Redactor
	scope    authz.ECSScope
	client   *aws.Client
}

func (b ecsWorkloads) workloads(ctx context.Context, r api.TimeRange) (workloadState, error) {
	query := fmt.Sprintf("cluster=%s service=%s", b.scope.Cluster(), b.scope.ECSService())
	recordQuery(ctx, b.scope.Target, query)

	var (
		wg               sync.WaitGroup
		svc              ecstypes.Service
		tasks            []ecstypes.Task
		truncated        bool
		svcErr, tasksErr error
	)
	wg.Go(func() { svc, svcErr = b.client.ECSService(ctx, b.scope) })
	wg.Go(func() { tasks, truncated, tasksErr = b.client.ECSTasks(ctx, b.scope) })
	wg.Wait()
	for _, err := range []error{svcErr, tasksErr} {
		if err != nil {
			return workloadState{}, err
		}
	}
	return workloadState{
		data: api.Workloads{
			Pods:     b.shapeTasks(tasks),
			Rollouts: ecsRollouts(svc),
			Events:   b.serviceEvents(svc, r),
		},
		truncated: truncated,
		source:    ecsSourceRef(b.scope, query),
	}, nil
}

func (b ecsWorkloads) shapeTasks(tasks []ecstypes.Task) []api.Pod {
	pods := make([]api.Pod, 0, len(tasks))
	for _, task := range tasks {
		status := sdkaws.ToString(task.LastStatus)
		pod := api.Pod{
			Name:    arnName(sdkaws.ToString(task.TaskArn)),
			Phase:   status,
			Ready:   status == "RUNNING" && task.HealthStatus != ecstypes.HealthStatusUnhealthy,
			Started: task.StartedAt,
			Reason:  b.redactor.Redact(sdkaws.ToString(task.StoppedReason)),
		}
		if deployment := sdkaws.ToString(task.StartedBy); deployment != "" {
			pod.Owner = "Deployment/" + deployment
		}
		for _, c := range task.Containers {
			pod.Containers = append(pod.Containers, b.shapeTaskContainer(c))
		}
		pods = append(pods, pod)
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
	return pods
}

func (b ecsWorkloads) shapeTaskContainer(c ecstypes.Container) api.Container {
	status := sdkaws.ToString(c.LastStatus)
	container := api.Container{
		Name:   sdkaws.ToString(c.Name),
		Image:  sdkaws.ToString(c.Image),
		Digest: sdkaws.ToString(c.ImageDigest),
		Ready:  status == "RUNNING" && c.HealthStatus != ecstypes.HealthStatusUnhealthy,
		Reason: b.redactor.Redact(sdkaws.ToString(c.Reason)),
	}
	switch status {
	case "RUNNING":
		container.State = "running"
	case "STOPPED":
		container.State = "terminated"
		if container.Reason == "" && c.ExitCode != nil {
			container.Reason = fmt.Sprintf("exit code %d", *c.ExitCode)
		}
	default:
		container.State = "waiting"
		if container.Reason == "" {
			container.Reason = status
		}
	}
	return container
}

// ecsRollouts returns the service's deployments newest first. The images of a deployment are
// in its task definition, which Sonda does not read; the revision names it.
func ecsRollouts(svc ecstypes.Service) []api.Rollout {
	rollouts := make([]api.Rollout, 0, len(svc.Deployments))
	for _, d := range svc.Deployments {
		rollout := api.Rollout{
			Name:          sdkaws.ToString(d.Id),
			Owner:         "Service/" + sdkaws.ToString(svc.ServiceName),
			Revision:      arnName(sdkaws.ToString(d.TaskDefinition)),
			Images:        []string{},
			Replicas:      int(d.DesiredCount),
			ReadyReplicas: int(d.RunningCount),
			State:         string(d.RolloutState),
		}
		if d.CreatedAt != nil {
			rollout.Created = *d.CreatedAt
		}
		rollouts = append(rollouts, rollout)
	}
	sort.SliceStable(rollouts, func(i, j int) bool { return rollouts[i].Created.After(rollouts[j].Created) })
	return rollouts
}

// serviceEvents returns the service events in the range, newest first. ECS keeps the last 100
// and gives them no severity, so every event is Normal.
func (b ecsWorkloads) serviceEvents(svc ecstypes.Service, r api.TimeRange) []api.WorkloadEvent {
	var events []api.WorkloadEvent
	for _, e := range svc.Events {
		if e.CreatedAt == nil || e.CreatedAt.Before(r.From) || e.CreatedAt.After(r.To) {
			continue
		}
		events = append(events, api.WorkloadEvent{
			Type:      "Normal",
			Object:    "Service/" + sdkaws.ToString(svc.ServiceName),
			Message:   b.redactor.Redact(sdkaws.ToString(e.Message)),
			Count:     1,
			FirstSeen: *e.CreatedAt,
			LastSeen:  *e.CreatedAt,
		})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].LastSeen.After(events[j].LastSeen) })
	return events
}

// ecsSourceRef links to the service's tasks in the ECS console.
func ecsSourceRef(scope authz.ECSScope, query string) api.SourceRef {
	region := scope.Source().AWS.Region
	return api.SourceRef{
		Kind:  "ecs",
		Query: query,
		URL: fmt.Sprintf("https://%s.console.aws.amazon.com/ecs/v2/clusters/%s/services/%s/tasks?region=%s",
			region, url.PathEscape(scope.Cluster()), url.PathEscape(scope.ECSService()), url.QueryEscape(region)),
	}
}

// arnName returns the resource name of an ARN such as arn:aws:ecs:…:task/cluster/id.
func arnName(arn string) string {
	return arn[strings.LastIndex(arn, "/")+1:]
}
