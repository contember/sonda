package query

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
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
			Name:    aws.ARNName(sdkaws.ToString(task.TaskArn)),
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
		// PENDING, PROVISIONING or ACTIVATING are the normal start of every task, like
		// Kubernetes' ContainerCreating, so they carry no reason the overview would flag.
		container.State = "waiting"
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
			Revision:      aws.ARNName(sdkaws.ToString(d.TaskDefinition)),
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

// objects describes the ECS service and the task definitions of its deployments, with variable
// names only.
func (b ecsWorkloads) objects(ctx context.Context) (objectState, error) {
	query := fmt.Sprintf("objects cluster=%s service=%s", b.scope.Cluster(), b.scope.ECSService())
	recordQuery(ctx, b.scope.Target, query)
	svc, err := b.client.ECSService(ctx, b.scope)
	if err != nil {
		return objectState{}, err
	}
	var arns []string
	for _, d := range svc.Deployments {
		if arn := sdkaws.ToString(d.TaskDefinition); arn != "" && !slices.Contains(arns, arn) {
			arns = append(arns, arn)
		}
	}
	defs := make([]api.TaskDefinition, len(arns))
	errs := make([]error, len(arns))
	var wg sync.WaitGroup
	for i, arn := range arns {
		wg.Go(func() {
			td, err := b.client.ECSTaskDefinition(ctx, b.scope, arn)
			defs[i], errs[i] = apiTaskDefinition(td), err
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return objectState{}, err
		}
	}
	sort.SliceStable(defs, func(i, j int) bool { return defs[i].Revision > defs[j].Revision })
	return objectState{
		data:   api.WorkloadObjects{Controllers: []api.Controller{ecsController(svc)}, TaskDefinitions: defs},
		source: ecsSourceRef(b.scope, query),
	}, nil
}

func ecsController(svc ecstypes.Service) api.Controller {
	desired := int(svc.DesiredCount)
	c := api.Controller{
		Kind:          "Service",
		Name:          sdkaws.ToString(svc.ServiceName),
		Replicas:      &desired,
		ReadyReplicas: int(svc.RunningCount),
		Details: map[string]string{
			"status":         sdkaws.ToString(svc.Status),
			"taskDefinition": aws.ARNName(sdkaws.ToString(svc.TaskDefinition)),
			"pending":        strconv.Itoa(int(svc.PendingCount)),
			"scheduling":     string(svc.SchedulingStrategy),
			"executeCommand": strconv.FormatBool(svc.EnableExecuteCommand),
		},
	}
	if svc.CreatedAt != nil {
		c.Created = *svc.CreatedAt
	}
	if svc.LaunchType != "" {
		c.Details["launchType"] = string(svc.LaunchType)
	}
	var providers []string
	for _, p := range svc.CapacityProviderStrategy {
		providers = append(providers, fmt.Sprintf("%s weight=%d base=%d", sdkaws.ToString(p.CapacityProvider), p.Weight, p.Base))
	}
	if len(providers) > 0 {
		c.Details["capacityProviders"] = strings.Join(providers, "; ")
	}
	if v := sdkaws.ToString(svc.PlatformVersion); v != "" {
		c.Details["platformVersion"] = v
	}
	if dc := svc.DeploymentConfiguration; dc != nil {
		c.Strategy = fmt.Sprintf("minHealthy=%d%% max=%d%%", sdkaws.ToInt32(dc.MinimumHealthyPercent), sdkaws.ToInt32(dc.MaximumPercent))
		if cb := dc.DeploymentCircuitBreaker; cb != nil && cb.Enable {
			c.Strategy += " circuitBreaker"
			if cb.Rollback {
				c.Strategy += "+rollback"
			}
		}
	}
	var balancers []string
	for _, lb := range svc.LoadBalancers {
		balancers = append(balancers, fmt.Sprintf("%s → %s:%d", targetGroupName(sdkaws.ToString(lb.TargetGroupArn)), sdkaws.ToString(lb.ContainerName), sdkaws.ToInt32(lb.ContainerPort)))
	}
	if len(balancers) > 0 {
		c.Details["loadBalancers"] = strings.Join(balancers, "; ")
	}
	if grace := sdkaws.ToInt32(svc.HealthCheckGracePeriodSeconds); grace > 0 {
		c.Details["healthCheckGracePeriod"] = fmt.Sprintf("%ds", grace)
	}
	if nc := svc.NetworkConfiguration; nc != nil && nc.AwsvpcConfiguration != nil {
		vpc := nc.AwsvpcConfiguration
		c.Details["network"] = fmt.Sprintf("awsvpc subnets=%d securityGroups=%d publicIp=%s", len(vpc.Subnets), len(vpc.SecurityGroups), vpc.AssignPublicIp)
	}
	return c
}

// targetGroupName returns the name in arn:aws:elasticloadbalancing:…:targetgroup/<name>/<id>.
func targetGroupName(arn string) string {
	_, rest, ok := strings.Cut(arn, ":targetgroup/")
	if !ok {
		return arn
	}
	name, _, _ := strings.Cut(rest, "/")
	return "targetgroup/" + name
}

func apiTaskDefinition(td aws.TaskDefinition) api.TaskDefinition {
	result := api.TaskDefinition{
		Family: td.Family, Revision: td.Revision, Status: td.Status, Registered: td.Registered,
		CPU: td.CPU, Memory: td.Memory, NetworkMode: td.NetworkMode, Compatibility: td.Compatibilities,
		TaskRole: td.TaskRole, ExecutionRole: td.ExecutionRole, Containers: []api.ContainerSpec{},
	}
	for _, c := range td.Containers {
		spec := api.ContainerSpec{Name: c.Name, Image: c.Image, Env: c.Env, SecretEnv: c.SecretEnv, Ports: c.Ports, LogGroup: c.LogGroup}
		requests := map[string]string{}
		limits := map[string]string{}
		if c.CPU > 0 {
			requests["cpu"] = strconv.Itoa(c.CPU) + " units"
		}
		if c.MemoryReservation > 0 {
			requests["memory"] = strconv.Itoa(c.MemoryReservation) + "MiB"
		}
		if c.Memory > 0 {
			limits["memory"] = strconv.Itoa(c.Memory) + "MiB"
		}
		if len(requests) > 0 {
			spec.Requests = requests
		}
		if len(limits) > 0 {
			spec.Limits = limits
		}
		if c.HealthCheck {
			spec.Probes = map[string]string{"health": "container health check"}
		}
		result.Containers = append(result.Containers, spec)
	}
	return result
}
