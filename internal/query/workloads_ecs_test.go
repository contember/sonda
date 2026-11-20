package query

import (
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestECSTasksAsPods(t *testing.T) {
	const digest = "sha256:0994af66bd88ce73c84ee33852b7a81a8ddef37e5c55187df223fb06d3b6deff"
	started := workloadRange.From
	tasks := []ecstypes.Task{{
		TaskArn:      sdkaws.String("arn:aws:ecs:eu-central-1:123456789012:task/shop-prod/b2"),
		LastStatus:   sdkaws.String("RUNNING"),
		HealthStatus: ecstypes.HealthStatusUnknown,
		StartedAt:    &started,
		StartedBy:    sdkaws.String("ecs-svc/123"),
		Containers: []ecstypes.Container{
			{Name: sdkaws.String("app"), Image: sdkaws.String("registry.example/shop:abc"), ImageDigest: sdkaws.String(digest), LastStatus: sdkaws.String("RUNNING"), HealthStatus: ecstypes.HealthStatusUnknown},
			{Name: sdkaws.String("migrate"), Image: sdkaws.String("registry.example/shop:abc"), LastStatus: sdkaws.String("STOPPED"), ExitCode: sdkaws.Int32(1)},
		},
	}, {
		TaskArn:      sdkaws.String("arn:aws:ecs:eu-central-1:123456789012:task/shop-prod/a1"),
		LastStatus:   sdkaws.String("RUNNING"),
		HealthStatus: ecstypes.HealthStatusUnhealthy,
		Containers:   []ecstypes.Container{{Name: sdkaws.String("app"), LastStatus: sdkaws.String("PENDING")}},
	}}
	pods := ecsWorkloads{redactor: testService(t).redactor}.shapeTasks(tasks)
	if len(pods) != 2 || pods[0].Name != "a1" || pods[1].Name != "b2" {
		t.Fatalf("pods = %+v", pods)
	}
	if pods[0].Ready || pods[0].Containers[0].State != "waiting" || pods[0].Containers[0].Reason != "PENDING" {
		t.Errorf("unhealthy pending task = %+v", pods[0])
	}
	b2 := pods[1]
	if !b2.Ready || b2.Phase != "RUNNING" || b2.Owner != "Deployment/ecs-svc/123" || b2.Started == nil {
		t.Errorf("running task = %+v", b2)
	}
	if c := b2.Containers[0]; c.Digest != digest || c.State != "running" || !c.Ready {
		t.Errorf("app container = %+v", c)
	}
	if c := b2.Containers[1]; c.State != "terminated" || c.Reason != "exit code 1" || c.Digest != "" {
		t.Errorf("stopped container = %+v", c)
	}
}

func TestECSRolloutsAndEvents(t *testing.T) {
	older, newer := workloadRange.From.Add(-time.Hour), workloadRange.From.Add(10*time.Minute)
	svc := ecstypes.Service{
		ServiceName: sdkaws.String("web"),
		Deployments: []ecstypes.Deployment{
			{Id: sdkaws.String("ecs-svc/1"), TaskDefinition: sdkaws.String("arn:aws:ecs:eu-central-1:123456789012:task-definition/shop-web:7"), CreatedAt: &older, DesiredCount: 2, RunningCount: 1, RolloutState: ecstypes.DeploymentRolloutStateCompleted},
			{Id: sdkaws.String("ecs-svc/2"), TaskDefinition: sdkaws.String("arn:aws:ecs:eu-central-1:123456789012:task-definition/shop-web:8"), CreatedAt: &newer, DesiredCount: 2, RunningCount: 1, RolloutState: ecstypes.DeploymentRolloutStateInProgress},
		},
		Events: []ecstypes.ServiceEvent{
			{CreatedAt: &newer, Message: sdkaws.String("(service web) token=abc has started 1 tasks")},
			{CreatedAt: &older, Message: sdkaws.String("(service web) has reached a steady state.")},
		},
	}
	rollouts := ecsRollouts(svc)
	if len(rollouts) != 2 || rollouts[0].Name != "ecs-svc/2" || rollouts[0].Revision != "shop-web:8" || rollouts[0].State != "IN_PROGRESS" || rollouts[0].Owner != "Service/web" {
		t.Errorf("rollouts = %+v", rollouts)
	}
	if rollouts[0].Images == nil || rollouts[0].Replicas != 2 || rollouts[0].ReadyReplicas != 1 {
		t.Errorf("newest rollout = %+v", rollouts[0])
	}
	events := ecsWorkloads{redactor: testService(t, `token=\S+`).redactor}.serviceEvents(svc, workloadRange)
	if len(events) != 1 || events[0].Object != "Service/web" || events[0].Message != "(service web) [REDACTED] has started 1 tasks" || events[0].Count != 1 {
		t.Errorf("events = %+v", events)
	}
}
