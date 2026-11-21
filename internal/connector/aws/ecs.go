package aws

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// ecsAPI is the part of the ECS client the connector uses.
type ecsAPI interface {
	DescribeServices(ctx context.Context, in *ecs.DescribeServicesInput, opts ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTasks(ctx context.Context, in *ecs.ListTasksInput, opts ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(ctx context.Context, in *ecs.DescribeTasksInput, opts ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	DescribeTaskDefinition(ctx context.Context, in *ecs.DescribeTaskDefinitionInput, opts ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

const (
	// maxTasks stops the task list of one service; a service runs far fewer.
	maxTasks = 500
	// ecsPage is the most tasks ListTasks returns and DescribeTasks accepts in one call.
	ecsPage = 100
)

// ECSService describes the scope's service with its deployments and its last 100 events.
func (c *Client) ECSService(ctx context.Context, scope authz.ECSScope) (ecstypes.Service, error) {
	out, err := c.ecs.DescribeServices(ctx, &ecs.DescribeServicesInput{
		Cluster:  sdkaws.String(scope.Cluster()),
		Services: []string{scope.ECSService()},
	})
	if err != nil {
		return ecstypes.Service{}, c.apiError("DescribeServices", err)
	}
	for _, svc := range out.Services {
		if !ecsServiceInScope(scope, svc) {
			return ecstypes.Service{}, c.outsideScope()
		}
	}
	if len(out.Services) == 0 {
		return ecstypes.Service{}, apierr.Upstream("source %s: ECS service %s not found in cluster %s", c.source.Name, scope.ECSService(), scope.Cluster())
	}
	return out.Services[0], nil
}

// ECSTasks lists the running tasks of the scope's service, at most maxTasks. Every task is
// checked against the scope again.
func (c *Client) ECSTasks(ctx context.Context, scope authz.ECSScope) ([]ecstypes.Task, bool, error) {
	var (
		arns      []string
		next      *string
		truncated bool
	)
	for {
		out, err := c.ecs.ListTasks(ctx, &ecs.ListTasksInput{
			Cluster:       sdkaws.String(scope.Cluster()),
			ServiceName:   sdkaws.String(scope.ECSService()),
			DesiredStatus: ecstypes.DesiredStatusRunning,
			MaxResults:    sdkaws.Int32(ecsPage),
			NextToken:     next,
		})
		if err != nil {
			return nil, false, c.apiError("ListTasks", err)
		}
		arns = append(arns, out.TaskArns...)
		if len(arns) >= maxTasks {
			truncated = len(arns) > maxTasks || out.NextToken != nil
			arns = arns[:maxTasks]
			break
		}
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	var tasks []ecstypes.Task
	for chunk := range slices.Chunk(arns, ecsPage) {
		out, err := c.ecs.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: sdkaws.String(scope.Cluster()), Tasks: chunk})
		if err != nil {
			return nil, false, c.apiError("DescribeTasks", err)
		}
		for _, task := range out.Tasks {
			if sdkaws.ToString(task.Group) != "service:"+scope.ECSService() || ARNName(sdkaws.ToString(task.ClusterArn)) != scope.Cluster() {
				return nil, false, c.outsideScope()
			}
		}
		tasks = append(tasks, out.Tasks...)
	}
	return tasks, truncated, nil
}

func ecsServiceInScope(scope authz.ECSScope, svc ecstypes.Service) bool {
	return sdkaws.ToString(svc.ServiceName) == scope.ECSService() && ARNName(sdkaws.ToString(svc.ClusterArn)) == scope.Cluster()
}

// ARNName returns the last path segment of an ARN, e.g. the name of arn:aws:ecs:…:cluster/name
// or the ID of arn:aws:ecs:…:task/cluster/id.
func ARNName(arn string) string {
	return arn[strings.LastIndex(arn, "/")+1:]
}

// outsideScope is the defense-in-depth error: every call names the scope's cluster, service or
// repository, so a resource outside them means AWS did not apply the parameter.
func (c *Client) outsideScope() error {
	return apierr.New(api.CodeInternal, "source %s returned data outside the scope", c.source.Name)
}

// TaskDefinition is the part of an ECS task definition Sonda returns. Values of environment
// variables, secret references, commands, Docker labels, log driver options other than the log
// group, and repository credentials are dropped here: a literal value can hold a secret, and
// IAM cannot exclude them from DescribeTaskDefinition.
type TaskDefinition struct {
	ARN             string
	Family          string
	Revision        int
	Status          string
	Registered      *time.Time
	CPU             string
	Memory          string
	NetworkMode     string
	Compatibilities []string
	TaskRole        string
	ExecutionRole   string
	Containers      []TaskContainer
}

type TaskContainer struct {
	Name              string
	Image             string
	CPU               int
	Memory            int
	MemoryReservation int
	Essential         bool
	// Env and SecretEnv are variable names: plain variables and those taken from a secret store.
	Env       []string
	SecretEnv []string
	Ports     []string
	// LogGroup is the awslogs log group; other log drivers yield none.
	LogGroup    string
	HealthCheck bool
}

// ECSTaskDefinition describes a task definition a deployment of the scope's service runs. The
// caller takes arn from the described service, so it is in the scope; the answer must be it.
func (c *Client) ECSTaskDefinition(ctx context.Context, scope authz.ECSScope, arn string) (TaskDefinition, error) {
	out, err := c.ecs.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: sdkaws.String(arn)})
	if err != nil {
		return TaskDefinition{}, c.apiError("DescribeTaskDefinition", err)
	}
	td := out.TaskDefinition
	if td == nil || sdkaws.ToString(td.TaskDefinitionArn) != arn {
		return TaskDefinition{}, c.outsideScope()
	}
	return taskDefinition(*td), nil
}

func taskDefinition(td ecstypes.TaskDefinition) TaskDefinition {
	result := TaskDefinition{
		ARN:           sdkaws.ToString(td.TaskDefinitionArn),
		Family:        sdkaws.ToString(td.Family),
		Revision:      int(td.Revision),
		Status:        string(td.Status),
		Registered:    td.RegisteredAt,
		CPU:           sdkaws.ToString(td.Cpu),
		Memory:        sdkaws.ToString(td.Memory),
		NetworkMode:   string(td.NetworkMode),
		TaskRole:      ARNName(sdkaws.ToString(td.TaskRoleArn)),
		ExecutionRole: ARNName(sdkaws.ToString(td.ExecutionRoleArn)),
	}
	for _, c := range td.RequiresCompatibilities {
		result.Compatibilities = append(result.Compatibilities, string(c))
	}
	for _, c := range td.ContainerDefinitions {
		container := TaskContainer{
			Name:              sdkaws.ToString(c.Name),
			Image:             sdkaws.ToString(c.Image),
			CPU:               int(c.Cpu),
			Memory:            int(sdkaws.ToInt32(c.Memory)),
			MemoryReservation: int(sdkaws.ToInt32(c.MemoryReservation)),
			Essential:         sdkaws.ToBool(c.Essential),
			HealthCheck:       c.HealthCheck != nil,
		}
		for _, e := range c.Environment {
			container.Env = append(container.Env, sdkaws.ToString(e.Name))
		}
		for _, s := range c.Secrets {
			container.SecretEnv = append(container.SecretEnv, sdkaws.ToString(s.Name))
		}
		for _, p := range c.PortMappings {
			port := fmt.Sprintf("%d/%s", sdkaws.ToInt32(p.ContainerPort), strings.ToUpper(string(p.Protocol)))
			if name := sdkaws.ToString(p.Name); name != "" {
				port = name + " " + port
			}
			container.Ports = append(container.Ports, port)
		}
		if lc := c.LogConfiguration; lc != nil && lc.LogDriver == ecstypes.LogDriverAwslogs {
			container.LogGroup = lc.Options["awslogs-group"]
		}
		slices.Sort(container.Env)
		slices.Sort(container.SecretEnv)
		result.Containers = append(result.Containers, container)
	}
	return result
}
