package aws

import (
	"context"
	"slices"
	"strings"

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
			if sdkaws.ToString(task.Group) != "service:"+scope.ECSService() || arnName(sdkaws.ToString(task.ClusterArn)) != scope.Cluster() {
				return nil, false, c.outsideScope()
			}
		}
		tasks = append(tasks, out.Tasks...)
	}
	return tasks, truncated, nil
}

func ecsServiceInScope(scope authz.ECSScope, svc ecstypes.Service) bool {
	return sdkaws.ToString(svc.ServiceName) == scope.ECSService() && arnName(sdkaws.ToString(svc.ClusterArn)) == scope.Cluster()
}

// arnName returns the resource name of an ARN such as arn:aws:ecs:…:cluster/name.
func arnName(arn string) string {
	return arn[strings.LastIndex(arn, "/")+1:]
}

// outsideScope is the defense-in-depth error: every call names the scope's cluster, service or
// repository, so a resource outside them means AWS did not apply the parameter.
func (c *Client) outsideScope() error {
	return apierr.New(api.CodeInternal, "source %s returned data outside the scope", c.source.Name)
}
