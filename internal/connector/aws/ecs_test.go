package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

const clusterARN = "arn:aws:ecs:eu-central-1:123456789012:cluster/shop-prod"

func ecsScope(t *testing.T) (*config.Config, authz.ECSScope) {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  aws: { type: aws, region: eu-central-1 }
projects:
  shop:
    services:
      web:
        environments:
          production:
            workloads: { source: aws, cluster: shop-prod, service: web }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "shop", Environment: "production", Capability: api.CapabilityWorkloads},
	}}
	scope, err := authz.New(cfg, nil).WorkloadScope(identity, "web", "production")
	if err != nil {
		t.Fatal(err)
	}
	tasks, ok := scope.ECS()
	if !ok {
		t.Fatal("not an ECS scope")
	}
	return cfg, tasks
}

// fakeECS serves count running tasks of service:web, in pages of the requested size.
type fakeECS struct {
	count        int
	group        string // the group of every task; service:web by default
	cluster      string // the cluster ARN of every task; clusterARN by default
	services     []ecstypes.Service
	listInputs   []*ecs.ListTasksInput
	describeArns [][]string
	// taskDefinition answers DescribeTaskDefinition; nil fails the call.
	taskDefinition *ecstypes.TaskDefinition
}

func (f *fakeECS) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	if f.taskDefinition == nil {
		return nil, fmt.Errorf("unexpected input %+v", in)
	}
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: f.taskDefinition}, nil
}

func (f *fakeECS) DescribeServices(_ context.Context, in *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	if sdkaws.ToString(in.Cluster) != "shop-prod" || len(in.Services) != 1 || in.Services[0] != "web" {
		return nil, fmt.Errorf("unexpected input %+v", in)
	}
	return &ecs.DescribeServicesOutput{Services: f.services}, nil
}

func (f *fakeECS) ListTasks(_ context.Context, in *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	f.listInputs = append(f.listInputs, in)
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := min(start+int(sdkaws.ToInt32(in.MaxResults)), f.count)
	out := &ecs.ListTasksOutput{}
	for i := start; i < end; i++ {
		out.TaskArns = append(out.TaskArns, fmt.Sprintf("arn:aws:ecs:eu-central-1:123456789012:task/shop-prod/%04d", i))
	}
	if end < f.count {
		out.NextToken = sdkaws.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *fakeECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	f.describeArns = append(f.describeArns, in.Tasks)
	group := f.group
	if group == "" {
		group = "service:web"
	}
	cluster := f.cluster
	if cluster == "" {
		cluster = clusterARN
	}
	out := &ecs.DescribeTasksOutput{}
	for _, arn := range in.Tasks {
		out.Tasks = append(out.Tasks, ecstypes.Task{TaskArn: sdkaws.String(arn), ClusterArn: sdkaws.String(cluster), Group: sdkaws.String(group)})
	}
	return out, nil
}

func ecsClient(cfg *config.Config, fake *fakeECS) *Client {
	c := newClient(cfg.Sources["aws"], nil, nil, &fakeIdentity{})
	c.ecs = fake
	return c
}

func TestECSTasksPageAndDescribeInChunks(t *testing.T) {
	cfg, scope := ecsScope(t)
	fake := &fakeECS{count: 230}
	tasks, truncated, err := ecsClient(cfg, fake).ECSTasks(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 230 || truncated {
		t.Errorf("tasks = %d, truncated = %v", len(tasks), truncated)
	}
	if len(fake.listInputs) != 3 {
		t.Errorf("ListTasks calls = %d, want 3", len(fake.listInputs))
	}
	for _, in := range fake.listInputs {
		if sdkaws.ToString(in.Cluster) != "shop-prod" || sdkaws.ToString(in.ServiceName) != "web" || in.DesiredStatus != ecstypes.DesiredStatusRunning {
			t.Errorf("ListTasks input = %+v", in)
		}
	}
	var sizes []int
	for _, arns := range fake.describeArns {
		sizes = append(sizes, len(arns))
	}
	if fmt.Sprint(sizes) != "[100 100 30]" {
		t.Errorf("DescribeTasks chunks = %v, want [100 100 30]", sizes)
	}
}

func TestECSTasksTruncate(t *testing.T) {
	cfg, scope := ecsScope(t)
	tasks, truncated, err := ecsClient(cfg, &fakeECS{count: maxTasks + 1}).ECSTasks(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != maxTasks || !truncated {
		t.Errorf("tasks = %d, truncated = %v", len(tasks), truncated)
	}
	tasks, truncated, err = ecsClient(cfg, &fakeECS{count: maxTasks}).ECSTasks(context.Background(), scope)
	if err != nil || len(tasks) != maxTasks || truncated {
		t.Errorf("exactly maxTasks: tasks = %d, truncated = %v, err = %v", len(tasks), truncated, err)
	}
}

func TestECSTasksPostCheck(t *testing.T) {
	cfg, scope := ecsScope(t)
	for _, fake := range []*fakeECS{
		{count: 2, group: "service:admin"},
		{count: 2, cluster: "arn:aws:ecs:eu-central-1:123456789012:cluster/other"},
	} {
		_, _, err := ecsClient(cfg, fake).ECSTasks(context.Background(), scope)
		if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeInternal || !strings.Contains(err.Error(), "outside the scope") {
			t.Errorf("group %q, cluster %q: error = %v", fake.group, fake.cluster, err)
		}
	}
}

func TestECSService(t *testing.T) {
	cfg, scope := ecsScope(t)
	web := ecstypes.Service{ServiceName: sdkaws.String("web"), ClusterArn: sdkaws.String(clusterARN)}
	svc, err := ecsClient(cfg, &fakeECS{services: []ecstypes.Service{web}}).ECSService(context.Background(), scope)
	if err != nil || sdkaws.ToString(svc.ServiceName) != "web" {
		t.Errorf("service = %+v, err = %v", svc, err)
	}

	_, err = ecsClient(cfg, &fakeECS{}).ECSService(context.Background(), scope)
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeUpstreamError || !strings.Contains(err.Error(), "not found in cluster shop-prod") {
		t.Errorf("missing service: error = %v", err)
	}

	other := ecstypes.Service{ServiceName: sdkaws.String("web"), ClusterArn: sdkaws.String("arn:aws:ecs:eu-central-1:123456789012:cluster/other")}
	_, err = ecsClient(cfg, &fakeECS{services: []ecstypes.Service{other}}).ECSService(context.Background(), scope)
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeInternal {
		t.Errorf("service of another cluster: error = %v", err)
	}
}

const taskDefinitionARN = "arn:aws:ecs:eu-central-1:123456789012:task-definition/web:42"

func TestECSTaskDefinitionDropsValues(t *testing.T) {
	cfg, scope := ecsScope(t)
	secretARN := "arn:aws:secretsmanager:eu-central-1:123456789012:secret:web/db-AbCdEf"
	fake := &fakeECS{taskDefinition: &ecstypes.TaskDefinition{
		TaskDefinitionArn: sdkaws.String(taskDefinitionARN),
		Family:            sdkaws.String("web"),
		Revision:          42,
		TaskRoleArn:       sdkaws.String("arn:aws:iam::123456789012:role/web-task"),
		ContainerDefinitions: []ecstypes.ContainerDefinition{{
			Name:         sdkaws.String("app"),
			Image:        sdkaws.String("123456789012.dkr.ecr.eu-central-1.amazonaws.com/web:1.2.3"),
			Environment:  []ecstypes.KeyValuePair{{Name: sdkaws.String("PORT"), Value: sdkaws.String("8080")}, {Name: sdkaws.String("API_KEY"), Value: sdkaws.String("plain-s3cr3t")}},
			Secrets:      []ecstypes.Secret{{Name: sdkaws.String("DATABASE_URL"), ValueFrom: sdkaws.String(secretARN)}},
			Command:      []string{"serve", "--token=cmd-s3cr3t"},
			DockerLabels: map[string]string{"auth": "label-s3cr3t"},
			LogConfiguration: &ecstypes.LogConfiguration{LogDriver: ecstypes.LogDriverAwslogs, Options: map[string]string{
				"awslogs-group": "/ecs/web", "awslogs-region": "eu-central-1", "token": "log-s3cr3t",
			}},
			PortMappings:          []ecstypes.PortMapping{{ContainerPort: sdkaws.Int32(8080), Protocol: ecstypes.TransportProtocolTcp}},
			RepositoryCredentials: &ecstypes.RepositoryCredentials{CredentialsParameter: sdkaws.String(secretARN)},
		}},
	}}
	td, err := ecsClient(cfg, fake).ECSTaskDefinition(context.Background(), scope, taskDefinitionARN)
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", td)
	for _, value := range []string{"s3cr3t", secretARN} {
		if strings.Contains(dump, value) {
			t.Errorf("task definition keeps %q: %s", value, dump)
		}
	}
	c := td.Containers[0]
	if fmt.Sprint(c.Env) != "[API_KEY PORT]" || fmt.Sprint(c.SecretEnv) != "[DATABASE_URL]" || c.LogGroup != "/ecs/web" || fmt.Sprint(c.Ports) != "[8080/TCP]" {
		t.Errorf("container = %+v", c)
	}
	if td.Family != "web" || td.Revision != 42 || td.TaskRole != "web-task" {
		t.Errorf("task definition = %+v", td)
	}
}

func TestECSTaskDefinitionPostCheck(t *testing.T) {
	cfg, scope := ecsScope(t)
	fake := &fakeECS{taskDefinition: &ecstypes.TaskDefinition{TaskDefinitionArn: sdkaws.String("arn:aws:ecs:eu-central-1:123456789012:task-definition/admin:1")}}
	_, err := ecsClient(cfg, fake).ECSTaskDefinition(context.Background(), scope, taskDefinitionARN)
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeInternal {
		t.Errorf("another task definition: error = %v", err)
	}
}
