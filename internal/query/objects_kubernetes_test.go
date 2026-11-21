package query

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/connector/kubernetes"
)

func decode[T any](t *testing.T, text string) []T {
	t.Helper()
	var items []T
	if err := json.Unmarshal([]byte(text), &items); err != nil {
		t.Fatal(err)
	}
	return items
}

// A namespace with two services: engine-api (app=engine-api), the scope, and admin (app=admin).
func namespaceObjects(t *testing.T) kubernetesObjects {
	t.Helper()
	return kubernetesObjects{
		deployments: decode[kubernetes.Deployment](t, `[
			{"metadata":{"name":"engine-api","namespace":"engine"},"spec":{"replicas":3,"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxSurge":"25%","maxUnavailable":0}},
			 "template":{"metadata":{"labels":{"app":"engine-api","version":"v2"}},"spec":{
			  "containers":[{"name":"app","image":"engine:2","env":[{"name":"API_KEY","value":"env-s3cr3t"},{"name":"DB_PASSWORD","valueFrom":{"secretKeyRef":{"name":"db","key":"password"}}}],
			   "envFrom":[{"configMapRef":{"name":"engine-env"}},{"secretRef":{"name":"engine-secrets"}}],
			   "ports":[{"name":"http","containerPort":8080}],"readinessProbe":{"httpGet":{"path":"/healthz","port":"http"}},
			   "resources":{"requests":{"cpu":"250m"},"limits":{"memory":"1Gi"}}}],
			  "volumes":[{"configMap":{"name":"engine-files"}}]}}},
			 "status":{"readyReplicas":2,"conditions":[{"type":"Available","status":"False","message":"token=abc needed"}]}},
			{"metadata":{"name":"admin","namespace":"engine"},"spec":{"template":{"metadata":{"labels":{"app":"admin"}},"spec":{"volumes":[{"configMap":{"name":"admin-files"}}]}}}}
		]`),
		cronJobs: decode[kubernetes.CronJob](t, `[
			{"metadata":{"name":"engine-cleanup","namespace":"engine"},"spec":{"schedule":"0 3 * * *","jobTemplate":{"spec":{"template":{"metadata":{"labels":{"app":"engine-api"}}}}}}}
		]`),
		services: decode[kubernetes.Service](t, `[
			{"metadata":{"name":"engine-api","namespace":"engine"},"spec":{"type":"ClusterIP","selector":{"app":"engine-api"},"ports":[{"name":"http","port":80,"targetPort":"http","protocol":"TCP"}]}},
			{"metadata":{"name":"admin","namespace":"engine"},"spec":{"selector":{"app":"admin"}}},
			{"metadata":{"name":"external","namespace":"engine"},"spec":{"type":"ExternalName"}}
		]`),
		slices: decode[kubernetes.EndpointSlice](t, `[
			{"metadata":{"name":"engine-api-x","labels":{"kubernetes.io/service-name":"engine-api"}},"endpoints":[{"conditions":{"ready":true}},{"conditions":{"ready":false}},{"conditions":{}}]},
			{"metadata":{"name":"admin-x","labels":{"kubernetes.io/service-name":"admin"}},"endpoints":[{"conditions":{"ready":true}}]}
		]`),
		ingresses: decode[kubernetes.Ingress](t, `[
			{"metadata":{"name":"public"},"spec":{"ingressClassName":"traefik","rules":[{"host":"api.example.com","http":{"paths":[
				{"path":"/","backend":{"service":{"name":"engine-api","port":{"name":"http"}}}},
				{"path":"/admin","backend":{"service":{"name":"admin","port":{"number":80}}}}]}}],"tls":[{"hosts":["api.example.com"]}]}},
			{"metadata":{"name":"admin-only"},"spec":{"rules":[{"host":"admin.example.com","http":{"paths":[{"path":"/","backend":{"service":{"name":"admin","port":{"number":80}}}}]}}]}}
		]`),
		policies: decode[kubernetes.NetworkPolicy](t, `[
			{"metadata":{"name":"default-deny"},"spec":{"podSelector":{},"policyTypes":["Ingress"]}},
			{"metadata":{"name":"engine-db"},"spec":{"podSelector":{"matchLabels":{"app":"engine-api"}},"policyTypes":["Egress"],
			 "egress":[{"to":[{"namespaceSelector":{"matchLabels":{"name":"db"}},"podSelector":{"matchLabels":{"app":"postgres"}}}],"ports":[{"port":5432}]}]}},
			{"metadata":{"name":"admin-only"},"spec":{"podSelector":{"matchLabels":{"app":"admin"}}}}
		]`),
		budgets: decode[kubernetes.PodDisruptionBudget](t, `[
			{"metadata":{"name":"engine-api"},"spec":{"minAvailable":1,"selector":{"matchLabels":{"app":"engine-api"}}},"status":{"currentHealthy":2,"desiredHealthy":1,"expectedPods":3,"disruptionsAllowed":1}},
			{"metadata":{"name":"admin"},"spec":{"maxUnavailable":"50%","selector":{"matchLabels":{"app":"admin"}}}}
		]`),
		autoscalers: decode[kubernetes.HorizontalPodAutoscaler](t, `[
			{"metadata":{"name":"engine-api"},"spec":{"scaleTargetRef":{"kind":"Deployment","name":"engine-api"},"minReplicas":2,"maxReplicas":6,
			 "metrics":[{"type":"Resource","resource":{"name":"cpu","target":{"type":"Utilization","averageUtilization":70}}}]},
			 "status":{"currentReplicas":3,"desiredReplicas":3,"currentMetrics":[{"type":"Resource","resource":{"name":"cpu","current":{"averageUtilization":45}}}]}},
			{"metadata":{"name":"admin"},"spec":{"scaleTargetRef":{"kind":"Deployment","name":"admin"},"maxReplicas":2}}
		]`),
		applications: decode[kubernetes.Application](t, `[
			{"metadata":{"name":"engine","namespace":"argocd"},"spec":{"project":"default"},"status":{"sync":{"status":"OutOfSync","revision":"abc123"},"health":{"status":"Degraded"},
			 "operationState":{"phase":"Failed","message":"one or more objects failed"},
			 "resources":[{"kind":"Deployment","namespace":"engine","name":"engine-api","status":"OutOfSync","health":{"status":"Degraded"}},
			  {"kind":"Deployment","namespace":"engine","name":"admin","status":"Synced"},
			  {"kind":"Service","namespace":"engine","name":"engine-api","status":"Synced"}]}},
			{"metadata":{"name":"admin","namespace":"argocd"},"status":{"resources":[{"kind":"Deployment","namespace":"engine","name":"admin"}]}},
			{"metadata":{"name":"other-ns","namespace":"argocd"},"status":{"resources":[{"kind":"Deployment","namespace":"other","name":"engine-api"}]}}
		]`),
	}
}

func TestRelateObjectsKeepsTheServiceOnly(t *testing.T) {
	related := testService(t).relateObjects("engine", map[string]string{"app": "engine-api"}, namespaceObjects(t))
	data := related.data

	var controllers []string
	for _, c := range data.Controllers {
		controllers = append(controllers, c.Kind+"/"+c.Name)
	}
	if fmt.Sprint(controllers) != "[Deployment/engine-api CronJob/engine-cleanup]" {
		t.Errorf("controllers = %v", controllers)
	}
	d := data.Controllers[0]
	if d.Strategy != "RollingUpdate maxSurge=25% maxUnavailable=0" || *d.Replicas != 3 || d.ReadyReplicas != 2 {
		t.Errorf("deployment = %+v", d)
	}
	if d.Conditions[0].Message != "token=[REDACTED] needed" {
		t.Errorf("condition message is not redacted: %q", d.Conditions[0].Message)
	}
	app := d.Containers[0]
	if fmt.Sprintln(app.Env, app.SecretEnv, app.EnvFrom, app.Ports, app.Probes["readiness"]) != "[API_KEY] [DB_PASSWORD] [ConfigMap/engine-env Secret/engine-secrets] [http 8080/TCP] http :http/healthz delay=0s period=10s failures=3\n" {
		t.Errorf("container = %+v", app)
	}
	if fmt.Sprint(related.configMaps) != "[engine-env engine-files]" {
		t.Errorf("config maps = %v", related.configMaps)
	}

	if len(data.Services) != 1 || data.Services[0].Name != "engine-api" || data.Services[0].ReadyEndpoints != 2 || data.Services[0].NotReadyEndpoints != 1 {
		t.Errorf("services = %+v", data.Services)
	}
	if len(data.Ingresses) != 1 || fmt.Sprint(data.Ingresses[0].Rules) != "[api.example.com/ → engine-api:http]" {
		t.Errorf("ingresses = %+v", data.Ingresses)
	}
	var policies []string
	for _, p := range data.NetworkPolicies {
		policies = append(policies, p.Name+": "+strings.Join(p.Egress, "; "))
	}
	if fmt.Sprint(policies) != "[default-deny:  engine-db: to namespaces {name=db} and pods {app=postgres} ports 5432/TCP]" {
		t.Errorf("policies = %q", policies)
	}
	if len(data.DisruptionBudgets) != 1 || data.DisruptionBudgets[0].MinAvailable != "1" {
		t.Errorf("budgets = %+v", data.DisruptionBudgets)
	}
	if len(data.Autoscalers) != 1 || fmt.Sprint(data.Autoscalers[0].Metrics) != "[cpu 45%/70%]" || data.Autoscalers[0].MinReplicas != 2 {
		t.Errorf("autoscalers = %+v", data.Autoscalers)
	}
	if len(data.Applications) != 1 {
		t.Fatalf("applications = %+v", data.Applications)
	}
	a := data.Applications[0]
	if a.Name != "engine" || a.Sync != "OutOfSync" || a.Operation != "Failed" || fmt.Sprint(a.Resources) != "[{Deployment/engine-api OutOfSync Degraded} {Service/engine-api Synced }]" {
		t.Errorf("application = %+v", a)
	}

	out, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"s3cr3t", "admin"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("response contains %q: %s", leak, out)
		}
	}
}

func TestRelateObjectsKeepsNewestJobs(t *testing.T) {
	var jobs []string
	for i := range maxJobs + 5 {
		jobs = append(jobs, fmt.Sprintf(`{"metadata":{"name":"job-%02d","creationTimestamp":"2026-10-%02dT00:00:00Z"},"spec":{"template":{"metadata":{"labels":{"app":"engine-api"}}}}}`, i, i+1))
	}
	o := kubernetesObjects{jobs: decode[kubernetes.Job](t, "["+strings.Join(jobs, ",")+"]")}
	related := testService(t).relateObjects("engine", map[string]string{"app": "engine-api"}, o)
	if len(related.data.Controllers) != maxJobs || !related.truncated || related.data.Controllers[0].Name != "job-24" {
		t.Errorf("%d jobs, truncated %v, first %s", len(related.data.Controllers), related.truncated, related.data.Controllers[0].Name)
	}
}

func TestAddPodUsageJoinsByName(t *testing.T) {
	pods := []api.Pod{{Name: "engine-api-1", Containers: []api.Container{{Name: "app"}}}}
	metrics := decode[kubernetes.PodMetrics](t, `[
		{"metadata":{"name":"engine-api-1"},"containers":[{"name":"app","usage":{"cpu":"125m","memory":"256Mi"}}]},
		{"metadata":{"name":"admin-1"},"containers":[{"name":"app","usage":{"cpu":"9","memory":"9Gi"}}]}
	]`)
	addPodUsage(pods, metrics)
	if u := pods[0].Containers[0].Usage; u == nil || u.CPUMillicores != 125 || u.MemoryBytes != 256<<20 {
		t.Errorf("usage = %+v", u)
	}
}

func TestShapeNodes(t *testing.T) {
	nodes := decode[kubernetes.Node](t, `[
		{"metadata":{"name":"b","labels":{"node.kubernetes.io/instance-type":"m6i.large","eks.amazonaws.com/nodegroup":"main"}},
		 "spec":{"taints":[{"key":"dedicated","value":"db","effect":"NoSchedule"}]},
		 "status":{"conditions":[{"type":"Ready","status":"True"},{"type":"MemoryPressure","status":"True","reason":"KubeletHasInsufficientMemory"}],
		  "allocatable":{"cpu":"1930m","memory":"7Gi","pods":"29","ephemeral-storage":"1"},"nodeInfo":{"kubeletVersion":"v1.33.1"}}},
		{"metadata":{"name":"a"},"spec":{"unschedulable":true},"status":{"conditions":[{"type":"Ready","status":"Unknown","reason":"NodeStatusUnknown"}]}}
	]`)
	usage := decode[kubernetes.NodeMetrics](t, `[{"metadata":{"name":"b"},"usage":{"cpu":"500m","memory":"2Gi"}}]`)
	shaped := shapeNodes(nodes, usage)
	if shaped[0].Name != "a" || shaped[0].Ready || !shaped[0].Unschedulable || fmt.Sprint(shaped[0].Problems) != "[Ready=Unknown (NodeStatusUnknown)]" {
		t.Errorf("node a = %+v", shaped[0])
	}
	b := shaped[1]
	if !b.Ready || fmt.Sprint(b.Problems) != "[MemoryPressure=True (KubeletHasInsufficientMemory)]" || b.InstanceType != "m6i.large" || b.NodeGroup != "main" ||
		fmt.Sprint(b.Taints) != "[dedicated=db:NoSchedule]" || len(b.Allocatable) != 3 || b.Usage == nil || b.Usage.CPUMillicores != 500 {
		t.Errorf("node b = %+v", b)
	}
	summary := summarizeWorkloads(api.Workloads{Nodes: shaped}, workloadRange)
	if summary.Nodes != 2 || summary.NodesReady != 1 || len(summary.Problems) != 2 {
		t.Errorf("summary = %+v", summary)
	}
}

func TestECSObjects(t *testing.T) {
	created := workloadRange.From
	svc := ecstypes.Service{
		ServiceName: sdkaws.String("web"), Status: sdkaws.String("ACTIVE"), DesiredCount: 2, RunningCount: 1, CreatedAt: &created,
		TaskDefinition: sdkaws.String("arn:aws:ecs:eu-central-1:123456789012:task-definition/web:42"),
		LaunchType:     ecstypes.LaunchTypeFargate,
		DeploymentConfiguration: &ecstypes.DeploymentConfiguration{MinimumHealthyPercent: sdkaws.Int32(100), MaximumPercent: sdkaws.Int32(200),
			DeploymentCircuitBreaker: &ecstypes.DeploymentCircuitBreaker{Enable: true, Rollback: true}},
		LoadBalancers: []ecstypes.LoadBalancer{{TargetGroupArn: sdkaws.String("arn:aws:elasticloadbalancing:eu-central-1:123456789012:targetgroup/web-tg/abc"),
			ContainerName: sdkaws.String("app"), ContainerPort: sdkaws.Int32(8080)}},
	}
	c := ecsController(svc)
	if c.Strategy != "minHealthy=100% max=200% circuitBreaker+rollback" || c.Details["loadBalancers"] != "targetgroup/web-tg → app:8080" ||
		c.Details["taskDefinition"] != "web:42" || *c.Replicas != 2 || c.ReadyReplicas != 1 {
		t.Errorf("controller = %+v", c)
	}
	td := apiTaskDefinition(aws.TaskDefinition{Family: "web", Revision: 42, Containers: []aws.TaskContainer{{Name: "app", CPU: 256, Memory: 512, Env: []string{"PORT"}}}})
	if td.Containers[0].Requests["cpu"] != "256 units" || td.Containers[0].Limits["memory"] != "512MiB" || fmt.Sprint(td.Containers[0].Env) != "[PORT]" {
		t.Errorf("task definition = %+v", td)
	}
}
