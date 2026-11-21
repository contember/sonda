package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/upstream"
)

// maxObjects stops each namespace list; a namespace holds far fewer objects of one kind.
const maxObjects = 500

// IntString is a Kubernetes int-or-string value, such as a port or a percentage, kept as text.
type IntString string

func (v *IntString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*v = IntString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*v = IntString(n.String())
	return nil
}

// LabelSelector is a metav1.LabelSelector.
type LabelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

// Matches evaluates the selector against a label set. A nil selector matches nothing, an empty
// one everything, as in Kubernetes. An unknown operator matches nothing.
func (s *LabelSelector) Matches(labels map[string]string) bool {
	if s == nil {
		return false
	}
	for key, value := range s.MatchLabels {
		if got, ok := labels[key]; !ok || got != value {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		value, ok := labels[e.Key]
		switch e.Operator {
		case "In":
			if !ok || !slices.Contains(e.Values, value) {
				return false
			}
		case "NotIn":
			if ok && slices.Contains(e.Values, value) {
				return false
			}
		case "Exists":
			if !ok {
				return false
			}
		case "DoesNotExist":
			if ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type PodTemplate struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Containers     []ContainerSpec `json:"containers"`
		InitContainers []ContainerSpec `json:"initContainers"`
		Volumes        []struct {
			ConfigMap *struct {
				Name string `json:"name"`
			} `json:"configMap"`
			Projected *struct {
				Sources []struct {
					ConfigMap *struct {
						Name string `json:"name"`
					} `json:"configMap"`
				} `json:"sources"`
			} `json:"projected"`
		} `json:"volumes"`
	} `json:"spec"`
}

// ConfigMaps names the ConfigMaps the template mounts or reads variables from.
func (t PodTemplate) ConfigMaps() []string {
	var names []string
	for _, v := range t.Spec.Volumes {
		if v.ConfigMap != nil {
			names = append(names, v.ConfigMap.Name)
		}
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.ConfigMap != nil {
					names = append(names, s.ConfigMap.Name)
				}
			}
		}
	}
	for _, c := range slices.Concat(t.Spec.InitContainers, t.Spec.Containers) {
		for _, e := range c.EnvFrom {
			if e.ConfigMapRef != nil {
				names = append(names, e.ConfigMapRef.Name)
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.ConfigMapKeyRef != nil {
				names = append(names, e.ValueFrom.ConfigMapKeyRef.Name)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

type StatusCondition struct {
	Type               string     `json:"type"`
	Status             string     `json:"status"`
	Reason             string     `json:"reason"`
	Message            string     `json:"message"`
	LastTransitionTime *time.Time `json:"lastTransitionTime"`
}

type Deployment struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Replicas *int `json:"replicas"`
		Paused   bool `json:"paused"`
		Strategy struct {
			Type          string `json:"type"`
			RollingUpdate *struct {
				MaxSurge       IntString `json:"maxSurge"`
				MaxUnavailable IntString `json:"maxUnavailable"`
			} `json:"rollingUpdate"`
		} `json:"strategy"`
		Template PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas     int               `json:"readyReplicas"`
		UpdatedReplicas   int               `json:"updatedReplicas"`
		AvailableReplicas int               `json:"availableReplicas"`
		Conditions        []StatusCondition `json:"conditions"`
	} `json:"status"`
}

type StatefulSet struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Replicas       *int `json:"replicas"`
		UpdateStrategy struct {
			Type string `json:"type"`
		} `json:"updateStrategy"`
		Template PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas     int               `json:"readyReplicas"`
		UpdatedReplicas   int               `json:"updatedReplicas"`
		AvailableReplicas int               `json:"availableReplicas"`
		Conditions        []StatusCondition `json:"conditions"`
	} `json:"status"`
}

type DaemonSet struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		UpdateStrategy struct {
			Type string `json:"type"`
		} `json:"updateStrategy"`
		Template PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		DesiredNumberScheduled int               `json:"desiredNumberScheduled"`
		NumberReady            int               `json:"numberReady"`
		UpdatedNumberScheduled int               `json:"updatedNumberScheduled"`
		NumberAvailable        int               `json:"numberAvailable"`
		Conditions             []StatusCondition `json:"conditions"`
	} `json:"status"`
}

type Job struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Template PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		Active         int               `json:"active"`
		Succeeded      int               `json:"succeeded"`
		Failed         int               `json:"failed"`
		StartTime      *time.Time        `json:"startTime"`
		CompletionTime *time.Time        `json:"completionTime"`
		Conditions     []StatusCondition `json:"conditions"`
	} `json:"status"`
}

type CronJob struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Schedule    string `json:"schedule"`
		Suspend     *bool  `json:"suspend"`
		JobTemplate struct {
			Spec struct {
				Template PodTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
	Status struct {
		Active             []struct{} `json:"active"`
		LastScheduleTime   *time.Time `json:"lastScheduleTime"`
		LastSuccessfulTime *time.Time `json:"lastSuccessfulTime"`
	} `json:"status"`
}

type MetricTarget struct {
	Type               string    `json:"type"`
	AverageUtilization *int      `json:"averageUtilization"`
	AverageValue       IntString `json:"averageValue"`
	Value              IntString `json:"value"`
}

// HPAMetric is a metric of an autoscaling/v2 HorizontalPodAutoscaler, in its spec (Target) or
// status (Current).
type HPAMetric struct {
	Type     string `json:"type"`
	Resource *struct {
		Name    string       `json:"name"`
		Target  MetricTarget `json:"target"`
		Current MetricTarget `json:"current"`
	} `json:"resource"`
	ContainerResource *struct {
		Name      string       `json:"name"`
		Container string       `json:"container"`
		Target    MetricTarget `json:"target"`
		Current   MetricTarget `json:"current"`
	} `json:"containerResource"`
	Pods     *namedMetric `json:"pods"`
	Object   *namedMetric `json:"object"`
	External *namedMetric `json:"external"`
}

type namedMetric struct {
	Metric struct {
		Name string `json:"name"`
	} `json:"metric"`
	Target  MetricTarget `json:"target"`
	Current MetricTarget `json:"current"`
}

// Named returns the metric name, its target and current value for the non-resource types.
func (m HPAMetric) Named() (*namedMetric, bool) {
	for _, n := range []*namedMetric{m.Pods, m.Object, m.External} {
		if n != nil {
			return n, true
		}
	}
	return nil, false
}

type HorizontalPodAutoscaler struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		ScaleTargetRef struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"scaleTargetRef"`
		MinReplicas *int        `json:"minReplicas"`
		MaxReplicas int         `json:"maxReplicas"`
		Metrics     []HPAMetric `json:"metrics"`
	} `json:"spec"`
	Status struct {
		CurrentReplicas int               `json:"currentReplicas"`
		DesiredReplicas int               `json:"desiredReplicas"`
		LastScaleTime   *time.Time        `json:"lastScaleTime"`
		CurrentMetrics  []HPAMetric       `json:"currentMetrics"`
		Conditions      []StatusCondition `json:"conditions"`
	} `json:"status"`
}

type PodDisruptionBudget struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		MinAvailable   *IntString     `json:"minAvailable"`
		MaxUnavailable *IntString     `json:"maxUnavailable"`
		Selector       *LabelSelector `json:"selector"`
	} `json:"spec"`
	Status struct {
		CurrentHealthy     int `json:"currentHealthy"`
		DesiredHealthy     int `json:"desiredHealthy"`
		ExpectedPods       int `json:"expectedPods"`
		DisruptionsAllowed int `json:"disruptionsAllowed"`
	} `json:"status"`
}

type LoadBalancerStatus struct {
	Ingress []struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
	} `json:"ingress"`
}

type Service struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Type     string            `json:"type"`
		Selector map[string]string `json:"selector"`
		Ports    []struct {
			Name       string    `json:"name"`
			Port       int       `json:"port"`
			TargetPort IntString `json:"targetPort"`
			Protocol   string    `json:"protocol"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer LoadBalancerStatus `json:"loadBalancer"`
	} `json:"status"`
}

// ServiceNameLabel links an EndpointSlice to its Service.
const ServiceNameLabel = "kubernetes.io/service-name"

type EndpointSlice struct {
	Metadata  ObjectMeta `json:"metadata"`
	Endpoints []struct {
		Conditions struct {
			Ready *bool `json:"ready"`
		} `json:"conditions"`
	} `json:"endpoints"`
}

type IngressBackend struct {
	Service *struct {
		Name string `json:"name"`
		Port struct {
			Name   string `json:"name"`
			Number int    `json:"number"`
		} `json:"port"`
	} `json:"service"`
}

type Ingress struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		IngressClassName *string         `json:"ingressClassName"`
		DefaultBackend   *IngressBackend `json:"defaultBackend"`
		Rules            []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Path    string         `json:"path"`
					Backend IngressBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
		TLS []struct {
			Hosts []string `json:"hosts"`
		} `json:"tls"`
	} `json:"spec"`
	Status struct {
		LoadBalancer LoadBalancerStatus `json:"loadBalancer"`
	} `json:"status"`
}

type NetworkPolicyPeer struct {
	PodSelector       *LabelSelector `json:"podSelector"`
	NamespaceSelector *LabelSelector `json:"namespaceSelector"`
	IPBlock           *struct {
		CIDR   string   `json:"cidr"`
		Except []string `json:"except"`
	} `json:"ipBlock"`
}

type NetworkPolicyPort struct {
	Protocol *string    `json:"protocol"`
	Port     *IntString `json:"port"`
	EndPort  *int       `json:"endPort"`
}

type NetworkPolicy struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		PodSelector LabelSelector `json:"podSelector"`
		PolicyTypes []string      `json:"policyTypes"`
		Ingress     []struct {
			From  []NetworkPolicyPeer `json:"from"`
			Ports []NetworkPolicyPort `json:"ports"`
		} `json:"ingress"`
		Egress []struct {
			To    []NetworkPolicyPeer `json:"to"`
			Ports []NetworkPolicyPort `json:"ports"`
		} `json:"egress"`
	} `json:"spec"`
}

// KeysOnly decodes a map and keeps its keys; the values are discarded while decoding.
type KeysOnly []string

func (k *KeysOnly) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	*k = keys
	return nil
}

// ConfigMap keeps the keys of data and binaryData, never their values.
type ConfigMap struct {
	Metadata   ObjectMeta `json:"metadata"`
	Data       KeysOnly   `json:"data"`
	BinaryData KeysOnly   `json:"binaryData"`
}

// Application is an Argo CD Application. Its spec.source (Helm values among it) is not decoded.
type Application struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Project string `json:"project"`
	} `json:"spec"`
	Status struct {
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		Health struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"health"`
		OperationState *struct {
			Phase      string     `json:"phase"`
			Message    string     `json:"message"`
			FinishedAt *time.Time `json:"finishedAt"`
		} `json:"operationState"`
		ReconciledAt *time.Time `json:"reconciledAt"`
		Conditions   []struct {
			Type               string     `json:"type"`
			Message            string     `json:"message"`
			LastTransitionTime *time.Time `json:"lastTransitionTime"`
		} `json:"conditions"`
		Resources []AppResource `json:"resources"`
	} `json:"status"`
}

// AppResource is an object an Application manages, with its sync and health state.
type AppResource struct {
	Group     string `json:"group"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Health    *struct {
		Status string `json:"status"`
	} `json:"health"`
}

type Node struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Unschedulable bool `json:"unschedulable"`
		Taints        []struct {
			Key    string `json:"key"`
			Value  string `json:"value"`
			Effect string `json:"effect"`
		} `json:"taints"`
	} `json:"spec"`
	Status struct {
		Conditions  []StatusCondition `json:"conditions"`
		Allocatable map[string]string `json:"allocatable"`
		NodeInfo    struct {
			KubeletVersion          string `json:"kubeletVersion"`
			OSImage                 string `json:"osImage"`
			ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

// PodMetrics is the current usage of a pod's containers from the metrics API.
type PodMetrics struct {
	Metadata   ObjectMeta `json:"metadata"`
	Containers []struct {
		Name  string            `json:"name"`
		Usage map[string]string `json:"usage"`
	} `json:"containers"`
}

type NodeMetrics struct {
	Metadata ObjectMeta        `json:"metadata"`
	Usage    map[string]string `json:"usage"`
}

// Namespaced lists of the scope's namespace. They are not filtered by labels: controllers carry
// the service's labels on their pod template, and Services, Ingresses, policies and budgets
// select pods without carrying their labels, so the caller keeps the objects that relate to the
// service. Every object is checked against the namespace.

func (c *Client) Deployments(ctx context.Context, scope authz.KubernetesScope) ([]Deployment, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/apps/v1", "deployments", func(d Deployment) ObjectMeta { return d.Metadata })
}

func (c *Client) StatefulSets(ctx context.Context, scope authz.KubernetesScope) ([]StatefulSet, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/apps/v1", "statefulsets", func(d StatefulSet) ObjectMeta { return d.Metadata })
}

func (c *Client) DaemonSets(ctx context.Context, scope authz.KubernetesScope) ([]DaemonSet, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/apps/v1", "daemonsets", func(d DaemonSet) ObjectMeta { return d.Metadata })
}

func (c *Client) Jobs(ctx context.Context, scope authz.KubernetesScope) ([]Job, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/batch/v1", "jobs", func(d Job) ObjectMeta { return d.Metadata })
}

func (c *Client) CronJobs(ctx context.Context, scope authz.KubernetesScope) ([]CronJob, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/batch/v1", "cronjobs", func(d CronJob) ObjectMeta { return d.Metadata })
}

func (c *Client) HorizontalPodAutoscalers(ctx context.Context, scope authz.KubernetesScope) ([]HorizontalPodAutoscaler, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/autoscaling/v2", "horizontalpodautoscalers", func(d HorizontalPodAutoscaler) ObjectMeta { return d.Metadata })
}

func (c *Client) PodDisruptionBudgets(ctx context.Context, scope authz.KubernetesScope) ([]PodDisruptionBudget, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/policy/v1", "poddisruptionbudgets", func(d PodDisruptionBudget) ObjectMeta { return d.Metadata })
}

func (c *Client) Services(ctx context.Context, scope authz.KubernetesScope) ([]Service, bool, error) {
	return listNamespace(ctx, c, scope, "/api/v1", "services", func(d Service) ObjectMeta { return d.Metadata })
}

func (c *Client) EndpointSlices(ctx context.Context, scope authz.KubernetesScope) ([]EndpointSlice, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/discovery.k8s.io/v1", "endpointslices", func(d EndpointSlice) ObjectMeta { return d.Metadata })
}

func (c *Client) Ingresses(ctx context.Context, scope authz.KubernetesScope) ([]Ingress, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/networking.k8s.io/v1", "ingresses", func(d Ingress) ObjectMeta { return d.Metadata })
}

func (c *Client) NetworkPolicies(ctx context.Context, scope authz.KubernetesScope) ([]NetworkPolicy, bool, error) {
	return listNamespace(ctx, c, scope, "/apis/networking.k8s.io/v1", "networkpolicies", func(d NetworkPolicy) ObjectMeta { return d.Metadata })
}

func listNamespace[T any](ctx context.Context, c *Client, scope authz.KubernetesScope, group, resource string, meta func(T) ObjectMeta) ([]T, bool, error) {
	items, truncated, err := listAll[T](ctx, c, group+"/namespaces/"+url.PathEscape(scope.Namespace())+"/"+resource, nil, maxObjects)
	if err != nil {
		return nil, false, err
	}
	for _, item := range items {
		if meta(item).Namespace != scope.Namespace() {
			return nil, false, c.outsideScope()
		}
	}
	return items, truncated, nil
}

// ConfigMap reads one ConfigMap of the scope's namespace by name; found is false when it does
// not exist. Only its keys are decoded.
func (c *Client) ConfigMap(ctx context.Context, scope authz.KubernetesScope, name string) (ConfigMap, bool, error) {
	var cm ConfigMap
	err := upstream.GetJSON(ctx, c.http, c.source.Name, c.url("/api/v1/namespaces/"+url.PathEscape(scope.Namespace())+"/configmaps/"+url.PathEscape(name)), &cm)
	if upstream.IsNotFound(err) {
		return ConfigMap{}, false, nil
	}
	if err != nil {
		return ConfigMap{}, false, upstream.Wrap(c.source.Name, err)
	}
	if cm.Metadata.Namespace != scope.Namespace() || cm.Metadata.Name != name {
		return ConfigMap{}, false, c.outsideScope()
	}
	return cm, true, nil
}

// Applications lists the Argo CD Applications of the source's Argo CD namespace; the caller keeps
// those that manage the service's objects. Without a configured namespace there are none.
func (c *Client) Applications(ctx context.Context) ([]Application, bool, error) {
	ns := c.source.ArgoCDNamespace
	if ns == "" {
		return nil, false, nil
	}
	apps, truncated, err := listAll[Application](ctx, c, "/apis/argoproj.io/v1alpha1/namespaces/"+url.PathEscape(ns)+"/applications", nil, maxObjects)
	if err != nil {
		return nil, false, err
	}
	for _, app := range apps {
		if app.Metadata.Namespace != ns {
			return nil, false, c.outsideScope()
		}
	}
	return apps, truncated, nil
}

// PodMetrics reads the usage of the pods with the scope's labels. Pod metrics need not carry
// the pod's labels, so they are checked only against the namespace; the caller joins them to
// the scope's pods by name. ok is false when the cluster has no metrics API or Sonda may not
// read it: usage is optional.
func (c *Client) PodMetrics(ctx context.Context, scope authz.KubernetesScope) ([]PodMetrics, bool, error) {
	items, _, err := listAllRaw[PodMetrics](ctx, c, "/apis/metrics.k8s.io/v1beta1/namespaces/"+url.PathEscape(scope.Namespace())+"/pods", selectorParams(scope), maxPods)
	if err != nil {
		return nil, false, c.optionalAPI(err)
	}
	for _, m := range items {
		if m.Metadata.Namespace != scope.Namespace() {
			return nil, false, c.outsideScope()
		}
	}
	return items, true, nil
}

// Nodes lists the cluster's nodes.
func (c *Client) Nodes(ctx context.Context, _ authz.NodeScope) ([]Node, bool, error) {
	return listAll[Node](ctx, c, "/api/v1/nodes", nil, maxObjects)
}

// NodeMetrics reads the usage of the cluster's nodes; ok is false as for PodMetrics.
func (c *Client) NodeMetrics(ctx context.Context, _ authz.NodeScope) ([]NodeMetrics, bool, error) {
	items, _, err := listAllRaw[NodeMetrics](ctx, c, "/apis/metrics.k8s.io/v1beta1/nodes", nil, maxObjects)
	if err != nil {
		return nil, false, c.optionalAPI(err)
	}
	return items, true, nil
}

// nodeEventsNamespace is where Kubernetes records the events of nodes.
const nodeEventsNamespace = "default"

// NodeEvents lists the events of nodes, filtered upstream by the involved object's kind and
// checked again.
func (c *Client) NodeEvents(ctx context.Context, _ authz.NodeScope) ([]Event, bool, error) {
	filter := url.Values{"fieldSelector": {"involvedObject.kind=Node"}}
	events, truncated, err := listAll[Event](ctx, c, "/api/v1/namespaces/"+nodeEventsNamespace+"/events", filter, maxEvents)
	if err != nil {
		return nil, false, err
	}
	for _, e := range events {
		if e.InvolvedObject.Kind != "Node" {
			return nil, false, c.outsideScope()
		}
	}
	return events, truncated, nil
}

// optionalAPI turns the answers of a cluster without the metrics API, or without Sonda's access
// to it, into a nil error; anything else stays an error.
func (c *Client) optionalAPI(err error) error {
	var se *upstream.StatusError
	if errors.As(err, &se) && (se.Status == http.StatusNotFound || se.Status == http.StatusForbidden || se.Status == http.StatusServiceUnavailable) {
		return nil
	}
	return upstream.Wrap(c.source.Name, err)
}

func (c *Client) url(path string) string {
	return strings.TrimRight(c.source.URL, "/") + path
}

// ParseCPU converts a CPU quantity (e.g. 250m, 1, 123456789n) to millicores.
func ParseCPU(q string) (int64, bool) {
	for _, unit := range []struct {
		suffix string
		div    float64
	}{{"n", 1e6}, {"u", 1e3}, {"m", 1}} {
		if number, ok := strings.CutSuffix(q, unit.suffix); ok {
			v, err := strconv.ParseFloat(number, 64)
			return int64(v / unit.div), err == nil
		}
	}
	v, err := strconv.ParseFloat(q, 64)
	return int64(v * 1000), err == nil
}

// ParseMemory converts a memory quantity (e.g. 512Mi, 1G, 123456Ki, 1e6) to bytes.
func ParseMemory(q string) (int64, bool) {
	for _, unit := range []struct {
		suffix string
		mul    float64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}} {
		if number, ok := strings.CutSuffix(q, unit.suffix); ok {
			v, err := strconv.ParseFloat(number, 64)
			return int64(v * unit.mul), err == nil
		}
	}
	v, err := strconv.ParseFloat(q, 64)
	return int64(v), err == nil
}
