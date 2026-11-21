// Package kubernetes reads pods, their controllers and the objects that select them, events,
// nodes and resource usage from the Kubernetes API.
package kubernetes

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/upstream"
)

const (
	pageSize = 500
	// Lists stop after these many objects and report truncation; a service has far fewer.
	maxPods        = 500
	maxReplicaSets = 500
	maxEvents      = 2000
)

type Client struct {
	source *config.Source
	http   *http.Client
}

func New(src *config.Source, client *http.Client) *Client {
	return &Client{source: src, http: client}
}

type ObjectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
}

type OwnerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller bool   `json:"controller"`
}

// Controller returns the owner that manages the object, if any.
func (m ObjectMeta) Controller() (OwnerReference, bool) {
	i := slices.IndexFunc(m.OwnerReferences, func(o OwnerReference) bool { return o.Controller })
	if i < 0 {
		return OwnerReference{}, false
	}
	return m.OwnerReferences[i], true
}

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		NodeName   string          `json:"nodeName"`
		Containers []ContainerSpec `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string            `json:"phase"`
		Reason            string            `json:"reason"`
		StartTime         *time.Time        `json:"startTime"`
		Conditions        []Condition       `json:"conditions"`
		ContainerStatuses []ContainerStatus `json:"containerStatuses"`
	} `json:"status"`
}

// ContainerSpec is a container of a pod or pod template. Env values are not decoded, so a
// literal value never reaches Sonda's types.
type ContainerSpec struct {
	Name      string `json:"name"`
	Image     string `json:"image"`
	Resources struct {
		Requests map[string]string `json:"requests"`
		Limits   map[string]string `json:"limits"`
	} `json:"resources"`
	Env            []EnvVar        `json:"env"`
	EnvFrom        []EnvFromSource `json:"envFrom"`
	Ports          []ContainerPort `json:"ports"`
	LivenessProbe  *Probe          `json:"livenessProbe"`
	ReadinessProbe *Probe          `json:"readinessProbe"`
	StartupProbe   *Probe          `json:"startupProbe"`
}

// EnvVar has no Value field on purpose: a literal value can hold a secret.
type EnvVar struct {
	Name      string `json:"name"`
	ValueFrom *struct {
		ConfigMapKeyRef *KeyRef `json:"configMapKeyRef"`
		SecretKeyRef    *KeyRef `json:"secretKeyRef"`
	} `json:"valueFrom"`
}

type KeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type EnvFromSource struct {
	ConfigMapRef *struct {
		Name string `json:"name"`
	} `json:"configMapRef"`
	SecretRef *struct {
		Name string `json:"name"`
	} `json:"secretRef"`
}

type ContainerPort struct {
	Name          string `json:"name"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

// Probe keeps the kind of check and its timing; an exec probe's command is not decoded.
type Probe struct {
	HTTPGet *struct {
		Path string    `json:"path"`
		Port IntString `json:"port"`
	} `json:"httpGet"`
	TCPSocket *struct {
		Port IntString `json:"port"`
	} `json:"tcpSocket"`
	GRPC *struct {
		Port int `json:"port"`
	} `json:"grpc"`
	Exec                *struct{} `json:"exec"`
	InitialDelaySeconds int       `json:"initialDelaySeconds"`
	PeriodSeconds       int       `json:"periodSeconds"`
	FailureThreshold    int       `json:"failureThreshold"`
}

type Condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type ContainerStatus struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageID is the image the runtime pulled, e.g. docker.io/library/nginx@sha256:…; empty
	// until the pull finishes.
	ImageID      string         `json:"imageID"`
	Ready        bool           `json:"ready"`
	RestartCount int            `json:"restartCount"`
	State        ContainerState `json:"state"`
	LastState    ContainerState `json:"lastState"`
}

// ContainerState has at most one of its fields set.
type ContainerState struct {
	Running *struct {
		StartedAt time.Time `json:"startedAt"`
	} `json:"running"`
	Waiting *struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} `json:"waiting"`
	Terminated *Terminated `json:"terminated"`
}

type Terminated struct {
	Reason     string    `json:"reason"`
	Message    string    `json:"message"`
	ExitCode   int       `json:"exitCode"`
	FinishedAt time.Time `json:"finishedAt"`
}

type ReplicaSet struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Template struct {
			Spec struct {
				Containers []ContainerSpec `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		Replicas      int `json:"replicas"`
		ReadyReplicas int `json:"readyReplicas"`
	} `json:"status"`
}

// Event is a core/v1 event. Older events set the timestamps, newer ones eventTime and series.
type Event struct {
	Metadata       ObjectMeta `json:"metadata"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"involvedObject"`
	Type           string    `json:"type"`
	Reason         string    `json:"reason"`
	Message        string    `json:"message"`
	Count          int       `json:"count"`
	FirstTimestamp time.Time `json:"firstTimestamp"`
	LastTimestamp  time.Time `json:"lastTimestamp"`
	EventTime      time.Time `json:"eventTime"`
	Series         *struct {
		Count            int       `json:"count"`
		LastObservedTime time.Time `json:"lastObservedTime"`
	} `json:"series"`
}

// FirstSeen and LastSeen fall back through the timestamps the event has.
func (e Event) FirstSeen() time.Time {
	return firstSet(e.FirstTimestamp, e.EventTime, e.Metadata.CreationTimestamp)
}

func (e Event) LastSeen() time.Time {
	var observed time.Time
	if e.Series != nil {
		observed = e.Series.LastObservedTime
	}
	return firstSet(observed, e.LastTimestamp, e.EventTime, e.Metadata.CreationTimestamp)
}

// Occurrences counts repeats; an event without a count happened once.
func (e Event) Occurrences() int {
	if e.Series != nil && e.Series.Count > 0 {
		return e.Series.Count
	}
	return max(e.Count, 1)
}

func firstSet(times ...time.Time) time.Time {
	for _, t := range times {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

type list[T any] struct {
	Items    []T `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}

// Pods lists the pods of the scope. Every pod is checked against the scope again.
func (c *Client) Pods(ctx context.Context, scope authz.KubernetesScope) ([]Pod, bool, error) {
	pods, truncated, err := listAll[Pod](ctx, c, "/api/v1/namespaces/"+url.PathEscape(scope.Namespace())+"/pods", selectorParams(scope), maxPods)
	if err != nil {
		return nil, false, err
	}
	for _, pod := range pods {
		if !inScope(scope, pod.Metadata) {
			return nil, false, c.outsideScope()
		}
	}
	return pods, truncated, nil
}

// ReplicaSets lists the ReplicaSets of the scope. Every ReplicaSet is checked against the scope again.
func (c *Client) ReplicaSets(ctx context.Context, scope authz.KubernetesScope) ([]ReplicaSet, bool, error) {
	sets, truncated, err := listAll[ReplicaSet](ctx, c, "/apis/apps/v1/namespaces/"+url.PathEscape(scope.Namespace())+"/replicasets", selectorParams(scope), maxReplicaSets)
	if err != nil {
		return nil, false, err
	}
	for _, set := range sets {
		if !inScope(scope, set.Metadata) {
			return nil, false, c.outsideScope()
		}
	}
	return sets, truncated, nil
}

// Events lists the events of the scope's namespace. Events carry no labels, so they cannot be
// scoped upstream; the caller keeps only events of the scope's objects.
func (c *Client) Events(ctx context.Context, scope authz.KubernetesScope) ([]Event, bool, error) {
	events, truncated, err := listAll[Event](ctx, c, "/api/v1/namespaces/"+url.PathEscape(scope.Namespace())+"/events", nil, maxEvents)
	if err != nil {
		return nil, false, err
	}
	for _, event := range events {
		if event.Metadata.Namespace != scope.Namespace() {
			return nil, false, c.outsideScope()
		}
	}
	return events, truncated, nil
}

// listAll follows continue tokens until the list ends or holds limit items. filter holds
// label or field selectors.
func listAll[T any](ctx context.Context, c *Client, path string, filter url.Values, limit int) ([]T, bool, error) {
	items, truncated, err := listAllRaw[T](ctx, c, path, filter, limit)
	if err != nil {
		return nil, false, upstream.Wrap(c.source.Name, err)
	}
	return items, truncated, nil
}

// listAllRaw is listAll with the upstream error as it came, so callers can read its status.
func listAllRaw[T any](ctx context.Context, c *Client, path string, filter url.Values, limit int) ([]T, bool, error) {
	var items []T
	next := ""
	for {
		params := url.Values{"limit": {strconv.Itoa(pageSize)}}
		for key, values := range filter {
			params[key] = values
		}
		if next != "" {
			params.Set("continue", next)
		}
		var page list[T]
		if err := upstream.GetJSON(ctx, c.http, c.source.Name, c.url(path)+"?"+params.Encode(), &page); err != nil {
			return nil, false, err
		}
		items = append(items, page.Items...)
		if len(items) >= limit {
			return items[:limit], true, nil
		}
		if page.Metadata.Continue == "" {
			return items, false, nil
		}
		next = page.Metadata.Continue
	}
}

func selectorParams(scope authz.KubernetesScope) url.Values {
	return url.Values{"labelSelector": {labelSelector(scope)}}
}

// labelSelector requires every scope label. Config validation keeps keys and values free of
// selector syntax.
func labelSelector(scope authz.KubernetesScope) string {
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
	return strings.Join(parts, ",")
}

func inScope(scope authz.KubernetesScope, meta ObjectMeta) bool {
	if meta.Namespace != scope.Namespace() {
		return false
	}
	for key, value := range scope.Labels() {
		if meta.Labels[key] != value {
			return false
		}
	}
	return true
}

// outsideScope is the defense-in-depth error: lists filter by namespace and labels, so an
// object outside them means the API did not apply the filter.
func (c *Client) outsideScope() error {
	return apierr.New(api.CodeInternal, "source %s returned data outside the scope", c.source.Name)
}
