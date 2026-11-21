package query

import (
	"context"
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/kubernetes"
)

// nodeWorkloads reads the nodes of a cluster, their usage and their events. It serves a
// service that stands for the cluster itself.
type nodeWorkloads struct {
	s      *Service
	scope  authz.NodeScope
	client *kubernetes.Client
}

func (b nodeWorkloads) workloads(ctx context.Context, r api.TimeRange) (workloadState, error) {
	const query = "nodes"
	recordQuery(ctx, b.scope.Target, query)

	var (
		wg                            sync.WaitGroup
		nodes                         []kubernetes.Node
		usage                         []kubernetes.NodeMetrics
		events                        []kubernetes.Event
		nodesCut, eventsCut           bool
		nodesErr, usageErr, eventsErr error
	)
	wg.Go(func() { nodes, nodesCut, nodesErr = b.client.Nodes(ctx, b.scope) })
	wg.Go(func() { usage, _, usageErr = b.client.NodeMetrics(ctx, b.scope) })
	wg.Go(func() { events, eventsCut, eventsErr = b.client.NodeEvents(ctx, b.scope) })
	wg.Wait()
	for _, err := range []error{nodesErr, usageErr, eventsErr} {
		if err != nil {
			return workloadState{}, err
		}
	}
	return workloadState{
		data: api.Workloads{
			Pods:     []api.Pod{},
			Rollouts: []api.Rollout{},
			Events:   b.s.nodeEvents(events, r),
			Nodes:    shapeNodes(nodes, usage),
		},
		truncated: nodesCut || eventsCut,
		source:    api.SourceRef{Kind: "kubernetes", Query: query},
	}, nil
}

func (b nodeWorkloads) objects(context.Context) (objectState, error) {
	return objectState{}, apierr.InvalidRequest("service %s stands for a cluster's nodes and has no objects; use workloads", b.scope.Service())
}

// Well-known node labels that tell where and on what a node runs, in order of preference.
var (
	instanceTypeLabels = []string{"node.kubernetes.io/instance-type"}
	zoneLabels         = []string{"topology.kubernetes.io/zone"}
	nodeGroupLabels    = []string{"eks.amazonaws.com/nodegroup", "karpenter.sh/nodepool"}
	capacityTypeLabels = []string{"eks.amazonaws.com/capacityType", "karpenter.sh/capacity-type"}
)

// healthyCondition is the healthy status of each node condition; Ready must be True, the
// pressure conditions False.
func healthyCondition(kind string) string {
	if kind == "Ready" {
		return "True"
	}
	return "False"
}

func shapeNodes(nodes []kubernetes.Node, metrics []kubernetes.NodeMetrics) []api.Node {
	usage := map[string]map[string]string{}
	for _, m := range metrics {
		usage[m.Metadata.Name] = m.Usage
	}
	result := make([]api.Node, 0, len(nodes))
	for _, n := range nodes {
		labels := n.Metadata.Labels
		node := api.Node{
			Name:             n.Metadata.Name,
			Unschedulable:    n.Spec.Unschedulable,
			Created:          n.Metadata.CreationTimestamp,
			InstanceType:     firstLabel(labels, instanceTypeLabels),
			Zone:             firstLabel(labels, zoneLabels),
			NodeGroup:        firstLabel(labels, nodeGroupLabels),
			CapacityType:     firstLabel(labels, capacityTypeLabels),
			KubeletVersion:   n.Status.NodeInfo.KubeletVersion,
			OSImage:          n.Status.NodeInfo.OSImage,
			ContainerRuntime: n.Status.NodeInfo.ContainerRuntimeVersion,
			Allocatable:      pick(n.Status.Allocatable, "cpu", "memory", "pods"),
		}
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" {
				node.Ready = c.Status == "True"
			}
			if c.Status != healthyCondition(c.Type) {
				problem := c.Type + "=" + c.Status
				if c.Reason != "" {
					problem += " (" + c.Reason + ")"
				}
				node.Problems = append(node.Problems, problem)
			}
		}
		for _, t := range n.Spec.Taints {
			taint := t.Key
			if t.Value != "" {
				taint += "=" + t.Value
			}
			node.Taints = append(node.Taints, taint+":"+t.Effect)
		}
		if u, ok := usage[n.Metadata.Name]; ok {
			node.Usage = usageOf(u)
		}
		result = append(result, node)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func firstLabel(labels map[string]string, keys []string) string {
	for _, key := range keys {
		if value := labels[key]; value != "" {
			return value
		}
	}
	return ""
}

func pick(m map[string]string, keys ...string) map[string]string {
	result := maps.Clone(m)
	maps.DeleteFunc(result, func(key, _ string) bool { return !slices.Contains(keys, key) })
	if len(result) == 0 {
		return nil
	}
	return result
}

// nodeEvents keeps the node events that overlap the range, newest first.
func (s *Service) nodeEvents(events []kubernetes.Event, r api.TimeRange) []api.WorkloadEvent {
	var result []api.WorkloadEvent
	for _, e := range events {
		first, last := e.FirstSeen(), e.LastSeen()
		if last.Before(r.From) || first.After(r.To) {
			continue
		}
		result = append(result, api.WorkloadEvent{
			Type:      e.Type,
			Reason:    e.Reason,
			Object:    "Node/" + e.InvolvedObject.Name,
			Message:   s.redactor.Redact(e.Message),
			Count:     e.Occurrences(),
			FirstSeen: first,
			LastSeen:  last,
		})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	if result == nil {
		result = []api.WorkloadEvent{}
	}
	return result
}
