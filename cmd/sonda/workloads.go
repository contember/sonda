package main

import (
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) workloadsCmd() *cobra.Command {
	var window windowFlags
	cmd := &cobra.Command{
		Use:   "workloads <service>",
		Short: "Show the service's pods or ECS tasks and rollouts now, and its events in the range",
		Long: "Show the service's Kubernetes pods or ECS tasks and its rollouts now, with the image digest each\n" +
			"container runs, and the events of its objects in the range.\n" +
			"Kubernetes keeps events for about an hour by default; ECS keeps the last 100 service events.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/workloads", params, renderWorkloads)
		},
	}
	window.register(cmd, "1h")
	return cmd
}

func renderWorkloads(w io.Writer, resp api.Response[api.Workloads]) {
	renderMeta(w, resp.Meta)
	if len(resp.Data.Nodes) > 0 {
		renderNodes(w, resp.Data.Nodes)
		renderEvents(w, resp.Data.Events)
		return
	}
	fmt.Fprintln(w, "\nPODS")
	t := table(w)
	for _, pod := range resp.Data.Pods {
		ready := "not ready"
		if pod.Ready {
			ready = "ready"
		}
		fmt.Fprintf(t, "  %s\t%s\t%s\trestarts=%d\t%s\t%s\n", pod.Name, pod.Phase, ready, pod.Restarts, podUsage(pod), podDetail(pod))
	}
	t.Flush()
	if len(resp.Data.Pods) == 0 {
		fmt.Fprintln(w, "  none")
	}

	fmt.Fprintln(w, "\nIMAGES")
	for _, line := range runningImages(resp.Data.Pods) {
		fmt.Fprintln(w, "  "+line)
	}

	fmt.Fprintln(w, "\nROLLOUTS")
	t = table(w)
	for _, r := range resp.Data.Rollouts {
		fmt.Fprintf(t, "  %s\trev %s\t%s\t%d/%d ready\t%s\n", r.Name, valueOrDash(r.Revision), r.Created.Format(time.RFC3339), r.ReadyReplicas, r.Replicas, strings.TrimSpace(r.State+" "+strings.Join(r.Images, ",")))
	}
	t.Flush()
	renderEvents(w, resp.Data.Events)
}

func renderEvents(w io.Writer, events []api.WorkloadEvent) {
	fmt.Fprintln(w, "\nEVENTS")
	if len(events) == 0 {
		fmt.Fprintln(w, "  none in range")
	}
	for _, e := range events {
		// ECS service events have no reason.
		head := strings.Join(slices.DeleteFunc([]string{e.LastSeen.Format(time.RFC3339), e.Type, e.Reason, e.Object}, func(s string) bool { return s == "" }), " ")
		fmt.Fprintf(w, "  %s ×%d: %s\n", head, e.Count, e.Message)
	}
}

func renderNodes(w io.Writer, nodes []api.Node) {
	fmt.Fprintln(w, "\nNODES")
	t := table(w)
	for _, n := range nodes {
		state := "not ready"
		if n.Ready {
			state = "ready"
		}
		if n.Unschedulable {
			state += ",cordoned"
		}
		usage := "-"
		if n.Usage != nil {
			usage = fmt.Sprintf("cpu %dm/%s mem %s/%s", n.Usage.CPUMillicores, valueOrDash(n.Allocatable["cpu"]), mebibytes(n.Usage.MemoryBytes), valueOrDash(n.Allocatable["memory"]))
		}
		fmt.Fprintf(t, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.Name, state, valueOrDash(n.InstanceType), valueOrDash(n.NodeGroup), n.KubeletVersion, usage, strings.Join(n.Problems, "; "))
	}
	t.Flush()
}

// podUsage sums the usage of the pod's containers; "-" without metrics.
func podUsage(pod api.Pod) string {
	var cpu, memory int64
	seen := false
	for _, c := range pod.Containers {
		if c.Usage != nil {
			cpu, memory, seen = cpu+c.Usage.CPUMillicores, memory+c.Usage.MemoryBytes, true
		}
	}
	if !seen {
		return "-"
	}
	return fmt.Sprintf("cpu %dm mem %s", cpu, mebibytes(memory))
}

func mebibytes(bytes int64) string {
	return fmt.Sprintf("%dMi", bytes>>20)
}

// runningImages lists each image and digest the containers run, with the number of containers
// that run it, in order of first appearance.
func runningImages(pods []api.Pod) []string {
	var order []string
	counts := map[string]int{}
	for _, pod := range pods {
		for _, c := range pod.Containers {
			key := c.Image + " " + valueOrDash(c.Digest)
			if counts[key] == 0 {
				order = append(order, key)
			}
			counts[key]++
		}
	}
	lines := make([]string, len(order))
	for i, key := range order {
		lines[i] = fmt.Sprintf("%s  containers=%d", key, counts[key])
	}
	if len(lines) == 0 {
		return []string{"none"}
	}
	return lines
}

// podDetail names the container states that explain an unhealthy pod.
func podDetail(pod api.Pod) string {
	var parts []string
	if pod.Reason != "" {
		parts = append(parts, pod.Reason)
	}
	for _, c := range pod.Containers {
		if c.State != "running" && c.Reason != "" {
			parts = append(parts, c.Name+": "+c.Reason)
		}
		if t := c.LastTermination; t != nil {
			parts = append(parts, fmt.Sprintf("%s last exit: %s (%d) at %s", c.Name, t.Reason, t.ExitCode, t.Finished.Format(time.RFC3339)))
		}
	}
	return strings.Join(parts, "; ")
}

func writeWorkloadSummary(w io.Writer, s *api.WorkloadSummary) {
	if s.Nodes > 0 {
		fmt.Fprintf(w, "  nodes %d/%d ready, %d warning events\n", s.NodesReady, s.Nodes, s.Warnings)
	} else {
		fmt.Fprintf(w, "  pods %d/%d ready, %d restarts, %d warning events\n", s.Ready, s.Pods, s.Restarts, s.Warnings)
	}
	if s.Rollout != nil {
		fmt.Fprintf(w, "  rollout %s rev %s (%s) %s\n", s.Rollout.Name, valueOrDash(s.Rollout.Revision), s.Rollout.Created.Format(time.RFC3339), strings.Join(s.Rollout.Images, ","))
	}
	for _, problem := range s.Problems {
		fmt.Fprintln(w, "  ! "+problem)
	}
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
