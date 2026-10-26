package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) workloadsCmd() *cobra.Command {
	var window windowFlags
	cmd := &cobra.Command{
		Use:   "workloads <service>",
		Short: "Show the service's Kubernetes pods and rollouts now, and its events in the range",
		Long: "Show the service's Kubernetes pods and rollouts now, and the events of its objects in the range.\n" +
			"Kubernetes keeps events for about an hour by default.",
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
	fmt.Fprintln(w, "\nPODS")
	t := table(w)
	for _, pod := range resp.Data.Pods {
		ready := "not ready"
		if pod.Ready {
			ready = "ready"
		}
		fmt.Fprintf(t, "  %s\t%s\t%s\trestarts=%d\t%s\n", pod.Name, pod.Phase, ready, pod.Restarts, podDetail(pod))
	}
	t.Flush()
	if len(resp.Data.Pods) == 0 {
		fmt.Fprintln(w, "  none")
	}

	fmt.Fprintln(w, "\nROLLOUTS")
	t = table(w)
	for _, r := range resp.Data.Rollouts {
		fmt.Fprintf(t, "  %s\trev %s\t%s\t%d/%d ready\t%s\n", r.Name, valueOrDash(r.Revision), r.Created.Format(time.RFC3339), r.ReadyReplicas, r.Replicas, strings.Join(r.Images, ","))
	}
	t.Flush()

	fmt.Fprintln(w, "\nEVENTS")
	if len(resp.Data.Events) == 0 {
		fmt.Fprintln(w, "  none in range")
	}
	for _, e := range resp.Data.Events {
		fmt.Fprintf(w, "  %s %s %s %s ×%d: %s\n", e.LastSeen.Format(time.RFC3339), e.Type, e.Reason, e.Object, e.Count, e.Message)
	}
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
	fmt.Fprintf(w, "  pods %d/%d ready, %d restarts, %d warning events\n", s.Ready, s.Pods, s.Restarts, s.Warnings)
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
