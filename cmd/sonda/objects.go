package main

import (
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) objectsCmd() *cobra.Command {
	var env string
	cmd := &cobra.Command{
		Use:   "objects <service>",
		Short: "Show the configuration of the objects that run the service",
		Long: "Show the configuration of the objects that run the service. On Kubernetes: its Deployments,\n" +
			"StatefulSets, DaemonSets, Jobs and CronJobs, and the Services, Ingress rules, network policies,\n" +
			"disruption budgets, autoscalers, ConfigMap keys and Argo CD Applications that relate to them.\n" +
			"On ECS: the service and the task definitions of its deployments.\n" +
			"Environment variables are listed by name; values are never returned. There is no range.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if env != "" {
				params.Set("env", env)
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/workloads/objects", params, renderObjects)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment (optional when only one is available)")
	return cmd
}

func renderObjects(w io.Writer, resp api.Response[api.WorkloadObjects]) {
	fmt.Fprintf(w, "# %s/%s now\n", resp.Meta.Service, resp.Meta.Environment)
	renderMeta(w, resp.Meta)
	d := resp.Data

	fmt.Fprintln(w, "\nCONTROLLERS")
	if len(d.Controllers) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, c := range d.Controllers {
		fmt.Fprintf(w, "  %s/%s  %s\n", c.Kind, c.Name, controllerState(c))
		for _, key := range slices.Sorted(maps.Keys(c.Details)) {
			fmt.Fprintf(w, "    %s: %s\n", key, c.Details[key])
		}
		for _, cond := range c.Conditions {
			fmt.Fprintf(w, "    condition %s=%s %s %s\n", cond.Type, cond.Status, cond.Reason, cond.Message)
		}
		writeContainerSpecs(w, c.Containers)
	}
	for _, td := range d.TaskDefinitions {
		fmt.Fprintf(w, "\nTASK DEFINITION %s:%d  %s cpu=%s memory=%s %s role=%s\n", td.Family, td.Revision, td.Status, valueOrDash(td.CPU), valueOrDash(td.Memory), td.NetworkMode, valueOrDash(td.TaskRole))
		writeContainerSpecs(w, td.Containers)
	}
	if len(d.Services) > 0 {
		fmt.Fprintln(w, "\nSERVICES")
		for _, s := range d.Services {
			fmt.Fprintf(w, "  %s  %s  %s  endpoints %d ready, %d not ready %s\n", s.Name, s.Type, strings.Join(s.Ports, ", "), s.ReadyEndpoints, s.NotReadyEndpoints, strings.Join(s.LoadBalancer, ","))
		}
	}
	if len(d.Ingresses) > 0 {
		fmt.Fprintln(w, "\nINGRESSES")
		for _, i := range d.Ingresses {
			fmt.Fprintf(w, "  %s  class=%s tls=%s\n", i.Name, valueOrDash(i.Class), valueOrDash(strings.Join(i.TLSHosts, ",")))
			for _, r := range i.Rules {
				fmt.Fprintln(w, "    "+r)
			}
		}
	}
	if len(d.NetworkPolicies) > 0 {
		fmt.Fprintln(w, "\nNETWORK POLICIES")
		for _, p := range d.NetworkPolicies {
			fmt.Fprintf(w, "  %s  %s\n", p.Name, strings.Join(p.PolicyTypes, ","))
			for _, r := range p.Ingress {
				fmt.Fprintln(w, "    ingress "+r)
			}
			for _, r := range p.Egress {
				fmt.Fprintln(w, "    egress "+r)
			}
		}
	}
	if len(d.Autoscalers) > 0 {
		fmt.Fprintln(w, "\nAUTOSCALERS")
		for _, a := range d.Autoscalers {
			fmt.Fprintf(w, "  %s → %s  %d..%d, now %d, desired %d  %s\n", a.Name, a.Target, a.MinReplicas, a.MaxReplicas, a.CurrentReplicas, a.DesiredReplicas, strings.Join(a.Metrics, ", "))
		}
	}
	if len(d.DisruptionBudgets) > 0 {
		fmt.Fprintln(w, "\nDISRUPTION BUDGETS")
		for _, b := range d.DisruptionBudgets {
			fmt.Fprintf(w, "  %s  minAvailable=%s maxUnavailable=%s  healthy %d/%d, %d disruptions allowed\n", b.Name, valueOrDash(b.MinAvailable), valueOrDash(b.MaxUnavailable), b.CurrentHealthy, b.DesiredHealthy, b.DisruptionsAllowed)
		}
	}
	if len(d.ConfigMaps) > 0 {
		fmt.Fprintln(w, "\nCONFIGMAPS (keys only)")
		for _, cm := range d.ConfigMaps {
			if cm.Missing {
				fmt.Fprintf(w, "  %s  MISSING\n", cm.Name)
				continue
			}
			fmt.Fprintf(w, "  %s  %s\n", cm.Name, strings.Join(cm.Keys, ", "))
		}
	}
	if len(d.Applications) > 0 {
		fmt.Fprintln(w, "\nARGO CD")
		for _, app := range d.Applications {
			shared := ""
			if app.Shared {
				shared = "  shared, sync and health of this service's objects"
			}
			fmt.Fprintf(w, "  %s  sync=%s health=%s rev=%s%s\n", app.Name, app.Sync, app.Health, valueOrDash(app.Revision), shared)
			if app.Operation != "" {
				ended := ""
				if app.OperationEnded != nil {
					ended = " at " + app.OperationEnded.Format(time.RFC3339)
				}
				fmt.Fprintf(w, "    last operation %s%s: %s\n", app.Operation, ended, app.OperationDetail)
			}
			for _, c := range app.Conditions {
				fmt.Fprintf(w, "    %s: %s\n", c.Type, c.Message)
			}
			for _, r := range app.Resources {
				fmt.Fprintf(w, "    %s sync=%s health=%s\n", r.Object, valueOrDash(r.Sync), valueOrDash(r.Health))
			}
		}
	}
}

func controllerState(c api.Controller) string {
	var parts []string
	if c.Replicas != nil {
		parts = append(parts, fmt.Sprintf("%d/%d ready", c.ReadyReplicas, *c.Replicas))
	}
	if c.Strategy != "" {
		parts = append(parts, c.Strategy)
	}
	if c.Paused {
		parts = append(parts, "paused")
	}
	if c.Schedule != "" {
		parts = append(parts, "schedule "+c.Schedule)
	}
	if c.Suspended {
		parts = append(parts, "suspended")
	}
	if c.LastSchedule != nil {
		parts = append(parts, "last run "+c.LastSchedule.Format(time.RFC3339))
	}
	if c.LastSuccess != nil {
		parts = append(parts, "last success "+c.LastSuccess.Format(time.RFC3339))
	}
	if c.Kind == "Job" {
		parts = append(parts, fmt.Sprintf("active=%d succeeded=%d failed=%d", c.Active, c.Succeeded, c.Failed))
	}
	return strings.Join(parts, ", ")
}

func writeContainerSpecs(w io.Writer, containers []api.ContainerSpec) {
	for _, c := range containers {
		kind := "container"
		if c.Init {
			kind = "init"
		}
		fmt.Fprintf(w, "    %s %s  %s\n", kind, c.Name, c.Image)
		if len(c.Requests) > 0 || len(c.Limits) > 0 {
			fmt.Fprintf(w, "      requests %s  limits %s\n", quantities(c.Requests), quantities(c.Limits))
		}
		if len(c.Ports) > 0 {
			fmt.Fprintf(w, "      ports %s\n", strings.Join(c.Ports, ", "))
		}
		for _, kind := range slices.Sorted(maps.Keys(c.Probes)) {
			fmt.Fprintf(w, "      %s %s\n", kind, c.Probes[kind])
		}
		if len(c.Env) > 0 {
			fmt.Fprintf(w, "      env %s\n", strings.Join(c.Env, " "))
		}
		if len(c.SecretEnv) > 0 {
			fmt.Fprintf(w, "      env from secrets %s\n", strings.Join(c.SecretEnv, " "))
		}
		if len(c.EnvFrom) > 0 {
			fmt.Fprintf(w, "      env from %s\n", strings.Join(c.EnvFrom, " "))
		}
		if c.LogGroup != "" {
			fmt.Fprintf(w, "      log group %s\n", c.LogGroup)
		}
	}
}

func quantities(q map[string]string) string {
	if len(q) == 0 {
		return "-"
	}
	var parts []string
	for _, key := range slices.Sorted(maps.Keys(q)) {
		parts = append(parts, key+"="+q[key])
	}
	return strings.Join(parts, ",")
}
