package main

import (
	"net/url"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) metricsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "List and query Prometheus metrics of a service",
	}
	cmd.AddCommand(a.metricsListCmd(), a.metricsQueryCmd())
	return cmd
}

func (a *app) metricsListCmd() *cobra.Command {
	var window windowFlags
	var filter string
	cmd := &cobra.Command{
		Use:   "list <service>",
		Short: "List metric names with type and help",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			if filter != "" {
				params.Set("filter", filter)
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/metrics", params, renderMetricNames)
		},
	}
	window.register(cmd, "1h")
	cmd.Flags().StringVar(&filter, "filter", "", "only names containing this text")
	return cmd
}

func (a *app) metricsQueryCmd() *cobra.Command {
	var window windowFlags
	var step string
	var noPoints bool
	cmd := &cobra.Command{
		Use:   "query <service> <promql>",
		Short: "Run PromQL; every selector is restricted to the service",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := window.window()
			if err != nil {
				return err
			}
			path := "/v1/services/" + url.PathEscape(args[0]) + "/metrics/query?points=" + strconv.FormatBool(!noPoints)
			return send(a, cmd, path, api.MetricQueryRequest{Window: w, Query: args[1], Step: step}, renderMetricResult)
		},
	}
	window.register(cmd, "1h")
	cmd.Flags().StringVar(&step, "step", "", "resolution, e.g. 1m (default: about 60 points)")
	cmd.Flags().BoolVar(&noPoints, "no-points", false, "return only summaries")
	return cmd
}

func (a *app) signalCmd() *cobra.Command {
	var window windowFlags
	var step string
	var noPoints bool
	cmd := &cobra.Command{
		Use:   "signal <service> <name>",
		Short: "Evaluate a named signal defined for the service (see describe)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			if step != "" {
				params.Set("step", step)
			}
			params.Set("points", strconv.FormatBool(!noPoints))
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/signals/"+url.PathEscape(args[1]), params, renderMetricResult)
		},
	}
	window.register(cmd, "1h")
	cmd.Flags().StringVar(&step, "step", "", "resolution, e.g. 1m (default: about 60 points)")
	cmd.Flags().BoolVar(&noPoints, "no-points", false, "return only summaries")
	return cmd
}
