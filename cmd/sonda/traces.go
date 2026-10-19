package main

import (
	"net/url"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) tracesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "traces",
		Short: "Search and query traces of a service",
	}
	cmd.AddCommand(a.tracesSearchCmd(), a.tracesQueryCmd())
	return cmd
}

func (a *app) tracesSearchCmd() *cobra.Command {
	var window windowFlags
	var minDuration, maxDuration, name string
	var errorsOnly bool
	var where []string
	var limit int
	cmd := &cobra.Command{
		Use:   "search <service>",
		Short: "Find traces with spans of the service that match all filters",
		Long: "Find traces with spans of the service that match all filters.\n" +
			"Show one with: sonda trace <service> <traceId>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := window.window()
			if err != nil {
				return err
			}
			return send(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/traces/search", api.TraceSearchRequest{
				Window: w, MinDuration: minDuration, MaxDuration: maxDuration,
				Errors: errorsOnly, Name: name, Where: where, Limit: limit,
			}, renderTraceSearch)
		},
	}
	window.register(cmd, "1h")
	cmd.Flags().StringVar(&minDuration, "min-duration", "", "only spans at least this long, e.g. 500ms")
	cmd.Flags().StringVar(&maxDuration, "max-duration", "", "only spans at most this long, e.g. 2s")
	cmd.Flags().BoolVar(&errorsOnly, "errors", false, "only traces with an error span of the service")
	cmd.Flags().StringVar(&name, "name", "", "span name must contain this text")
	cmd.Flags().StringArrayVar(&where, "where", nil, "span attribute condition, field=value or field!=value (repeatable)")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum traces (default 20)")
	return cmd
}

func (a *app) tracesQueryCmd() *cobra.Command {
	var window windowFlags
	var limit int
	cmd := &cobra.Command{
		Use:   "query <service> <query>",
		Short: "Run a native trace query restricted to the service",
		Long: "Run a native trace query restricted to the service. The dialect depends on the source\n" +
			`(see describe): TraceQL for Tempo, query JSON with "view":"traces" for Cloudflare.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := window.window()
			if err != nil {
				return err
			}
			return send(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/traces/query", api.TraceQueryRequest{
				Window: w, Query: args[1], Limit: limit,
			}, renderTraceSearch)
		},
	}
	window.register(cmd, "1h")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum traces (default 20)")
	return cmd
}

func (a *app) traceCmd() *cobra.Command {
	var window windowFlags
	cmd := &cobra.Command{
		Use:   "trace <service> <traceId>",
		Short: "Show a trace that contains a span of the service as a span tree",
		Long: "Show a trace that contains a span of the service as a span tree.\n" +
			"Spans of services you have no traces grant for show only service, timing and status.\n" +
			"The range must cover the trace; widen --since for older traces.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/traces/"+url.PathEscape(args[1]), params, renderTrace)
		},
	}
	window.register(cmd, "1h")
	return cmd
}
