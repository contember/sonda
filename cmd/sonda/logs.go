package main

import (
	"net/url"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) logsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Search and query logs of a service",
	}
	cmd.AddCommand(a.logsSearchCmd(), a.logsQueryCmd(), a.logsFieldsCmd())
	return cmd
}

func (a *app) logsSearchCmd() *cobra.Command {
	var window windowFlags
	var contains, where []string
	var pipeline string
	var limit int
	cmd := &cobra.Command{
		Use:   "search <service>",
		Short: "Count matching lines and group a sample into patterns",
		Long: "Count matching lines exactly and group a sample of the newest lines into patterns.\n" +
			"Drill into a group with: sonda result <resultId> --group <index>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := window.window()
			if err != nil {
				return err
			}
			return send(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/logs/search", api.LogSearchRequest{
				Window: w, Contains: contains, Where: where, Pipeline: pipeline, Limit: limit,
			}, renderLogSearch)
		},
	}
	window.register(cmd, "1h")
	cmd.Flags().StringArrayVar(&contains, "contains", nil, "line must contain this text (repeatable)")
	cmd.Flags().StringArrayVar(&where, "where", nil, "field=value or field!=value condition (repeatable)")
	cmd.Flags().StringVar(&pipeline, "pipeline", "", `LogQL pipeline, Loki only, e.g. '| json | level="error"'`)
	cmd.Flags().IntVar(&limit, "limit", 0, "sample size (default: server maximum)")
	return cmd
}

func (a *app) logsQueryCmd() *cobra.Command {
	var window windowFlags
	var limit int
	var step string
	cmd := &cobra.Command{
		Use:   "query <service> <query>",
		Short: "Run a native log query restricted to the service",
		Long: "Run a native log query restricted to the service. The dialect depends on the source\n" +
			"(see describe): LogQL for Loki, query JSON for Cloudflare, Logs Insights for CloudWatch.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := window.window()
			if err != nil {
				return err
			}
			return send(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/logs/query", api.LogQueryRequest{
				Window: w, Query: args[1], Limit: limit, Step: step,
			}, renderLogQuery)
		},
	}
	window.register(cmd, "1h")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum lines (default 100)")
	cmd.Flags().StringVar(&step, "step", "", "resolution of metric queries, e.g. 1m")
	return cmd
}

func (a *app) logsFieldsCmd() *cobra.Command {
	var window windowFlags
	cmd := &cobra.Command{
		Use:   "fields <service>",
		Short: "List stream labels with values and fields detected in lines",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/logs/fields", params, renderLogFields)
		},
	}
	window.register(cmd, "1h")
	return cmd
}

func (a *app) resultCmd() *cobra.Command {
	var group, offset, limit int
	cmd := &cobra.Command{
		Use:   "result <resultId>",
		Short: "Page through stored lines of an earlier search or query",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if cmd.Flags().Changed("group") {
				params.Set("group", strconv.Itoa(group))
			}
			if offset > 0 {
				params.Set("offset", strconv.Itoa(offset))
			}
			if limit > 0 {
				params.Set("limit", strconv.Itoa(limit))
			}
			return fetch(a, cmd, "/v1/results/"+url.PathEscape(args[0]), params, renderResultPage)
		},
	}
	cmd.Flags().IntVar(&group, "group", 0, "only lines of this group index")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many lines")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum lines (default 100)")
	return cmd
}
