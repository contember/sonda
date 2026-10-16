package main

import (
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
)

func (a *app) overviewCmd() *cobra.Command {
	var window windowFlags
	cmd := &cobra.Command{
		Use:   "overview <service>",
		Short: "Recent releases, top errors and signal summaries; start an investigation here",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/overview", params, renderOverview)
		},
	}
	window.register(cmd, "24h")
	return cmd
}

func (a *app) errorsCmd() *cobra.Command {
	var window windowFlags
	var query string
	var limit int
	cmd := &cobra.Command{
		Use:   "errors <service>",
		Short: "List Sentry issues seen in the range, most frequent first",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			if query != "" {
				params.Set("query", query)
			}
			if limit > 0 {
				params.Set("limit", strconv.Itoa(limit))
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/errors", params, renderIssues)
		},
	}
	window.register(cmd, "24h")
	cmd.Flags().StringVar(&query, "query", "", "Sentry search query (default is:unresolved)")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum issues (default 25)")
	return cmd
}

func (a *app) errorCmd() *cobra.Command {
	var env string
	cmd := &cobra.Command{
		Use:   "error <service> <issueId>",
		Short: "Show a Sentry issue with its latest event and stack trace",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if env != "" {
				params.Set("env", env)
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/errors/"+url.PathEscape(args[1]), params, renderIssueDetail)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment (optional when only one is available)")
	return cmd
}

func (a *app) releasesCmd() *cobra.Command {
	var window windowFlags
	cmd := &cobra.Command{
		Use:   "releases <service>",
		Short: "List releases created or deployed in the range",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/releases", params, renderReleases)
		},
	}
	window.register(cmd, "24h")
	return cmd
}
