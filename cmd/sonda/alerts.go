package main

import (
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) alertsCmd() *cobra.Command {
	var env string
	cmd := &cobra.Command{
		Use:   "alerts <service>",
		Short: "Show the service's active alerts: firing, pending, recovering, nodata and error",
		Long: "Show the service's active alerts: firing, pending, recovering, nodata and error.\n" +
			"Alerts are the current state of the alerting rules; there is no range.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if env != "" {
				params.Set("env", env)
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/alerts", params, renderAlerts)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment (optional when only one is available)")
	return cmd
}

func renderAlerts(w io.Writer, resp api.Response[[]api.Alert]) {
	fmt.Fprintf(w, "# %s/%s now\n", resp.Meta.Service, resp.Meta.Environment)
	renderMeta(w, resp.Meta)
	if len(resp.Data) == 0 {
		fmt.Fprintln(w, "no active alerts")
		return
	}
	writeAlerts(w, resp.Data)
}

func writeAlerts(w io.Writer, alerts []api.Alert) {
	t := table(w)
	for _, alert := range alerts {
		state := alert.State
		if alert.StateReason != "" {
			state += " (" + alert.StateReason + ")"
		}
		since := "-"
		if alert.ActiveAt != nil {
			since = "since " + alert.ActiveAt.Format(time.RFC3339)
		}
		fmt.Fprintf(t, "  %s\t%s\t%s\tvalue=%s\t%s\n", state, valueOrDash(alert.Name), since, valueOrDash(alert.Value), alertText(alert))
	}
	t.Flush()
}

// alertText is the alert's summary, or its description when it has none.
func alertText(alert api.Alert) string {
	if summary := alert.Annotations["summary"]; summary != "" {
		return summary
	}
	return alert.Annotations["description"]
}
