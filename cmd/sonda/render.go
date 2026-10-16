package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/contember/sonda/api"
)

func table(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

func renderServices(w io.Writer, resp api.Response[[]api.ServiceSummary]) {
	t := table(w)
	fmt.Fprintln(t, "SERVICE\tENVIRONMENTS\tDESCRIPTION")
	for _, svc := range resp.Data {
		fmt.Fprintf(t, "%s\t%s\t%s\n", svc.Name, strings.Join(svc.Environments, ","), svc.Description)
	}
	t.Flush()
}

func renderService(w io.Writer, resp api.Response[api.ServiceDetail]) {
	svc := resp.Data
	fmt.Fprintln(w, svc.Name)
	if svc.Description != "" {
		fmt.Fprintln(w, "  "+svc.Description)
	}
	if svc.Repository != "" {
		fmt.Fprintln(w, "  repository: "+svc.Repository)
	}
	for _, env := range svc.Environments {
		caps := make([]string, len(env.Capabilities))
		for i, c := range env.Capabilities {
			caps[i] = string(c)
		}
		fmt.Fprintf(w, "  env %s: %s\n", env.Name, strings.Join(caps, ", "))
	}
	if len(svc.Signals) > 0 {
		fmt.Fprintln(w, "  signals: "+strings.Join(svc.Signals, ", "))
	}
}
