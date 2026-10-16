package main

import (
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

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

func renderMeta(w io.Writer, meta api.Meta) {
	if meta.Range != nil {
		fmt.Fprintf(w, "# %s/%s %s → %s\n", meta.Service, meta.Environment,
			meta.Range.From.Format(time.RFC3339), meta.Range.To.Format(time.RFC3339))
	}
	for _, src := range meta.Sources {
		if src.URL != "" {
			fmt.Fprintf(w, "# %s: %s\n", src.Kind, src.URL)
		}
	}
	if meta.Truncated {
		fmt.Fprintln(w, "# result truncated")
	}
}

func renderMetricNames(w io.Writer, resp api.Response[[]api.MetricInfo]) {
	renderMeta(w, resp.Meta)
	t := table(w)
	for _, m := range resp.Data {
		fmt.Fprintf(t, "%s\t%s\t%s\n", m.Name, m.Type, m.Help)
	}
	t.Flush()
}

func renderMetricResult(w io.Writer, resp api.Response[api.MetricResult]) {
	renderMeta(w, resp.Meta)
	fmt.Fprintf(w, "# %s (step %s)\n", resp.Data.Query, resp.Data.Step)
	for _, s := range resp.Data.Series {
		fmt.Fprintf(w, "%s\n  %s %s\n", formatLabels(s.Labels), formatSummary(s.Summary), sparkline(s.Points))
	}
}

func formatLabels(labels map[string]string) string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = fmt.Sprintf("%s=%q", name, labels[name])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func formatSummary(s api.SeriesSummary) string {
	if s.Count == 0 {
		return "no values"
	}
	return fmt.Sprintf("last=%s min=%s max=%s avg=%s", num(*s.Last), num(*s.Min), num(*s.Max), num(*s.Avg))
}

func num(v float64) string {
	return strconv.FormatFloat(v, 'g', 4, 64)
}

func sparkline(points []api.Point) string {
	const ticks = "▁▂▃▄▅▆▇█"
	values := make([]float64, 0, len(points))
	for _, p := range points {
		if !math.IsNaN(p.Value) && !math.IsInf(p.Value, 0) {
			values = append(values, p.Value)
		}
	}
	if len(values) == 0 {
		return ""
	}
	low, high := slices.Min(values), slices.Max(values)
	runes := []rune(ticks)
	var b strings.Builder
	for _, v := range values {
		i := 0
		if high > low {
			i = int((v - low) / (high - low) * float64(len(runes)-1))
		}
		b.WriteRune(runes[i])
	}
	return b.String()
}
