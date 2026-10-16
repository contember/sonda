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

func renderLogSearch(w io.Writer, resp api.Response[api.LogSearchResult]) {
	renderMeta(w, resp.Meta)
	d := resp.Data
	fmt.Fprintf(w, "# %s\n# %d matching lines, %d sampled", d.Query, d.Total, d.SampleSize)
	if d.SampleRange != nil {
		fmt.Fprintf(w, " (%s → %s)", d.SampleRange.From.Format(time.RFC3339), d.SampleRange.To.Format(time.RFC3339))
	}
	fmt.Fprintf(w, ", result %s\n", resp.Meta.ResultID)
	t := table(w)
	fmt.Fprintln(t, "GROUP\t~COUNT\tSAMPLED\tPATTERN")
	for _, g := range d.Groups {
		fmt.Fprintf(t, "%d\t%d\t%d\t%s\n", g.Index, g.EstimatedCount, g.SampleCount, g.Pattern)
	}
	t.Flush()
	if d.Ungrouped > 0 {
		fmt.Fprintf(w, "# %d sampled lines could not be grouped\n", d.Ungrouped)
	}
}

func renderLogQuery(w io.Writer, resp api.Response[api.LogQueryResult]) {
	renderMeta(w, resp.Meta)
	fmt.Fprintf(w, "# %s\n", resp.Data.Query)
	renderLines(w, resp.Data.Streams, resp.Data.Lines)
	for _, s := range resp.Data.Series {
		fmt.Fprintf(w, "%s\n  %s %s\n", formatLabels(s.Labels), formatSummary(s.Summary), sparkline(s.Points))
	}
	if resp.Meta.ResultID != "" {
		fmt.Fprintf(w, "# more lines: sonda result %s --offset %d\n", resp.Meta.ResultID, len(resp.Data.Lines))
	}
}

func renderLines(w io.Writer, streams []map[string]string, lines []api.LogLine) {
	for i, s := range streams {
		fmt.Fprintf(w, "# stream %d: %s\n", i, formatLabels(s))
	}
	for _, line := range lines {
		fmt.Fprintf(w, "%s [%d] %s\n", line.Time.Format(time.RFC3339Nano), line.Stream, line.Line)
	}
}

func renderLogFields(w io.Writer, resp api.Response[api.LogFields]) {
	renderMeta(w, resp.Meta)
	t := table(w)
	fmt.Fprintln(t, "LABEL\tVALUES")
	for _, l := range resp.Data.Labels {
		values := strings.Join(l.Values, ", ")
		if l.MoreValues {
			values += ", …"
		}
		fmt.Fprintf(t, "%s\t%s\n", l.Name, values)
	}
	t.Flush()
	if len(resp.Data.Fields) > 0 {
		t = table(w)
		fmt.Fprintln(t, "FIELD\tTYPE\tCARDINALITY\tPARSERS")
		for _, f := range resp.Data.Fields {
			fmt.Fprintf(t, "%s\t%s\t%d\t%s\n", f.Name, f.Type, f.Cardinality, strings.Join(f.Parsers, ","))
		}
		t.Flush()
	}
}

func renderResultPage(w io.Writer, resp api.Response[api.ResultPage]) {
	p := resp.Data
	fmt.Fprintf(w, "# %d lines", p.Total)
	if p.Group != nil {
		fmt.Fprintf(w, " in group %d", *p.Group)
	}
	fmt.Fprintf(w, ", showing from offset %d\n", p.Offset)
	renderLines(w, p.Streams, p.Lines)
	if p.NextOffset != nil {
		fmt.Fprintf(w, "# next page: --offset %d\n", *p.NextOffset)
	}
}

func renderIssues(w io.Writer, resp api.Response[[]api.Issue]) {
	renderMeta(w, resp.Meta)
	writeIssues(w, resp.Data)
}

func writeIssues(w io.Writer, issues []api.Issue) {
	t := table(w)
	fmt.Fprintln(t, "ID\tSHORT ID\tCOUNT\tUSERS\tLAST SEEN\tNEW\tTITLE")
	for _, i := range issues {
		isNew := ""
		if i.New {
			isNew = "new"
		}
		fmt.Fprintf(t, "%s\t%s\t%d\t%d\t%s\t%s\t%s\n", i.ID, i.ShortID, i.Count, i.Users, i.LastSeen.Format(time.RFC3339), isNew, i.Title)
	}
	t.Flush()
}

func renderIssueDetail(w io.Writer, resp api.Response[api.IssueDetail]) {
	i := resp.Data.Issue
	fmt.Fprintf(w, "%s %s\n  %s\n  culprit: %s\n  %d events, %d users, first %s, last %s\n  %s\n",
		i.ShortID, i.Level, i.Title, i.Culprit, i.Count, i.Users,
		i.FirstSeen.Format(time.RFC3339), i.LastSeen.Format(time.RFC3339), i.Link)
	e := resp.Data.LatestEvent
	if e == nil {
		return
	}
	fmt.Fprintf(w, "\nlatest event %s at %s", e.ID, e.Timestamp.Format(time.RFC3339))
	if e.Release != "" {
		fmt.Fprintf(w, ", release %s", e.Release)
	}
	if e.TraceID != "" {
		fmt.Fprintf(w, ", trace %s", e.TraceID)
	}
	fmt.Fprintln(w)
	for _, ex := range e.Exceptions {
		fmt.Fprintf(w, "  %s: %s\n", ex.Type, ex.Value)
		for _, f := range ex.Frames {
			fmt.Fprintf(w, "    at %s (%s:%d:%d)\n", f.Function, f.File, f.Line, f.Column)
		}
	}
	if len(e.Tags) > 0 {
		fmt.Fprintf(w, "  tags: %s\n", formatLabels(e.Tags))
	}
}

func renderReleases(w io.Writer, resp api.Response[[]api.Release]) {
	renderMeta(w, resp.Meta)
	writeReleases(w, resp.Data)
}

func writeReleases(w io.Writer, releases []api.Release) {
	t := table(w)
	fmt.Fprintln(t, "VERSION\tCREATED\tLAST DEPLOY")
	for _, r := range releases {
		deploy := ""
		if r.LastDeploy != nil {
			deploy = r.LastDeploy.Environment + " " + r.LastDeploy.Finished.Format(time.RFC3339)
		}
		fmt.Fprintf(t, "%s\t%s\t%s\n", r.Version, r.Created.Format(time.RFC3339), deploy)
	}
	t.Flush()
}

func renderOverview(w io.Writer, resp api.Response[api.Overview]) {
	renderMeta(w, resp.Meta)
	o := resp.Data
	if o.Releases != nil {
		fmt.Fprintln(w, "\nRELEASES")
		if o.Releases.Error != "" {
			fmt.Fprintln(w, "  error: "+o.Releases.Error)
		} else if len(o.Releases.Items) == 0 {
			fmt.Fprintln(w, "  none in range")
		} else {
			writeReleases(w, o.Releases.Items)
		}
	}
	if o.Issues != nil {
		fmt.Fprintln(w, "\nTOP ERRORS")
		if o.Issues.Error != "" {
			fmt.Fprintln(w, "  error: "+o.Issues.Error)
		} else {
			writeIssues(w, o.Issues.Items)
		}
	}
	if len(o.Signals) > 0 {
		fmt.Fprintln(w, "\nSIGNALS")
		for _, s := range o.Signals {
			if s.Error != "" {
				fmt.Fprintf(w, "  %s: error: %s\n", s.Name, s.Error)
				continue
			}
			if len(s.Series) == 0 {
				fmt.Fprintf(w, "  %s: no data\n", s.Name)
			}
			for _, series := range s.Series {
				fmt.Fprintf(w, "  %s %s: %s\n", s.Name, formatLabels(series.Labels), formatSummary(series.Summary))
			}
		}
	}
}
