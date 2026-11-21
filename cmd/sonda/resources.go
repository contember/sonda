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

func (a *app) resourcesCmd() *cobra.Command {
	var window windowFlags
	cmd := &cobra.Command{
		Use:   "resources <service>",
		Short: "Show the versions, upgrades, maintenance, backups and expiry of the service's managed resources",
		Long: "Show the service's managed resources now: RDS and Aurora databases with their engine version,\n" +
			"available upgrades, support dates, pending maintenance and backups; ElastiCache with newer\n" +
			"engine versions and pending updates; ACM certificates with expiry and renewal; Lambda runtimes;\n" +
			"EKS clusters with their support dates and add-on versions. Database events are those in the range.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := window.query()
			if err != nil {
				return err
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/resources", params, renderResources)
		},
	}
	window.register(cmd, "24h")
	return cmd
}

func renderResources(w io.Writer, resp api.Response[api.Resources]) {
	renderMeta(w, resp.Meta)
	d := resp.Data
	for _, db := range d.Databases {
		fmt.Fprintf(w, "\n%s %s  %s %s  %s\n", db.Kind, db.Identifier, db.Engine, db.EngineVersion, valueOrDash(db.Status))
		version := "  version: " + valueOrDash(db.VersionStatus)
		if db.Lifecycle != "" {
			version += "  lifecycle=" + db.Lifecycle
		}
		fmt.Fprintln(w, version)
		fmt.Fprintf(w, "  upgrades: minor=%s  major=%s\n", listOrDash(db.Upgrades.Minor), listOrDash(db.Upgrades.Major))
		for _, s := range db.Support {
			fmt.Fprintf(w, "  support: %s until %s\n", s.Name, formatDate(s.End))
		}
		fmt.Fprintf(w, "  backups: retention=%dd window=%s latest restorable=%s\n", db.BackupRetentionDays, valueOrDash(db.BackupWindow), formatTime(db.LatestRestorableTime))
		fmt.Fprintf(w, "  maintenance: window=%s autoMinor=%t\n", valueOrDash(db.MaintenanceWindow), db.AutoMinorVersionUpgrade)
		writeMaintenance(w, "  ", db.PendingMaintenance)
		instances := db.Members
		if db.Instance != nil {
			instances = []api.DatabaseInstance{*db.Instance}
		}
		for _, i := range instances {
			role := ""
			if i.Writer {
				role = " writer"
			}
			fmt.Fprintf(w, "  instance %s%s  %s  %s  ca=%s until %s\n", i.Identifier, role, i.Class, valueOrDash(i.Status), valueOrDash(i.CA), formatDate(i.CAValidTill))
			writeMaintenance(w, "    ", i.PendingMaintenance)
		}
		for _, s := range db.Snapshots {
			fmt.Fprintf(w, "  snapshot %s  %s  %s  %s\n", s.Identifier, s.Type, formatTime(s.Created), s.Status)
		}
	}
	for _, c := range d.Caches {
		fmt.Fprintf(w, "\ncache %s  %s %s  %s\n", c.Identifier, c.Engine, valueOrDash(c.EngineVersion), valueOrDash(c.Status))
		fmt.Fprintf(w, "  newer: %s\n", listOrDash(c.NewerVersions))
		fmt.Fprintf(w, "  snapshots: retention=%dd window=%s  maintenance window=%s\n", c.SnapshotRetentionDays, valueOrDash(c.SnapshotWindow), valueOrDash(c.MaintenanceWindow))
		writeMaintenance(w, "  ", c.PendingUpdates)
	}
	for _, c := range d.Certificates {
		days := "-"
		if c.DaysLeft != nil {
			days = fmt.Sprintf("%dd left", *c.DaysLeft)
		}
		fmt.Fprintf(w, "\ncertificate %s  %s  expires %s (%s)  renewal=%s %s\n", c.Domain, c.Status, formatDate(c.NotAfter), days, valueOrDash(c.RenewalEligibility), c.RenewalStatus)
		fmt.Fprintf(w, "  in use by: %s\n", listOrDash(c.InUseBy))
	}
	for _, f := range d.Functions {
		fmt.Fprintf(w, "\nfunction %s  %s  %s  last modified %s\n", f.Name, valueOrDash(f.Runtime), valueOrDash(f.State), valueOrDash(f.LastModified))
	}
	for _, c := range d.Clusters {
		fmt.Fprintf(w, "\nkubernetes %s  %s  %s  support=%s  standard until %s, extended until %s\n", c.Name, c.Version, valueOrDash(c.Status), valueOrDash(c.SupportType), formatDate(c.StandardSupportEnd), formatDate(c.ExtendedSupportEnd))
		for _, a := range c.Addons {
			fmt.Fprintf(w, "  addon %s %s  %s  newer=%s default=%s\n", a.Name, a.Version, valueOrDash(a.Status), listOrDash(a.NewerVersions), valueOrDash(a.DefaultVersion))
		}
	}
	if len(d.Events) > 0 {
		fmt.Fprintln(w, "\nEVENTS")
		t := table(w)
		for _, e := range d.Events {
			fmt.Fprintf(t, "  %s\t%s\t%s\n", e.Time.Format(time.RFC3339), e.Source, e.Message)
		}
		t.Flush()
	}
}

func writeMaintenance(w io.Writer, indent string, items []api.MaintenanceItem) {
	for _, m := range items {
		parts := []string{"pending " + m.Action}
		for _, p := range []struct {
			name string
			at   *time.Time
		}{{"auto after", m.AutoAppliedAfter}, {"forced", m.ForcedApplyDate}, {"applies", m.CurrentApplyDate}, {"apply by", m.ApplyBy}} {
			if p.at != nil {
				parts = append(parts, p.name+" "+formatDate(p.at))
			}
		}
		if m.Severity != "" {
			parts = append(parts, m.Severity)
		}
		if m.Description != "" {
			parts = append(parts, m.Description)
		}
		fmt.Fprintln(w, indent+strings.Join(parts, "  "))
	}
}

func listOrDash(items []string) string {
	return valueOrDash(strings.Join(items, ","))
}

func formatDate(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.DateOnly)
}
