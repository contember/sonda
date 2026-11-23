package main

import (
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

type imageFlags struct {
	env        string
	repository string
	limit      int
}

// register adds the shared flags; limitHelp says what --limit caps for the command.
func (f *imageFlags) register(cmd *cobra.Command, limitHelp string) {
	cmd.Flags().StringVarP(&f.env, "env", "e", "", "environment (optional when only one is available)")
	cmd.Flags().StringVar(&f.repository, "repository", "", "one of the service's repositories (default: all)")
	cmd.Flags().IntVar(&f.limit, "limit", 0, limitHelp)
}

func (f *imageFlags) query() url.Values {
	params := url.Values{}
	if f.env != "" {
		params.Set("env", f.env)
	}
	if f.repository != "" {
		params.Set("repository", f.repository)
	}
	if f.limit > 0 {
		params.Set("limit", strconv.Itoa(f.limit))
	}
	return params
}

func (a *app) imagesCmd() *cobra.Command {
	var (
		flags   imageFlags
		digests []string
	)
	cmd := &cobra.Command{
		Use:   "images <service>",
		Short: "List the images in the service's registry repositories with their scan summaries",
		Long: "List the images in the service's registry repositories, newest pushed first, with their tags and\n" +
			"vulnerability scan summary. --digest selects images by digest, e.g. those workloads reports as running.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := flags.query()
			for _, digest := range digests {
				params.Add("digest", digest)
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/images", params, renderImages)
		},
	}
	flags.register(cmd, "maximum number of images (default 20, at most 100)")
	cmd.Flags().StringArrayVar(&digests, "digest", nil, "image digest sha256:… (repeatable)")
	return cmd
}

func (a *app) imageCmd() *cobra.Command {
	var flags imageFlags
	cmd := &cobra.Command{
		Use:   "image <service> <digest>",
		Short: "Show one image with the findings of its latest vulnerability scan",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/v1/services/" + url.PathEscape(args[0]) + "/images/" + url.PathEscape(args[1])
			return fetch(a, cmd, path, flags.query(), renderImage)
		},
	}
	flags.register(cmd, "maximum number of findings (default 100, at most 1000)")
	return cmd
}

func renderImages(w io.Writer, resp api.Response[[]api.Image]) {
	fmt.Fprintf(w, "# %s/%s now\n", resp.Meta.Service, resp.Meta.Environment)
	renderMeta(w, resp.Meta)
	if len(resp.Data) == 0 {
		fmt.Fprintln(w, "no images")
		return
	}
	t := table(w)
	for _, image := range resp.Data {
		fmt.Fprintf(t, "  %s\t%s\t%s\t%s\t%s\n", image.Repository, image.Digest, valueOrDash(strings.Join(image.Tags, ",")), formatTime(image.PushedAt), imageScanSummary(image))
	}
	t.Flush()
}

func renderImage(w io.Writer, resp api.Response[api.ImageDetail]) {
	image := resp.Data
	fmt.Fprintf(w, "# %s/%s now\n", resp.Meta.Service, resp.Meta.Environment)
	renderMeta(w, resp.Meta)
	fmt.Fprintf(w, "%s@%s  tags=%s  pushed=%s\n", image.Repository, image.Digest, valueOrDash(strings.Join(image.Tags, ",")), formatTime(image.PushedAt))
	if image.Platforms == nil {
		fmt.Fprintf(w, "scan: %s\n", scanDetail(image.Scan))
	} else {
		fmt.Fprintf(w, "index of %d platform image(s), each scanned on its own:\n", len(image.Platforms))
		for _, p := range image.Platforms {
			fmt.Fprintf(w, "  %s %s  scan: %s\n", valueOrDash(p.Platform), p.Digest, scanDetail(p.Scan))
		}
	}
	if len(image.Findings) == 0 {
		// Without a scan, "no findings" would read as a clean scan.
		if image.Scan != nil || slices.ContainsFunc(image.Platforms, func(p api.ImagePlatform) bool { return p.Scan != nil }) {
			fmt.Fprintln(w, "no findings")
		}
		return
	}
	t := table(w)
	for _, f := range image.Findings {
		fixed := ""
		if f.FixedIn != "" {
			fixed = "fixed in " + f.FixedIn
		}
		platform := ""
		if len(image.Platforms) > 0 {
			platform = valueOrDash(f.Platform) + "\t"
		}
		fmt.Fprintf(t, "  %s%s\t%s\t%s\t%s\t%s\n", platform, f.Severity, f.ID, valueOrDash(f.Package), valueOrDash(f.Version), fixed)
	}
	t.Flush()
}

// imageScanSummary summarizes the scan of an image, or the scans of the platforms of an index.
func imageScanSummary(image api.Image) string {
	if image.Platforms == nil {
		return scanSummary(image.Scan)
	}
	if len(image.Platforms) == 0 {
		return "index without image manifests"
	}
	parts := make([]string, 0, len(image.Platforms))
	for _, p := range image.Platforms {
		parts = append(parts, valueOrDash(p.Platform)+": "+scanSummary(p.Scan))
	}
	return strings.Join(parts, "; ")
}

func scanDetail(scan *api.ImageScan) string {
	if scan == nil {
		return scanSummary(scan)
	}
	return fmt.Sprintf("%s  completed=%s  database=%s", scanSummary(scan), formatTime(scan.CompletedAt), formatTime(scan.SourceUpdatedAt))
}

// scanSummary prints the scan status and the counts, most severe first; "0 findings" for a scan
// that found nothing, unlike "not scanned".
func scanSummary(scan *api.ImageScan) string {
	if scan == nil {
		return "not scanned"
	}
	parts := []string{strings.ToLower(scan.Status)}
	if scan.Counts != nil && len(scan.Counts) == 0 {
		parts = append(parts, "0 findings")
	}
	for _, severity := range slices.SortedFunc(maps.Keys(scan.Counts), func(a, b string) int {
		return api.SeverityRank(a) - api.SeverityRank(b)
	}) {
		parts = append(parts, fmt.Sprintf("%s=%d", strings.ToLower(severity), scan.Counts[severity]))
	}
	return strings.Join(parts, " ")
}

func formatTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}
