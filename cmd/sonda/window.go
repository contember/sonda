package main

import (
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

type windowFlags struct {
	env   string
	since string
	from  string
	to    string
}

func (f *windowFlags) register(cmd *cobra.Command, defaultSince string) {
	cmd.Flags().StringVarP(&f.env, "env", "e", "", "environment (optional when only one is available)")
	cmd.Flags().StringVar(&f.since, "since", "", "range length ending at --to or now, e.g. 30m, 6h, 2d (default "+defaultSince+")")
	cmd.Flags().StringVar(&f.from, "from", "", "range start, RFC 3339")
	cmd.Flags().StringVar(&f.to, "to", "", "range end, RFC 3339")
}

func (f *windowFlags) window() (api.Window, error) {
	w := api.Window{Environment: f.env, Since: f.since}
	for name, pair := range map[string]struct {
		raw    string
		target **time.Time
	}{"from": {f.from, &w.From}, "to": {f.to, &w.To}} {
		if pair.raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, pair.raw)
		if err != nil {
			return api.Window{}, fmt.Errorf("--%s must be an RFC 3339 time like 2026-10-16T10:00:00Z", name)
		}
		*pair.target = &t
	}
	return w, nil
}

func (f *windowFlags) query() (url.Values, error) {
	if _, err := f.window(); err != nil {
		return nil, err
	}
	params := url.Values{}
	for name, value := range map[string]string{"env": f.env, "since": f.since, "from": f.from, "to": f.to} {
		if value != "" {
			params.Set(name, value)
		}
	}
	return params, nil
}
