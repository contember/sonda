package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
	"golang.org/x/term"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/client"
)

const (
	exitOK       = 0
	exitUsage    = 1
	exitNotFound = 2
	exitLimit    = 3
	exitUpstream = 4
)

type app struct {
	url    string
	token  string
	format string
}

func main() {
	a := &app{}
	root := &cobra.Command{
		Use:           "sonda",
		Short:         "Query production telemetry through a Sonda server",
		Long:          "Query production telemetry through a Sonda server.\n\nOutput is JSON when stdout is not a terminal, compact text otherwise.\nConfigure with SONDA_URL and SONDA_TOKEN, or ~/.config/sonda/config.yaml (url, token).",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.url, "url", "", "Sonda server URL (default $SONDA_URL)")
	root.PersistentFlags().StringVar(&a.format, "format", "", "output format: json or text (default: json unless stdout is a terminal)")

	root.AddCommand(a.servicesCmd(), a.describeCmd(), a.metricsCmd(), a.signalCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(exitCode(err))
	}
}

func exitCode(err error) int {
	var apiErr *client.Error
	if !errors.As(err, &apiErr) {
		return exitUsage
	}
	switch apiErr.Code {
	case api.CodeInvalidRequest, api.CodeInvalidQuery:
		return exitUsage
	case api.CodeNotFound, api.CodeUnauthenticated:
		return exitNotFound
	case api.CodeLimitExceeded, api.CodeRateLimited:
		return exitLimit
	default:
		return exitUpstream
	}
}

type fileConfig struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

func (a *app) client() (*client.Client, error) {
	var file fileConfig
	if home, err := os.UserConfigDir(); err == nil {
		data, err := os.ReadFile(filepath.Join(home, "sonda", "config.yaml"))
		if err == nil {
			if err := yaml.Unmarshal(data, &file); err != nil {
				return nil, fmt.Errorf("read sonda config: %w", err)
			}
		}
	}
	baseURL := firstNonEmpty(a.url, os.Getenv("SONDA_URL"), file.URL)
	token := firstNonEmpty(os.Getenv("SONDA_TOKEN"), file.Token)
	if baseURL == "" || token == "" {
		return nil, errors.New("set SONDA_URL and SONDA_TOKEN, or url and token in ~/.config/sonda/config.yaml")
	}
	return client.New(baseURL, token), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (a *app) jsonOutput() (bool, error) {
	switch a.format {
	case "json":
		return true, nil
	case "text":
		return false, nil
	case "":
		return !term.IsTerminal(int(os.Stdout.Fd())), nil
	default:
		return false, fmt.Errorf("unknown format %q (expected json or text)", a.format)
	}
}

// output passes the raw JSON through, or decodes it and renders text.
func output[T any](a *app, w io.Writer, body []byte, render func(io.Writer, api.Response[T])) error {
	asJSON, err := a.jsonOutput()
	if err != nil {
		return err
	}
	if asJSON {
		_, err := w.Write(body)
		return err
	}
	var resp api.Response[T]
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	render(w, resp)
	return nil
}

func (a *app) servicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "services",
		Short: "List services you can access",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			body, err := c.Get("/v1/services", nil)
			if err != nil {
				return err
			}
			return output(a, cmd.OutOrStdout(), body, renderServices)
		},
	}
}

func (a *app) describeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <service>",
		Short: "Show environments, capabilities and signals of a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			body, err := c.Get("/v1/services/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			return output(a, cmd.OutOrStdout(), body, renderService)
		},
	}
}
