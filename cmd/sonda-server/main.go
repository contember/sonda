package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/internal/admin"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/httpapi"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/query"
	"github.com/contember/sonda/internal/store"
)

func main() {
	root := &cobra.Command{
		Use:           "sonda-server",
		Short:         "Read-only observability gateway for AI agents",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	var configPath string
	root.PersistentFlags().StringVarP(&configPath, "config", "c", "sonda.yaml", "path to the configuration file")

	root.AddCommand(
		&cobra.Command{
			Use:   "serve",
			Short: "Start the HTTP server",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return serve(cmd.Context(), configPath)
			},
		},
		checkCmd(&configPath),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func checkCmd(configPath *string) *cobra.Command {
	var online bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate the configuration file",
		Long: "Validate the configuration file. With --online, also connect to every data source and\n" +
			"check that its API key cannot write, that allow-listed entities and deny_fields exist,\n" +
			"and warn about readable fields that may hold personal data.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadFile(*configPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "configuration is valid")
			if !online {
				return nil
			}
			q, err := newQueryService(cfg, nil)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			failed := false
			for _, check := range q.CheckData(ctx) {
				status := "ok"
				if len(check.Errors) > 0 {
					status, failed = "FAILED", true
				}
				fmt.Fprintf(out, "data %s/%s (source %s): %s\n", check.Service, check.Environment, check.Source, status)
				for _, e := range check.Errors {
					fmt.Fprintf(out, "  error: %s\n", e)
				}
				for _, w := range check.Warnings {
					fmt.Fprintf(out, "  warning: %s\n", w)
				}
			}
			if failed {
				return errors.New("online check failed")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&online, "online", false, "also check data sources over the network")
	return cmd
}

// newQueryService builds the query service; the store may be nil for checks that do not
// authenticate.
func newQueryService(cfg *config.Config, st *store.Store) (*query.Service, error) {
	connectors, err := query.NewConnectors(cfg)
	if err != nil {
		return nil, err
	}
	var ids identities.Store
	if st != nil {
		ids = st
	}
	return query.New(cfg, authz.New(cfg, ids), connectors, st)
}

// checkData refuses to start when a data source's API key can write. An unreachable source
// only logs a warning, so one engine outage does not take telemetry down; requests to it
// fail until it is back, and every schema refresh repeats the write check.
func checkData(ctx context.Context, q *query.Service, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, check := range q.CheckData(ctx) {
		attrs := []any{"service", check.Service, "environment", check.Environment, "source", check.Source}
		if check.WriteAccess {
			return fmt.Errorf("data %s/%s: %s", check.Service, check.Environment, strings.Join(check.Errors, "; "))
		}
		for _, e := range check.Errors {
			log.Warn("data source check failed", append(attrs, "error", e)...)
		}
		for _, w := range check.Warnings {
			log.Warn("data source check", append(attrs, "warning", w)...)
		}
	}
	return nil
}

func serve(ctx context.Context, configPath string) error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return err
	}
	connectors, err := query.NewConnectors(cfg)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Server.Database)
	if err != nil {
		return err
	}
	defer st.Close()
	authorizer := authz.New(cfg, st)
	q, err := query.New(cfg, authorizer, connectors, st)
	if err != nil {
		return err
	}
	if err := checkData(ctx, q, log); err != nil {
		return err
	}
	handler := http.NewServeMux()
	handler.Handle("/", httpapi.New(q, authorizer, st, log))
	if cfg.Admin != nil {
		adminHandler, err := admin.New(cfg, st, st, log)
		if err != nil {
			return err
		}
		handler.Handle("/admin/", adminHandler)
	} else {
		log.Info("admin UI disabled: admin.token is not configured")
	}

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Server.Listen)
		errs <- server.ListenAndServe()
	}()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errs; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
