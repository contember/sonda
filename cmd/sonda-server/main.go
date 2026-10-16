package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/httpapi"
	"github.com/contember/sonda/internal/query"
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
		&cobra.Command{
			Use:   "check",
			Short: "Validate the configuration file",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if _, err := config.LoadFile(configPath); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "configuration is valid")
				return nil
			},
		},
		&cobra.Command{
			Use:   "token",
			Short: "Generate an identity token and the hash to put in the configuration",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				token, hash := generateToken()
				fmt.Fprintf(cmd.OutOrStdout(), "token:        %s\ntoken_sha256: %s\n", token, hash)
				return nil
			},
		},
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, configPath string) error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return err
	}
	authorizer := authz.New(cfg)
	handler := httpapi.New(query.New(cfg, authorizer), authorizer, log)

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

func generateToken() (token string, hash string) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	token = "sonda_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:])
}
