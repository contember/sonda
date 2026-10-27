package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/contember/sonda/internal/client"
)

func (a *app) authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage the stored Sonda credentials",
	}
	cmd.AddCommand(a.loginCmd())
	return cmd
}

func (a *app) loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Verify a token and save it to ~/.config/sonda/config.yaml",
		Long: "Verify a token against the Sonda server and save the URL and token to ~/.config/sonda/config.yaml with mode 0600.\n\n" +
			"In a terminal, the token is read without echo. Otherwise it is read from stdin:\n" +
			"  sonda auth login --url https://sonda.example.com < token.txt",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := configPath()
			if err != nil {
				return err
			}
			existing, err := readConfig(path)
			if err != nil {
				return err
			}
			stdin, interactive := cmd.InOrStdin().(*os.File)
			interactive = interactive && isTerminal(stdin)
			in := bufio.NewReader(cmd.InOrStdin())
			prompt := cmd.ErrOrStderr()

			baseURL := firstNonEmpty(a.url, os.Getenv("SONDA_URL"), existing.URL)
			if baseURL == "" {
				if !interactive {
					return errors.New("pass --url or set SONDA_URL")
				}
				fmt.Fprint(prompt, "Sonda URL: ")
				line, err := in.ReadString('\n')
				if err != nil {
					return err
				}
				baseURL = strings.TrimSpace(line)
			}

			var token string
			if interactive {
				fmt.Fprint(prompt, "Token: ")
				secret, err := term.ReadPassword(int(stdin.Fd()))
				fmt.Fprintln(prompt)
				if err != nil {
					return err
				}
				token = strings.TrimSpace(string(secret))
			} else {
				line, err := in.ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				token = strings.TrimSpace(line)
			}
			if baseURL == "" || token == "" {
				return errors.New("URL and token must not be empty")
			}

			if _, err := client.New(baseURL, token).Get("/v1/services", nil); err != nil {
				return err
			}
			if err := saveConfig(path, fileConfig{URL: baseURL, Token: token}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Logged in to %s. Saved to %s.\n", baseURL, path)
			if os.Getenv("SONDA_TOKEN") != "" {
				fmt.Fprintln(prompt, "warning: SONDA_TOKEN is set and takes precedence over the saved token")
			}
			return nil
		},
	}
}
