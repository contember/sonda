package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/contember/sonda/api"
)

func (a *app) dataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "data",
		Short: "Read application data of a service (read-only GraphQL)",
	}
	cmd.AddCommand(a.dataSchemaCmd(), a.dataQueryCmd())
	return cmd
}

func (a *app) dataSchemaCmd() *cobra.Command {
	var env string
	cmd := &cobra.Command{
		Use:   "schema <service>",
		Short: "Show the entities, fields and relations you can read",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if env != "" {
				params.Set("env", env)
			}
			return fetch(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/data/schema", params, renderDataSchema)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment (optional when only one is available)")
	return cmd
}

func (a *app) dataQueryCmd() *cobra.Command {
	var env, file, varsFile string
	var vars []string
	cmd := &cobra.Command{
		Use:   "query <service> [<query>]",
		Short: "Run a read-only GraphQL query against the service's data",
		Long: "Run a read-only GraphQL query against the service's data. The dialect depends on the\n" +
			"source (see describe); for Contember it is the Content API: get<Entity>(by: …),\n" +
			"list<Entity>(limit: N, …) and paginate<Entity>(first: N, …). Every list needs a limit.\n" +
			"Read the query from the argument, from --file, or from stdin with --file -.",
		Example: `  sonda data query shop -e production '{ listOrder(limit: 5, orderBy: [{createdAt: desc}]) { id status } }'
  sonda data query shop -f order.graphql --var id=0d6c… --var n:=10`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			query, err := queryText(args[1:], file, cmd.InOrStdin())
			if err != nil {
				return err
			}
			variables, err := variablesJSON(varsFile, vars)
			if err != nil {
				return err
			}
			return send(a, cmd, "/v1/services/"+url.PathEscape(args[0])+"/data/query", api.DataQueryRequest{
				Environment: env, Query: query, Variables: variables,
			}, renderDataQuery)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment (optional when only one is available)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "read the query from a file (- for stdin)")
	cmd.Flags().StringVar(&varsFile, "vars", "", "JSON file with variables")
	cmd.Flags().StringArrayVar(&vars, "var", nil, "variable name=text (a string) or name:=json (a number, boolean, list or object) (repeatable)")
	return cmd
}

func queryText(args []string, file string, stdin io.Reader) (string, error) {
	switch {
	case len(args) == 1 && file != "":
		return "", errors.New("give the query as an argument or with --file, not both")
	case len(args) == 1:
		return args[0], nil
	case file == "-":
		data, err := io.ReadAll(stdin)
		return string(data), err
	case file != "":
		data, err := os.ReadFile(file)
		return string(data), err
	}
	return "", errors.New("missing query: give it as an argument or with --file")
}

func variablesJSON(file string, pairs []string) (json.RawMessage, error) {
	vars := map[string]any{}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&vars); err != nil || decoder.More() {
			return nil, fmt.Errorf("--vars: %s must hold one JSON object", file)
		}
		if vars == nil {
			vars = map[string]any{}
		}
	}
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name == "" || name == ":" {
			return nil, fmt.Errorf("--var %q must be name=text or name:=json", pair)
		}
		// name=text is always a string, so IDs and years that look like numbers stay strings.
		jsonName, isJSON := strings.CutSuffix(name, ":")
		if !isJSON {
			vars[name] = value
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(value))
		decoder.UseNumber()
		var parsed any
		if err := decoder.Decode(&parsed); err != nil || decoder.More() {
			return nil, fmt.Errorf("--var %s: %q is not one JSON value", jsonName, value)
		}
		vars[jsonName] = parsed
	}
	if len(vars) == 0 {
		return nil, nil
	}
	return json.Marshal(vars)
}

func renderDataSchema(w io.Writer, resp api.Response[api.DataSchema]) {
	for _, e := range resp.Data.Entities {
		fmt.Fprintln(w, e.Name)
		for _, f := range e.Fields {
			switch {
			case f.Target != "" && f.Many:
				fmt.Fprintf(w, "  %s → [%s]\n", f.Name, f.Target)
			case f.Target != "":
				fmt.Fprintf(w, "  %s → %s\n", f.Name, f.Target)
			default:
				t := f.Type
				if f.List {
					t = "[" + t + "]"
				}
				if !f.Nullable {
					t += "!"
				}
				fmt.Fprintf(w, "  %s: %s\n", f.Name, t)
			}
		}
		if len(e.Unique) > 0 {
			fmt.Fprintf(w, "  unique: %s\n", strings.Join(e.Unique, ", "))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(resp.Data.Enums)) {
		fmt.Fprintf(w, "enum %s: %s\n", name, strings.Join(resp.Data.Enums[name], ", "))
	}
}

func renderDataQuery(w io.Writer, resp api.Response[api.DataQueryResult]) {
	fmt.Fprintf(w, "# %s/%s: %s\n", resp.Meta.Service, resp.Meta.Environment, resp.Data.Query)
	var out bytes.Buffer
	if err := json.Indent(&out, resp.Data.Data, "", "  "); err != nil {
		_, _ = w.Write(resp.Data.Data)
		fmt.Fprintln(w)
		return
	}
	out.WriteByte('\n')
	_, _ = out.WriteTo(w)
}
