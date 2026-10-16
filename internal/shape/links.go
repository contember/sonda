package shape

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

// SourceRef describes where a query ran. It links to Grafana Explore when Grafana and the
// source's datasource UID are configured.
func SourceRef(grafana *config.Grafana, src *config.Source, query string, r api.TimeRange) api.SourceRef {
	ref := api.SourceRef{Kind: string(src.Type), Query: query}
	if grafana == nil || src.GrafanaDatasourceUID == "" {
		return ref
	}
	datasource := map[string]string{"type": string(src.Type), "uid": src.GrafanaDatasourceUID}
	panes := map[string]any{
		"sonda": map[string]any{
			"datasource": src.GrafanaDatasourceUID,
			"queries":    []any{map[string]any{"refId": "A", "expr": query, "datasource": datasource}},
			"range": map[string]string{
				"from": strconv.FormatInt(r.From.UnixMilli(), 10),
				"to":   strconv.FormatInt(r.To.UnixMilli(), 10),
			},
		},
	}
	encoded, err := json.Marshal(panes)
	if err != nil {
		return ref
	}
	params := url.Values{"schemaVersion": {"1"}, "panes": {string(encoded)}}
	ref.URL = strings.TrimRight(grafana.URL, "/") + "/explore?" + params.Encode()
	return ref
}
