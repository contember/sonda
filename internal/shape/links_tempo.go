package shape

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

type tempoPane struct {
	Datasource string            `json:"datasource"`
	Queries    []tempoPaneQuery  `json:"queries"`
	Range      map[string]string `json:"range"`
}

type tempoPaneQuery struct {
	RefID      string            `json:"refId"`
	QueryType  string            `json:"queryType"`
	Query      string            `json:"query"`
	Datasource map[string]string `json:"datasource"`
}

// TempoSourceRef describes where a TraceQL query or a trace lookup ran. The query may be a
// trace ID, which Grafana's TraceQL editor opens as a trace. It links to Grafana Explore
// when Grafana and the source's datasource UID are configured.
func TempoSourceRef(grafana *config.Grafana, src *config.Source, query string, r api.TimeRange) api.SourceRef {
	ref := api.SourceRef{Kind: string(config.SourceTempo), Query: query}
	if grafana == nil || src.GrafanaDatasourceUID == "" {
		return ref
	}
	panes := map[string]tempoPane{
		"sonda": {
			Datasource: src.GrafanaDatasourceUID,
			Queries: []tempoPaneQuery{{
				RefID:      "A",
				QueryType:  "traceql",
				Query:      query,
				Datasource: map[string]string{"type": string(config.SourceTempo), "uid": src.GrafanaDatasourceUID},
			}},
			Range: map[string]string{
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
