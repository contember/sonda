package shape

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

// explorePane is a Grafana Explore pane. The fields of its structs are in alphabetical
// order, the order of the JSON maps they replaced, so existing links stay unchanged.
type explorePane struct {
	Datasource string         `json:"datasource"`
	Queries    []exploreQuery `json:"queries"`
	Range      exploreRange   `json:"range"`
}

type exploreQuery struct {
	Datasource exploreDatasource `json:"datasource"`
	Expr       string            `json:"expr,omitempty"`
	Query      string            `json:"query,omitempty"`
	QueryType  string            `json:"queryType,omitempty"`
	RefID      string            `json:"refId"`
}

type exploreDatasource struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

type exploreRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// SourceRef describes where a query ran. It links to Grafana Explore when Grafana and the
// source's datasource UID are configured.
func SourceRef(grafana *config.Grafana, src *config.Source, query string, r api.TimeRange) api.SourceRef {
	return exploreRef(grafana, src, query, r, exploreQuery{Expr: query})
}

// exploreRef describes where a query ran and links to a Grafana Explore pane that runs
// paneQuery, when Grafana and the source's datasource UID are configured.
func exploreRef(grafana *config.Grafana, src *config.Source, query string, r api.TimeRange, paneQuery exploreQuery) api.SourceRef {
	ref := api.SourceRef{Kind: string(src.Type), Query: query}
	if grafana == nil || src.GrafanaDatasourceUID == "" {
		return ref
	}
	paneQuery.RefID = "A"
	paneQuery.Datasource = exploreDatasource{Type: string(src.Type), UID: src.GrafanaDatasourceUID}
	panes := map[string]explorePane{
		"sonda": {
			Datasource: src.GrafanaDatasourceUID,
			Queries:    []exploreQuery{paneQuery},
			Range: exploreRange{
				From: strconv.FormatInt(r.From.UnixMilli(), 10),
				To:   strconv.FormatInt(r.To.UnixMilli(), 10),
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
