package shape

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

func TestTempoSourceRef(t *testing.T) {
	r := api.TimeRange{From: time.UnixMilli(1000).UTC(), To: time.UnixMilli(2000).UTC()}
	src := &config.Source{Name: "tempo", Type: config.SourceTempo}
	query := `{ resource.service.name = "api" }`

	if ref := TempoSourceRef(&config.Grafana{URL: "https://grafana"}, src, query, r); ref != (api.SourceRef{Kind: "tempo", Query: query}) {
		t.Errorf("without a datasource UID: %+v", ref)
	}
	src.GrafanaDatasourceUID = "tempo-uid"
	if ref := TempoSourceRef(nil, src, query, r); ref.URL != "" {
		t.Errorf("without Grafana: %+v", ref)
	}

	ref := TempoSourceRef(&config.Grafana{URL: "https://grafana/"}, src, query, r)
	link, err := url.Parse(ref.URL)
	if err != nil || !strings.HasPrefix(ref.URL, "https://grafana/explore?") || link.Query().Get("schemaVersion") != "1" {
		t.Fatalf("link %q: %v", ref.URL, err)
	}
	var panes map[string]tempoPane
	if err := json.Unmarshal([]byte(link.Query().Get("panes")), &panes); err != nil {
		t.Fatal(err)
	}
	want := map[string]tempoPane{"sonda": {
		Datasource: "tempo-uid",
		Queries: []tempoPaneQuery{{
			RefID: "A", QueryType: "traceql", Query: query,
			Datasource: map[string]string{"type": "tempo", "uid": "tempo-uid"},
		}},
		Range: map[string]string{"from": "1000", "to": "2000"},
	}}
	if !reflect.DeepEqual(panes, want) {
		t.Errorf("panes %+v, want %+v", panes, want)
	}
}
