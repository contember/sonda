package shape

import (
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

func TestSourceRef(t *testing.T) {
	r := api.TimeRange{From: time.UnixMilli(1767225600000).UTC(), To: time.UnixMilli(1767229200000).UTC()}
	query := `sum(rate({app="api"} |= "a&b" [5m]))`
	tests := []struct {
		sourceType config.SourceType
		url        string
	}{
		{config.SourceLoki, "https://grafana.example/explore?panes=%7B%22sonda%22%3A%7B%22datasource%22%3A%22uid-1%22%2C%22queries%22%3A%5B%7B%22datasource%22%3A%7B%22type%22%3A%22loki%22%2C%22uid%22%3A%22uid-1%22%7D%2C%22expr%22%3A%22sum%28rate%28%7Bapp%3D%5C%22api%5C%22%7D+%7C%3D+%5C%22a%5Cu0026b%5C%22+%5B5m%5D%29%29%22%2C%22refId%22%3A%22A%22%7D%5D%2C%22range%22%3A%7B%22from%22%3A%221767225600000%22%2C%22to%22%3A%221767229200000%22%7D%7D%7D&schemaVersion=1"},
		{config.SourcePrometheus, "https://grafana.example/explore?panes=%7B%22sonda%22%3A%7B%22datasource%22%3A%22uid-1%22%2C%22queries%22%3A%5B%7B%22datasource%22%3A%7B%22type%22%3A%22prometheus%22%2C%22uid%22%3A%22uid-1%22%7D%2C%22expr%22%3A%22sum%28rate%28%7Bapp%3D%5C%22api%5C%22%7D+%7C%3D+%5C%22a%5Cu0026b%5C%22+%5B5m%5D%29%29%22%2C%22refId%22%3A%22A%22%7D%5D%2C%22range%22%3A%7B%22from%22%3A%221767225600000%22%2C%22to%22%3A%221767229200000%22%7D%7D%7D&schemaVersion=1"},
	}
	for _, tt := range tests {
		src := &config.Source{Name: "x", Type: tt.sourceType, GrafanaDatasourceUID: "uid-1"}
		ref := SourceRef(&config.Grafana{URL: "https://grafana.example/"}, src, query, r)
		if want := (api.SourceRef{Kind: string(tt.sourceType), Query: query, URL: tt.url}); ref != want {
			t.Errorf("%s:\n got  %+v\n want %+v", tt.sourceType, ref, want)
		}
	}
}
