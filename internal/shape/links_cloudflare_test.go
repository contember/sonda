package shape

import (
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

func TestCloudflareSourceRef(t *testing.T) {
	src := &config.Source{Name: "cf", Type: config.SourceCloudflare, CloudflareAccountID: "abc123"}
	got := CloudflareSourceRef(src, `{"view":"events"}`, api.TimeRange{})
	want := api.SourceRef{
		Kind:  "cloudflare",
		URL:   "https://dash.cloudflare.com/abc123/workers-and-pages/observability",
		Query: `{"view":"events"}`,
	}
	if got != want {
		t.Errorf("CloudflareSourceRef = %+v, want %+v", got, want)
	}
}
