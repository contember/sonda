package shape

import (
	"net/url"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

// CloudflareSourceRef links to the account's Workers Observability dashboard. The dashboard
// cannot be deep-linked to a query, so the query is returned for copying.
func CloudflareSourceRef(src *config.Source, query string, _ api.TimeRange) api.SourceRef {
	return api.SourceRef{
		Kind:  string(src.Type),
		URL:   "https://dash.cloudflare.com/" + url.PathEscape(src.CloudflareAccountID) + "/workers-and-pages/observability",
		Query: query,
	}
}
