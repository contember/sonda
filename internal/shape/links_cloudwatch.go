package shape

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

const cloudWatchKind = "cloudwatch"

// CloudWatchLogsSourceRef links to the Logs Insights console with the query, log groups and
// range. The console keeps its state in an undocumented, jsurl-encoded fragment.
func CloudWatchLogsSourceRef(src *config.Source, groups []string, query string, r api.TimeRange) api.SourceRef {
	ref := api.SourceRef{Kind: cloudWatchKind, Query: query}
	if src.AWS == nil {
		return ref
	}
	const isoMillis = "2006-01-02T15:04:05.000Z"
	var detail strings.Builder
	detail.WriteString("~(end~" + jsurlString(r.To.UTC().Format(isoMillis)))
	detail.WriteString("~start~" + jsurlString(r.From.UTC().Format(isoMillis)))
	detail.WriteString("~timeType~'ABSOLUTE~tz~'UTC~editorString~" + jsurlString(query))
	detail.WriteString("~source~(")
	for _, group := range groups {
		detail.WriteString("~" + jsurlString(group))
	}
	detail.WriteString("))")

	region := src.AWS.Region
	fragment := "logsV2:logs-insights" + consoleEscape("?queryDetail="+detail.String())
	ref.URL = "https://" + region + ".console.aws.amazon.com/cloudwatch/home?region=" + url.QueryEscape(region) + "#" + fragment
	return ref
}

// CloudWatchMetricSourceRef describes a metric query. It has no link.
func CloudWatchMetricSourceRef(query string) api.SourceRef {
	return api.SourceRef{Kind: cloudWatchKind, Query: query}
}

// jsurlString writes a jsurl string: a quote, then the UTF-8 bytes with every byte outside
// [A-Za-z0-9_.-] written as *xx, which also escapes the jsurl syntax characters ~'()*!.
func jsurlString(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		if c := s[i]; isJsurlPlain(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "*%02x", c)
		}
	}
	return b.String()
}

func isJsurlPlain(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// consoleEscape percent-encodes like encodeURIComponent and writes % as $, as the console does
// for its fragment.
func consoleEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; isJsurlPlain(c) || strings.IndexByte("!~*'()", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "$%02X", c)
		}
	}
	return b.String()
}
