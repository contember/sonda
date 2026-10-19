package shape

import (
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/config"
)

func TestCloudWatchLogsSourceRef(t *testing.T) {
	src := &config.Source{Name: "aws", Type: config.SourceAWS, AWS: &config.AWSSource{Region: "eu-west-1"}}
	r := api.TimeRange{
		From: time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 10, 19, 9, 30, 0, 500_000_000, time.UTC),
	}
	query := "fields @timestamp, @message\n| filter @message like 'a~b' | filter x = \"(č)*!$%\""
	groups := []string{"/aws/rds/cluster/engine/postgresql", "/aws/lambda/x"}

	ref := CloudWatchLogsSourceRef(src, groups, query, r)
	if ref.Kind != "cloudwatch" || ref.Query != query {
		t.Errorf("ref = %+v", ref)
	}
	const prefix = "https://eu-west-1.console.aws.amazon.com/cloudwatch/home?region=eu-west-1#logsV2:logs-insights$3FqueryDetail$3D~(end~'"
	if !strings.HasPrefix(ref.URL, prefix) {
		t.Fatalf("URL = %s\nwant prefix %s", ref.URL, prefix)
	}
	if strings.ContainsAny(strings.SplitN(ref.URL, "#", 2)[1], "%# \n\"") {
		t.Errorf("fragment has characters a URL cannot carry: %s", ref.URL)
	}

	got := decodeQueryDetail(t, ref.URL)
	want := map[string]any{
		"end":          "2026-10-19T09:30:00.500Z",
		"start":        "2026-10-19T08:00:00.000Z",
		"timeType":     "ABSOLUTE",
		"tz":           "UTC",
		"editorString": query,
		"source":       []any{groups[0], groups[1]},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decoded %#v\nwant    %#v", got, want)
	}
}

func TestCloudWatchLogsSourceRefWithoutRegion(t *testing.T) {
	ref := CloudWatchLogsSourceRef(&config.Source{Type: config.SourceAWS}, nil, "fields @message", api.TimeRange{})
	if ref.URL != "" || ref.Query != "fields @message" {
		t.Errorf("ref = %+v", ref)
	}
}

// decodeQueryDetail reverses the console encoding: $ to %, percent-decoding, then jsurl.
func decodeQueryDetail(t *testing.T, link string) any {
	t.Helper()
	fragment := strings.SplitN(link, "#", 2)[1]
	decoded, err := url.PathUnescape(strings.ReplaceAll(fragment, "$", "%"))
	if err != nil {
		t.Fatal(err)
	}
	body, ok := strings.CutPrefix(decoded, "logsV2:logs-insights?queryDetail=~")
	if !ok {
		t.Fatalf("unexpected fragment %q", decoded)
	}
	d := &jsurlDecoder{text: body}
	value := d.value(t)
	if d.pos != len(d.text) {
		t.Fatalf("trailing jsurl %q", d.text[d.pos:])
	}
	return value
}

type jsurlDecoder struct {
	text string
	pos  int
}

func (d *jsurlDecoder) value(t *testing.T) any {
	t.Helper()
	switch d.text[d.pos] {
	case '\'':
		d.pos++
		return d.raw(t)
	case '(':
		d.pos++
		if d.text[d.pos] == '~' {
			var list []any
			for d.text[d.pos] == '~' {
				d.pos++
				list = append(list, d.value(t))
			}
			d.expect(t, ')')
			return list
		}
		object := map[string]any{}
		for {
			key := d.raw(t)
			d.expect(t, '~')
			object[key] = d.value(t)
			if d.text[d.pos] == ')' {
				d.pos++
				return object
			}
			d.expect(t, '~')
		}
	}
	t.Fatalf("unexpected jsurl at %q", d.text[d.pos:])
	return nil
}

// raw reads string characters up to ~ or ) and decodes *xx bytes.
func (d *jsurlDecoder) raw(t *testing.T) string {
	t.Helper()
	var b []byte
	for d.pos < len(d.text) && d.text[d.pos] != '~' && d.text[d.pos] != ')' {
		c := d.text[d.pos]
		if c == '*' {
			n, err := strconv.ParseUint(d.text[d.pos+1:d.pos+3], 16, 8)
			if err != nil {
				t.Fatal(err)
			}
			b = append(b, byte(n))
			d.pos += 3
			continue
		}
		if strings.IndexByte("'(!", c) >= 0 {
			t.Fatalf("unescaped %q in jsurl string", c)
		}
		b = append(b, c)
		d.pos++
	}
	return string(b)
}

func (d *jsurlDecoder) expect(t *testing.T, c byte) {
	t.Helper()
	if d.pos >= len(d.text) || d.text[d.pos] != c {
		t.Fatalf("expected %q at %q", c, d.text[d.pos:])
	}
	d.pos++
}
