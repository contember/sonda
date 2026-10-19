package policy

import (
	"reflect"
	"testing"
	"time"

	"github.com/contember/sonda/api"
)

func TestParseWhere(t *testing.T) {
	tests := []struct {
		in   string
		want Where
	}{
		{"level=error", Where{Field: "level", Value: "error"}},
		{"level!=info", Where{Field: "level", Value: "info", Negate: true}},
		{"msg=a=b", Where{Field: "msg", Value: "a=b"}},
		{"msg=a!=b", Where{Field: "msg", Value: "a!=b"}},
		{"empty=", Where{Field: "empty"}},
		{"@message=x", Where{Field: "@message", Value: "x"}},
		{"$metadata.service-name!=", Where{Field: "$metadata.service-name", Negate: true}},
	}
	for _, tt := range tests {
		got, err := ParseWhere([]string{tt.in})
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("%s: got %+v, want %+v", tt.in, got, tt.want)
		}
	}

	for _, in := range []string{"level", "=error", "!=error", "a b=c", "-x=1", "9x=1", `a"=b`, "a!b=c", "a{}=b"} {
		if _, err := ParseWhere([]string{in}); !isCode(err, api.CodeInvalidRequest) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestParseTraceFilter(t *testing.T) {
	f, err := ParseTraceFilter(api.TraceSearchRequest{
		MinDuration: "500ms",
		MaxDuration: "1m30s",
		Errors:      true,
		Name:        "GET",
		Where:       []string{"http.status_code=500"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := TraceFilter{
		MinDuration: 500 * time.Millisecond,
		MaxDuration: 90 * time.Second,
		Errors:      true,
		Name:        "GET",
		Where:       []Where{{Field: "http.status_code", Value: "500"}},
	}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("got %+v, want %+v", f, want)
	}
	if f, err := ParseTraceFilter(api.TraceSearchRequest{MinDuration: "1d"}); err != nil || f.MinDuration != 24*time.Hour {
		t.Errorf("prometheus duration: %+v, %v", f, err)
	}

	for _, req := range []api.TraceSearchRequest{
		{MinDuration: "soon"},
		{MinDuration: "0s"},
		{MaxDuration: "-1s"},
		{MinDuration: "2s", MaxDuration: "1s"},
		{Where: []string{"no-operator"}},
	} {
		if _, err := ParseTraceFilter(req); !isCode(err, api.CodeInvalidRequest) {
			t.Errorf("%+v: %v", req, err)
		}
	}
}
