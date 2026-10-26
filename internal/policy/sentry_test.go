package policy

import (
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
)

func TestSentrySpanSearch(t *testing.T) {
	f := TraceFilter{
		MinDuration: 1500 * time.Millisecond,
		MaxDuration: 2 * time.Second,
		Errors:      true,
		Name:        `GET "/a*"`,
		Where:       []Where{{Field: "span.op", Value: "db"}, {Field: "release", Value: "1.2", Negate: true}},
	}
	q, err := SentrySpanSearch(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `span.duration:>=1500ms span.duration:<=2000ms has:span.status !span.status:ok span.description:"*GET \"/a\*\"*" span.op:"db" !release:"1.2"`
	if q.String() != want {
		t.Errorf("query\n%s\nwant\n%s", q, want)
	}
	if q, _ := SentrySpanSearch(TraceFilter{}); q.String() != "" {
		t.Errorf("empty filter = %q", q)
	}
	_, err = SentrySpanSearch(TraceFilter{Where: []Where{{Field: "span.op", Value: `db\`}}})
	if e, ok := apierr.As(err); !ok || e.Code != api.CodeInvalidRequest {
		t.Errorf("backslash: %v", err)
	}
}

func TestSentryTraceQueries(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	if q, err := SentryTraceByID(id); err != nil || q.String() != "trace:"+id {
		t.Errorf("by ID = %q, %v", q, err)
	}
	if _, err := SentryTraceByID("0123456789abcdef"); err == nil {
		t.Error("16-character trace ID accepted")
	}
	q := SentryTraceSegments([]string{id, "x] OR project:other", id})
	if want := "is_transaction:true trace:[" + id + "," + id + "]"; q.String() != want {
		t.Errorf("segments = %q", q)
	}
}
