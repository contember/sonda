package shape

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/prometheus/common/model"
)

func TestSummarizeSkipsNonFinite(t *testing.T) {
	values := []model.SamplePair{
		{Timestamp: 1000, Value: model.SampleValue(math.NaN())},
		{Timestamp: 2000, Value: 2},
		{Timestamp: 3000, Value: model.SampleValue(math.Inf(1))},
		{Timestamp: 4000, Value: 4},
	}
	s := Summarize(values)
	if s.Count != 2 || *s.Min != 2 || *s.Max != 4 || *s.Avg != 3 || *s.First != 2 || *s.Last != 4 {
		t.Fatalf("summary = %+v", s)
	}
	if empty := Summarize([]model.SamplePair{{Value: model.SampleValue(math.NaN())}}); empty.Count != 0 || empty.Min != nil {
		t.Fatalf("all-NaN summary = %+v", empty)
	}
}

func TestSeriesEncodesNaNAsNull(t *testing.T) {
	matrix := model.Matrix{{
		Metric: model.Metric{"job": "api"},
		Values: []model.SamplePair{{Timestamp: 1000, Value: model.SampleValue(math.NaN())}},
	}}
	series, _ := Series(matrix, 10, true)
	encoded, err := json.Marshal(series)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"labels":{"job":"api"},"summary":{"count":0},"points":[[1,null]]}]`; string(encoded) != want {
		t.Fatalf("got %s", encoded)
	}
}
