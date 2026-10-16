// Package shape turns connector results into compact API responses. It has no I/O.
package shape

import (
	"math"
	"sort"

	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
)

// Series converts a matrix, sorted by labels, keeping at most maxSeries series.
func Series(matrix model.Matrix, maxSeries int, withPoints bool) (series []api.Series, truncated bool) {
	sort.Slice(matrix, func(i, j int) bool { return matrix[i].Metric.Before(matrix[j].Metric) })
	if len(matrix) > maxSeries {
		matrix, truncated = matrix[:maxSeries], true
	}
	series = make([]api.Series, 0, len(matrix))
	for _, stream := range matrix {
		s := api.Series{Labels: labelMap(stream.Metric), Summary: Summarize(stream.Values)}
		if withPoints {
			s.Points = make([]api.Point, len(stream.Values))
			for i, v := range stream.Values {
				s.Points[i] = api.Point{Time: v.Timestamp.Unix(), Value: float64(v.Value)}
			}
		}
		series = append(series, s)
	}
	return series, truncated
}

// Summarize computes statistics over finite values only. NaN appears for example in a
// ratio with no traffic and would make every statistic NaN.
func Summarize(values []model.SamplePair) api.SeriesSummary {
	var summary api.SeriesSummary
	var sum, minimum, maximum, first, last float64
	for _, pair := range values {
		v := float64(pair.Value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		if summary.Count == 0 {
			first, minimum, maximum = v, v, v
		}
		minimum, maximum = math.Min(minimum, v), math.Max(maximum, v)
		last = v
		sum += v
		summary.Count++
	}
	if summary.Count > 0 {
		avg := sum / float64(summary.Count)
		summary.Min, summary.Max, summary.Avg = &minimum, &maximum, &avg
		summary.First, summary.Last = &first, &last
	}
	return summary
}

func labelMap(metric model.Metric) map[string]string {
	labels := make(map[string]string, len(metric))
	for name, value := range metric {
		labels[string(name)] = string(value)
	}
	return labels
}
