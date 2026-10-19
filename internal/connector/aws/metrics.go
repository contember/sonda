package aws

import (
	"context"
	"maps"
	"math"
	"slices"
	"sort"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/policy"
)

const metricQueryID = "m0"

// MetricData fetches one statistic of one metric as a single series labeled with the
// dimensions and the statistic, and returns the period it used. It never sends an Expression:
// metric math, SEARCH and Metrics Insights can read other namespaces.
func (c *Client) MetricData(ctx context.Context, q policy.CloudWatchMetric, r api.TimeRange, step time.Duration) (model.Matrix, time.Duration, error) {
	dimensions := q.Dimensions()
	used := period(step, r.To.Sub(r.From))
	input := &cloudwatch.GetMetricDataInput{
		StartTime: sdkaws.Time(r.From),
		EndTime:   sdkaws.Time(r.To),
		ScanBy:    types.ScanByTimestampAscending,
		MetricDataQueries: []types.MetricDataQuery{{
			Id: sdkaws.String(metricQueryID),
			MetricStat: &types.MetricStat{
				Metric: &types.Metric{
					Namespace:  sdkaws.String(q.Namespace()),
					MetricName: sdkaws.String(q.Metric()),
					Dimensions: metricDimensions(dimensions),
				},
				Period: sdkaws.Int32(int32(used / time.Second)),
				Stat:   sdkaws.String(q.Stat()),
			},
			ReturnData: sdkaws.Bool(true),
		}},
	}
	metric := model.Metric{"stat": model.LabelValue(q.Stat())}
	for name, value := range dimensions {
		metric[model.LabelName(name)] = model.LabelValue(value)
	}
	stream := &model.SampleStream{Metric: metric}
	paginator := cloudwatch.NewGetMetricDataPaginator(c.metrics, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, 0, c.apiError("GetMetricData", err)
		}
		for _, result := range page.MetricDataResults {
			if err := c.appendResult(stream, result); err != nil {
				return nil, 0, err
			}
		}
	}
	if len(stream.Values) == 0 {
		return model.Matrix{}, used, nil
	}
	sort.Slice(stream.Values, func(i, j int) bool { return stream.Values[i].Timestamp < stream.Values[j].Timestamp })
	return model.Matrix{stream}, used, nil
}

func (c *Client) appendResult(stream *model.SampleStream, result types.MetricDataResult) error {
	switch result.StatusCode {
	case types.StatusCodeForbidden:
		return apierr.Upstream("source %s: AWS denied GetMetricData; check the permissions of Sonda's AWS credentials", c.source.Name)
	case types.StatusCodeInternalError:
		return apierr.Upstream("source %s: GetMetricData failed with an internal error", c.source.Name)
	}
	if len(result.Timestamps) != len(result.Values) {
		return apierr.Upstream("source %s returned %d timestamps for %d values", c.source.Name, len(result.Timestamps), len(result.Values))
	}
	for i, t := range result.Timestamps {
		stream.Values = append(stream.Values, model.SamplePair{Timestamp: model.TimeFromUnixNano(t.UnixNano()), Value: model.SampleValue(result.Values[i])})
	}
	return nil
}

// maxPeriod is the longest period in whole minutes that GetMetricData's int32 seconds hold.
const maxPeriod = math.MaxInt32 / 60 * 60 * time.Second

// period rounds the step up to whole minutes, the resolution every metric supports. It is at
// most the range rounded down to whole minutes, and at least one minute.
func period(step, rangeLength time.Duration) time.Duration {
	rounded := (min(step, maxPeriod) + time.Minute - 1) / time.Minute * time.Minute
	return max(min(rounded, rangeLength.Truncate(time.Minute)), time.Minute)
}

func metricDimensions(dimensions map[string]string) []types.Dimension {
	out := make([]types.Dimension, 0, len(dimensions))
	for _, name := range slices.Sorted(maps.Keys(dimensions)) {
		out = append(out, types.Dimension{Name: sdkaws.String(name), Value: sdkaws.String(dimensions[name])})
	}
	return out
}

// MetricNames lists the names of the namespace's metrics that have all scope dimensions.
func (c *Client) MetricNames(ctx context.Context, scope authz.CloudWatchMetricScope) ([]string, error) {
	dimensions := scope.Dimensions()
	filters := make([]types.DimensionFilter, 0, len(dimensions))
	for _, name := range slices.Sorted(maps.Keys(dimensions)) {
		filters = append(filters, types.DimensionFilter{Name: sdkaws.String(name), Value: sdkaws.String(dimensions[name])})
	}
	paginator := cloudwatch.NewListMetricsPaginator(c.metrics, &cloudwatch.ListMetricsInput{
		Namespace:  sdkaws.String(scope.Namespace()),
		Dimensions: filters,
	})
	seen := map[string]bool{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, c.apiError("ListMetrics", err)
		}
		for _, metric := range page.Metrics {
			if metric.MetricName != nil {
				seen[*metric.MetricName] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(seen)), nil
}
