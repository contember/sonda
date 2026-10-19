package aws

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/dustin/go-humanize"
	"github.com/prometheus/common/model"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/insights"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/telemetry"
)

const (
	stopTimeout = 5 * time.Second
	// fieldsWindow is half of the window GetLogGroupFields samples around its time.
	fieldsWindow = 8 * time.Minute
	// insightsTime is the format of @timestamp and bin() values; a fraction may follow.
	insightsTime = "2006-01-02 15:04:05"
)

// InsightsResult holds the rows of a finished query. Series is non-nil exactly when the query
// has a stats stage; otherwise Streams holds the rows as log lines.
type InsightsResult struct {
	Streams []telemetry.LogStream
	Series  model.Matrix
	// Total is the number of log events that matched the query, before any limit.
	Total int64
}

// Field is a field of the service's log events and the percentage of events that have it.
type Field struct {
	Name    string
	Percent int
}

// Insights runs a query over the scope's log groups and returns at most limit rows. It checks
// that AWS scanned no other log group before it returns any row.
func (c *Client) Insights(ctx context.Context, scope authz.LogGroupScope, q policy.InsightsQuery, r api.TimeRange, limit int) (InsightsResult, error) {
	groups := scope.LogGroups()
	started, err := c.logs.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupIdentifiers: groups,
		QueryString:         sdkaws.String(q.String()),
		QueryLanguage:       types.QueryLanguageCwli,
		StartTime:           sdkaws.Int64(r.From.Unix()),
		EndTime:             sdkaws.Int64(r.To.Unix()),
		Limit:               sdkaws.Int32(int32(min(max(limit, 1), insights.MaxRows))),
	})
	if err != nil {
		return InsightsResult{}, c.apiError("StartQuery", err)
	}
	if started.QueryId == nil {
		return InsightsResult{}, apierr.Upstream("source %s: StartQuery returned no query ID", c.source.Name)
	}
	id := *started.QueryId
	out, err := c.await(ctx, id)
	if err != nil {
		return InsightsResult{}, err
	}
	if err := c.remainingPages(ctx, id, out); err != nil {
		return InsightsResult{}, err
	}
	if err := c.checkScannedGroups(ctx, id, groups); err != nil {
		return InsightsResult{}, err
	}
	return c.result(out, q, r)
}

// await polls until the query completes. On any other outcome it stops the query, because a
// running query keeps scanning, and scanning is billed.
func (c *Client) await(ctx context.Context, id string) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	complete := false
	defer func() {
		if !complete {
			c.stopQuery(ctx, id)
		}
	}()
	delay := c.firstPoll
	for {
		out, err := c.logs.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: sdkaws.String(id)})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, c.apiError("GetQueryResults", err)
		}
		switch out.Status {
		case types.QueryStatusComplete:
			complete = true
			return out, nil
		case types.QueryStatusScheduled, types.QueryStatusRunning:
		default:
			return nil, apierr.Upstream("source %s: Logs Insights query ended with status %s", c.source.Name, out.Status)
		}
		if limit := c.source.AWS.MaxScanBytes; out.Statistics != nil && out.Statistics.BytesScanned > float64(limit) {
			return nil, apierr.New(api.CodeLimitExceeded, "query scanned more than %s", humanize.Bytes(uint64(limit)))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, c.maxPoll)
	}
}

// remainingPages appends the result pages after the first one to out.
func (c *Client) remainingPages(ctx context.Context, id string, out *cloudwatchlogs.GetQueryResultsOutput) error {
	for token := out.NextToken; token != nil && len(out.Results) < insights.MaxRows; {
		page, err := c.logs.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: sdkaws.String(id), NextToken: token})
		if err != nil {
			return c.apiError("GetQueryResults", err)
		}
		if len(page.Results) == 0 {
			return nil
		}
		out.Results = append(out.Results, page.Results...)
		token = page.NextToken
	}
	return nil
}

// stopQuery uses a fresh context, so it also stops a query whose request was cancelled. A
// failure is ignored: the query then runs until AWS ends it, and the caller already has an error.
func (c *Client) stopQuery(ctx context.Context, id string) {
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopTimeout)
	defer cancel()
	_, _ = c.logs.StopQuery(stopCtx, &cloudwatchlogs.StopQueryInput{QueryId: sdkaws.String(id)})
}

// checkScannedGroups verifies that AWS read only the scope's log groups, in case the query
// selected others in a way the lexer does not know. A violation is an internal error, so its
// details go to the server log only.
func (c *Client) checkScannedGroups(ctx context.Context, id string, groups []string) error {
	paginator := cloudwatchlogs.NewListLogGroupsForQueryPaginator(c.logs, &cloudwatchlogs.ListLogGroupsForQueryInput{QueryId: sdkaws.String(id)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return c.apiError("ListLogGroupsForQuery", err)
		}
		for _, identifier := range page.LogGroupIdentifiers {
			if !slices.Contains(groups, logGroupName(identifier)) {
				return fmt.Errorf("source %s: Logs Insights query %s scanned log group %q outside the scope %v", c.source.Name, id, identifier, groups)
			}
		}
	}
	return nil
}

// logGroupName returns the name of a log group identifier: a name, or an ARN like
// arn:aws:logs:region:account:log-group:name, optionally ending in :*.
func logGroupName(identifier string) string {
	if !strings.HasPrefix(identifier, "arn:") {
		return identifier
	}
	_, name, found := strings.Cut(identifier, ":log-group:")
	if !found {
		return identifier
	}
	return strings.TrimSuffix(name, ":*")
}

type resultField struct {
	name, value string
}

func (c *Client) result(out *cloudwatchlogs.GetQueryResultsOutput, q policy.InsightsQuery, r api.TimeRange) (InsightsResult, error) {
	var result InsightsResult
	if out.Statistics != nil {
		result.Total = int64(out.Statistics.RecordsMatched)
	}
	rows := make([][]resultField, 0, len(out.Results))
	for _, raw := range out.Results {
		var row []resultField
		for _, f := range raw {
			if f.Field == nil || *f.Field == "@ptr" {
				continue
			}
			row = append(row, resultField{name: *f.Field, value: sdkaws.ToString(f.Value)})
		}
		rows = append(rows, row)
	}
	var err error
	switch {
	case q.Aggregates():
		result.Series, err = c.statsSeries(rows, r)
	case len(rows) > 0 && !slices.ContainsFunc(rows, func(row []resultField) bool { return !isEvent(row) }):
		result.Streams, err = c.eventStreams(rows)
	default:
		result.Streams, err = c.rowLines(rows, r)
	}
	return result, err
}

func binColumn(row []resultField) int {
	return slices.IndexFunc(row, func(f resultField) bool { return strings.HasPrefix(f.name, "bin(") })
}

func isEvent(row []resultField) bool {
	_, hasTime := field(row, "@timestamp")
	_, hasMessage := field(row, "@message")
	return hasTime && hasMessage
}

func field(row []resultField, name string) (string, bool) {
	i := slices.IndexFunc(row, func(f resultField) bool { return f.name == name })
	if i < 0 {
		return "", false
	}
	return row[i].value, true
}

// eventStreams groups log events by their log stream and log group.
func (c *Client) eventStreams(rows [][]resultField) ([]telemetry.LogStream, error) {
	var streams []telemetry.LogStream
	index := map[[2]string]int{}
	for _, row := range rows {
		ts, _ := field(row, "@timestamp")
		t, err := c.parseTime(ts)
		if err != nil {
			return nil, err
		}
		message, _ := field(row, "@message")
		logStream, hasStream := field(row, "@logStream")
		logGroup, hasGroup := field(row, "@log")
		key := [2]string{logStream, logGroup}
		i, ok := index[key]
		if !ok {
			labels := map[string]string{}
			if hasStream {
				labels["@logStream"] = logStream
			}
			if hasGroup {
				labels["@log"] = logGroup
			}
			i = len(streams)
			index[key] = i
			streams = append(streams, telemetry.LogStream{Labels: labels})
		}
		streams[i].Entries = append(streams[i].Entries, telemetry.LogEntry{Time: t, Line: message})
	}
	return streams, nil
}

// rowLines renders rows that are not log events, like a fields stage without @message, as
// compact field=value lines. A row without @timestamp is stamped with the end of the range.
func (c *Client) rowLines(rows [][]resultField, r api.TimeRange) ([]telemetry.LogStream, error) {
	stream := telemetry.LogStream{Labels: map[string]string{}}
	for _, row := range rows {
		t := r.To
		if ts, ok := field(row, "@timestamp"); ok {
			parsed, err := c.parseTime(ts)
			if err != nil {
				return nil, err
			}
			t = parsed
		}
		parts := make([]string, len(row))
		for i, f := range row {
			parts[i] = f.name + "=" + compactValue(f.value)
		}
		stream.Entries = append(stream.Entries, telemetry.LogEntry{Time: t, Line: strings.Join(parts, " ")})
	}
	if len(stream.Entries) == 0 {
		return nil, nil
	}
	return []telemetry.LogStream{stream}, nil
}

func compactValue(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\n\"=") {
		return strconv.Quote(value)
	}
	return value
}

// statsSeries turns stats rows into series. A row's time is its bin() bucket, or the end of
// the range without bin(), as the statistic covers the whole range. Numeric columns become
// series named by the column; other columns are the labels of the group. A numeric group-by
// field therefore shows as a series of its own.
func (c *Client) statsSeries(rows [][]resultField, r api.TimeRange) (model.Matrix, error) {
	streams := map[model.Fingerprint]*model.SampleStream{}
	for _, row := range rows {
		t := r.To
		column := binColumn(row)
		if column >= 0 {
			parsed, err := c.parseTime(row[column].value)
			if err != nil {
				return nil, err
			}
			t = parsed
		}
		labels := model.Metric{}
		values := map[string]float64{}
		for i, f := range row {
			if i == column {
				continue
			}
			if v, err := strconv.ParseFloat(f.value, 64); err == nil {
				values[f.name] = v
			} else {
				labels[model.LabelName(f.name)] = model.LabelValue(f.value)
			}
		}
		for name, v := range values {
			metric := labels.Clone()
			metric[model.MetricNameLabel] = model.LabelValue(name)
			fingerprint := metric.Fingerprint()
			stream, ok := streams[fingerprint]
			if !ok {
				stream = &model.SampleStream{Metric: metric}
				streams[fingerprint] = stream
			}
			stream.Values = append(stream.Values, model.SamplePair{Timestamp: model.TimeFromUnixNano(t.UnixNano()), Value: model.SampleValue(v)})
		}
	}
	matrix := make(model.Matrix, 0, len(streams))
	for _, stream := range streams {
		sort.Slice(stream.Values, func(i, j int) bool { return stream.Values[i].Timestamp < stream.Values[j].Timestamp })
		matrix = append(matrix, stream)
	}
	return matrix, nil
}

func (c *Client) parseTime(value string) (time.Time, error) {
	t, err := time.ParseInLocation(insightsTime, value, time.UTC)
	if err != nil {
		return time.Time{}, apierr.Upstream("source %s returned an invalid timestamp %q", c.source.Name, value)
	}
	return t, nil
}

// LogFields lists the fields of the scope's log groups near the end of the range, with the
// highest percentage any group reports.
func (c *Client) LogFields(ctx context.Context, scope authz.LogGroupScope, r api.TimeRange) ([]Field, error) {
	at := r.To.Add(-fieldsWindow).Unix()
	percent := map[string]int{}
	for _, group := range scope.LogGroups() {
		out, err := c.logs.GetLogGroupFields(ctx, &cloudwatchlogs.GetLogGroupFieldsInput{
			LogGroupIdentifier: sdkaws.String(group),
			Time:               sdkaws.Int64(at),
		})
		if err != nil {
			return nil, c.apiError("GetLogGroupFields", err)
		}
		for _, f := range out.LogGroupFields {
			if f.Name != nil {
				percent[*f.Name] = max(percent[*f.Name], int(f.Percent))
			}
		}
	}
	fields := make([]Field, 0, len(percent))
	for name, p := range percent {
		fields = append(fields, Field{Name: name, Percent: p})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	return fields, nil
}
