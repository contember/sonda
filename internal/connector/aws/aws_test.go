package aws

import (
	"context"
	"errors"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/policy"
)

const (
	engineGroup = "/aws/rds/cluster/engine/postgresql"
	auditGroup  = "/aws/rds/cluster/engine/audit"
	maxScan     = 1000
)

func scopes(t *testing.T) (*config.Config, authz.LogGroupScope, authz.CloudWatchMetricScope) {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  aws: { type: aws, region: eu-west-1, max_scan_bytes: "1000" }
services:
  db:
    environments:
      production:
        logs: { source: aws, log_groups: [`+engineGroup+`, `+auditGroup+`] }
        metrics: { source: aws, namespace: AWS/RDS, dimensions: { DBClusterIdentifier: engine, Role: WRITER } }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	a := authz.New(cfg, nil)
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Service: "db", Environment: "production", Capability: api.CapabilityLogs},
		{Service: "db", Environment: "production", Capability: api.CapabilityMetrics},
	}}
	logScope, err := a.LogScope(identity, "db", "production")
	if err != nil {
		t.Fatal(err)
	}
	metricScope, err := a.MetricScope(identity, "db", "production")
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := logScope.CloudWatch()
	metrics, _ := metricScope.CloudWatch()
	return cfg, groups, metrics
}

var testRange = api.TimeRange{
	From: time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC),
	To:   time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC),
}

type fakeLogs struct {
	mu sync.Mutex
	// polls are returned in order; the last one repeats.
	polls    []*cloudwatchlogs.GetQueryResultsOutput
	startErr error
	pollErr  error
	// onPoll runs before each GetQueryResults call with its 1-based number.
	onPoll  func(n int)
	scanned [][]string
	fields  map[string][]types.LogGroupField

	started    []*cloudwatchlogs.StartQueryInput
	pollCount  int
	stopped    []string
	stopCtxErr error
	listed     int
	fieldCalls []*cloudwatchlogs.GetLogGroupFieldsInput
}

func (f *fakeLogs) StartQuery(_ context.Context, in *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, in)
	if f.startErr != nil {
		return nil, f.startErr
	}
	return &cloudwatchlogs.StartQueryOutput{QueryId: sdkaws.String("q-1")}, nil
}

func (f *fakeLogs) GetQueryResults(ctx context.Context, in *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.mu.Lock()
	f.pollCount++
	n := f.pollCount
	f.mu.Unlock()
	if f.onPoll != nil {
		f.onPoll(n)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.pollErr != nil {
		return nil, f.pollErr
	}
	return f.polls[min(n, len(f.polls))-1], nil
}

func (f *fakeLogs) StopQuery(ctx context.Context, in *cloudwatchlogs.StopQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, *in.QueryId)
	f.stopCtxErr = ctx.Err()
	return &cloudwatchlogs.StopQueryOutput{Success: true}, nil
}

func (f *fakeLogs) ListLogGroupsForQuery(_ context.Context, in *cloudwatchlogs.ListLogGroupsForQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListLogGroupsForQueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	page := 0
	if in.NextToken != nil {
		page = int((*in.NextToken)[0] - '0')
	}
	f.listed++
	out := &cloudwatchlogs.ListLogGroupsForQueryOutput{}
	if page < len(f.scanned) {
		out.LogGroupIdentifiers = f.scanned[page]
	}
	if page+1 < len(f.scanned) {
		out.NextToken = sdkaws.String(string(rune('0' + page + 1)))
	}
	return out, nil
}

func (f *fakeLogs) GetLogGroupFields(_ context.Context, in *cloudwatchlogs.GetLogGroupFieldsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogGroupFieldsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fieldCalls = append(f.fieldCalls, in)
	return &cloudwatchlogs.GetLogGroupFieldsOutput{LogGroupFields: f.fields[*in.LogGroupIdentifier]}, nil
}

const account = "123456789012"

type fakeIdentity struct {
	mu    sync.Mutex
	calls int
}

func (f *fakeIdentity) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return &sts.GetCallerIdentityOutput{Account: sdkaws.String(account)}, nil
}

func testClient(cfg *config.Config, logs logsAPI, metrics metricsAPI) *Client {
	c := newClient(cfg.Sources["aws"], logs, metrics, &fakeIdentity{})
	c.firstPoll, c.maxPoll = time.Millisecond, time.Millisecond
	return c
}

func row(fields ...string) []types.ResultField {
	var out []types.ResultField
	for i := 0; i < len(fields); i += 2 {
		out = append(out, types.ResultField{Field: sdkaws.String(fields[i]), Value: sdkaws.String(fields[i+1])})
	}
	return out
}

func running(scanned float64) *cloudwatchlogs.GetQueryResultsOutput {
	return &cloudwatchlogs.GetQueryResultsOutput{Status: types.QueryStatusRunning, Statistics: &types.QueryStatistics{BytesScanned: scanned}}
}

func complete(matched float64, rows ...[]types.ResultField) *cloudwatchlogs.GetQueryResultsOutput {
	return &cloudwatchlogs.GetQueryResultsOutput{
		Status:     types.QueryStatusComplete,
		Results:    rows,
		Statistics: &types.QueryStatistics{RecordsMatched: matched, BytesScanned: 10 * maxScan},
	}
}

func mustInsights(t *testing.T, scope authz.LogGroupScope, text string) policy.InsightsQuery {
	t.Helper()
	q, err := policy.ScopeInsights(scope, text)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func mustMetric(t *testing.T, scope authz.CloudWatchMetricScope, text string) policy.CloudWatchMetric {
	t.Helper()
	q, err := policy.ScopeCloudWatchMetric(scope, text)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestInsightsReturnsEvents(t *testing.T) {
	cfg, scope, _ := scopes(t)
	firstPage := complete(42,
		row("@timestamp", "2026-10-19 08:30:00.250", "@message", "first", "@logStream", "s1", "@log", "1:"+engineGroup, "@ptr", "p1"),
		row("@timestamp", "2026-10-19 08:31:00.000", "@message", "second", "@logStream", "s2", "@log", "1:"+auditGroup, "@ptr", "p2"),
	)
	firstPage.NextToken = sdkaws.String("page-2")
	logs := &fakeLogs{
		polls: []*cloudwatchlogs.GetQueryResultsOutput{
			running(maxScan),
			firstPage,
			complete(42, row("@timestamp", "2026-10-19 08:32:00.000", "@message", "third", "@logStream", "s1", "@log", "1:"+engineGroup, "@ptr", "p3")),
		},
		scanned: [][]string{{engineGroup}, {"arn:aws:logs:eu-west-1:123456789012:log-group:" + auditGroup + ":*"}},
	}
	c := testClient(cfg, logs, nil)
	result, err := c.Insights(context.Background(), scope, mustInsights(t, scope, "fields @timestamp, @message | limit 3"), testRange, 3)
	if err != nil {
		t.Fatal(err)
	}

	in := logs.started[0]
	if !slices.Equal(in.LogGroupIdentifiers, []string{engineGroup, auditGroup}) || in.LogGroupName != nil || in.LogGroupNames != nil {
		t.Errorf("log groups = %v %v %v", in.LogGroupIdentifiers, in.LogGroupName, in.LogGroupNames)
	}
	if in.QueryLanguage != types.QueryLanguageCwli || *in.QueryString != "fields @timestamp, @message | limit 3" {
		t.Errorf("query = %s %q", in.QueryLanguage, *in.QueryString)
	}
	if *in.StartTime != testRange.From.Unix() || *in.EndTime != testRange.To.Unix() || *in.Limit != 3 {
		t.Errorf("start=%d end=%d limit=%d", *in.StartTime, *in.EndTime, *in.Limit)
	}
	if len(logs.stopped) != 0 || logs.listed != 2 {
		t.Errorf("stopped=%v listed=%d", logs.stopped, logs.listed)
	}

	if result.Total != 42 || result.Series != nil || len(result.Streams) != 2 {
		t.Fatalf("result = %+v", result)
	}
	first := result.Streams[0]
	if first.Labels["@logStream"] != "s1" || first.Labels["@log"] != "1:"+engineGroup || len(first.Labels) != 2 {
		t.Errorf("labels = %v", first.Labels)
	}
	if len(first.Entries) != 2 || first.Entries[0].Line != "first" || first.Entries[1].Line != "third" {
		t.Errorf("entries = %+v", first.Entries)
	}
	if want := time.Date(2026, 10, 19, 8, 30, 0, 250_000_000, time.UTC); !first.Entries[0].Time.Equal(want) {
		t.Errorf("time = %s, want %s", first.Entries[0].Time, want)
	}
}

func TestInsightsStopsQueryOverScanLimit(t *testing.T) {
	cfg, scope, _ := scopes(t)
	logs := &fakeLogs{polls: []*cloudwatchlogs.GetQueryResultsOutput{running(maxScan), running(maxScan + 1), complete(1)}}
	c := testClient(cfg, logs, nil)
	result, err := c.Insights(context.Background(), scope, mustInsights(t, scope, "fields @message"), testRange, 10)
	e, ok := apierr.As(err)
	if !ok || e.Code != api.CodeLimitExceeded || e.Message != "query scanned more than 1.0 kB" {
		t.Fatalf("error = %v", err)
	}
	if !slices.Equal(logs.stopped, []string{"q-1"}) || logs.pollCount != 2 || logs.listed != 0 {
		t.Errorf("stopped=%v polls=%d listed=%d", logs.stopped, logs.pollCount, logs.listed)
	}
	if result.Streams != nil || result.Series != nil {
		t.Errorf("result = %+v", result)
	}
}

func TestInsightsStopsQueryWhenContextEnds(t *testing.T) {
	cfg, scope, _ := scopes(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &fakeLogs{
		polls: []*cloudwatchlogs.GetQueryResultsOutput{running(0)},
		onPoll: func(n int) {
			if n == 3 {
				cancel()
			}
		},
	}
	c := testClient(cfg, logs, nil)
	_, err := c.Insights(ctx, scope, mustInsights(t, scope, "fields @message"), testRange, 10)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if !slices.Equal(logs.stopped, []string{"q-1"}) || logs.stopCtxErr != nil {
		t.Errorf("stopped=%v with context error %v", logs.stopped, logs.stopCtxErr)
	}
}

func TestInsightsRejectsForeignLogGroup(t *testing.T) {
	cfg, scope, _ := scopes(t)
	for _, foreign := range []string{
		"/aws/lambda/billing",
		"arn:aws:logs:eu-west-1:123456789012:log-group:/aws/lambda/billing:*",
		engineGroup + "-copy",
		"arn:aws:logs:eu-west-1:123456789012:log-group:" + engineGroup + "x",
		"arn:aws:logs:eu-west-1:999999999999:log-group:" + engineGroup,
		"arn:aws:logs:us-east-1:123456789012:log-group:" + engineGroup + ":*",
		"arn:aws:s3:eu-west-1:123456789012:log-group:" + engineGroup,
		"arn:aws:logs:eu-west-1:123456789012:log-stream:" + engineGroup,
		"arn:broken",
	} {
		logs := &fakeLogs{
			polls:   []*cloudwatchlogs.GetQueryResultsOutput{complete(1, row("@timestamp", "2026-10-19 08:30:00.000", "@message", "secret"))},
			scanned: [][]string{{engineGroup}, {foreign}},
		}
		c := testClient(cfg, logs, nil)
		result, err := c.Insights(context.Background(), scope, mustInsights(t, scope, "fields @timestamp, @message"), testRange, 10)
		if err == nil {
			t.Fatalf("%s: accepted", foreign)
		}
		if _, ok := apierr.As(err); ok {
			t.Errorf("%s: error %v is client-visible, want internal", foreign, err)
		}
		if result.Streams != nil || result.Total != 0 {
			t.Errorf("%s: returned %+v", foreign, result)
		}
	}
}

func TestInsightsFailures(t *testing.T) {
	cfg, scope, _ := scopes(t)
	tests := []struct {
		name     string
		logs     *fakeLogs
		code     api.ErrorCode
		internal bool
		hidden   string
	}{
		{
			name: "malformed query",
			logs: &fakeLogs{startErr: &types.MalformedQueryException{Message: sdkaws.String("unexpected symbol")}},
			code: api.CodeInvalidQuery,
		},
		{
			name:   "access denied",
			logs:   &fakeLogs{startErr: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "arn:aws:sts::123:assumed-role/sonda is not authorized"}},
			code:   api.CodeUpstreamError,
			hidden: "arn:aws:sts",
		},
		{
			name: "throttled",
			logs: &fakeLogs{startErr: &types.LimitExceededException{Message: sdkaws.String("too many queries")}},
			code: api.CodeUpstreamError,
		},
		{
			name: "network",
			logs: &fakeLogs{startErr: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}},
			code: api.CodeUpstreamError,
		},
		{
			name:     "credentials",
			logs:     &fakeLogs{startErr: errors.New("get credentials: parse failed of process output: {\"SecretAccessKey\":\"s3cr3t\"")},
			internal: true,
		},
		{
			name: "failed",
			logs: &fakeLogs{polls: []*cloudwatchlogs.GetQueryResultsOutput{{Status: types.QueryStatusFailed}}},
			code: api.CodeUpstreamError,
		},
		{
			name: "poll error",
			logs: &fakeLogs{pollErr: &smithy.GenericAPIError{Code: "ServiceUnavailableException", Message: "try again"}},
			code: api.CodeUpstreamError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(cfg, tt.logs, nil)
			_, err := c.Insights(context.Background(), scope, mustInsights(t, scope, "fields @message"), testRange, 10)
			e, ok := apierr.As(err)
			switch {
			case tt.internal && ok:
				t.Fatalf("error %v is client-visible, want internal", err)
			case !tt.internal && (!ok || e.Code != tt.code):
				t.Fatalf("error = %v, want %s", err, tt.code)
			case ok && tt.hidden != "" && strings.Contains(e.Message, tt.hidden):
				t.Errorf("message %q reveals %q", e.Message, tt.hidden)
			}
			if tt.logs.startErr == nil && !slices.Equal(tt.logs.stopped, []string{"q-1"}) {
				t.Errorf("stopped = %v", tt.logs.stopped)
			}
		})
	}
}

func TestInsightsStats(t *testing.T) {
	cfg, scope, _ := scopes(t)
	binned := complete(5,
		row("bin(5m)", "2026-10-19 08:05:00.000", "status", "ok", "count(*)", "3"),
		row("bin(5m)", "2026-10-19 08:00:00.000", "status", "ok", "count(*)", "2"),
		row("bin(5m)", "2026-10-19 08:00:00.000", "status", "error", "count(*)", "1"),
	)
	c := testClient(cfg, &fakeLogs{polls: []*cloudwatchlogs.GetQueryResultsOutput{binned}}, nil)
	result, err := c.Insights(context.Background(), scope, mustInsights(t, scope, "stats count(*) by bin(5m), status"), testRange, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Series) != 2 || result.Streams != nil || result.Total != 5 {
		t.Fatalf("result = %+v", result)
	}
	for _, s := range result.Series {
		if s.Metric["__name__"] != "count(*)" {
			t.Errorf("metric = %v", s.Metric)
		}
		if s.Metric["status"] == "ok" && (len(s.Values) != 2 || s.Values[0].Value != 2 || s.Values[1].Value != 3) {
			t.Errorf("ok values = %v", s.Values)
		}
	}

	plain := complete(6, row("status", "ok", "count(*)", "5", "avg(ms)", "1.5"), row("status", "with space", "count(*)", "1", "avg(ms)", "2"))
	c = testClient(cfg, &fakeLogs{polls: []*cloudwatchlogs.GetQueryResultsOutput{plain}}, nil)
	result, err = c.Insights(context.Background(), scope, mustInsights(t, scope, "stats count(*), avg(ms) by status"), testRange, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Series) != 4 || result.Streams != nil {
		t.Fatalf("result = %+v", result)
	}
	for _, s := range result.Series {
		if len(s.Values) != 1 || !s.Values[0].Timestamp.Time().Equal(testRange.To) || s.Metric["status"] == "" {
			t.Errorf("series = %v", s)
		}
	}

	c = testClient(cfg, &fakeLogs{polls: []*cloudwatchlogs.GetQueryResultsOutput{complete(0)}}, nil)
	result, err = c.Insights(context.Background(), scope, mustInsights(t, scope, "filter x = 1 | stats count(*) by bin(5m)"), testRange, 10)
	if err != nil {
		t.Fatal(err)
	}
	if result.Series == nil || len(result.Series) != 0 || result.Streams != nil {
		t.Errorf("empty stats result = %+v", result)
	}
}

func TestInsightsRowsWithoutMessage(t *testing.T) {
	cfg, scope, _ := scopes(t)
	rows := complete(2, row("status", "ok", "user", "a b"), row("status", "error", "user", ""))
	c := testClient(cfg, &fakeLogs{polls: []*cloudwatchlogs.GetQueryResultsOutput{rows}}, nil)
	result, err := c.Insights(context.Background(), scope, mustInsights(t, scope, "fields status, user"), testRange, 10)
	if err != nil {
		t.Fatal(err)
	}
	if result.Series != nil || len(result.Streams) != 1 {
		t.Fatalf("result = %+v", result)
	}
	entries := result.Streams[0].Entries
	if len(entries) != 2 || entries[0].Line != `status=ok user="a b"` || entries[1].Line != `status=error user=""` || !entries[0].Time.Equal(testRange.To) {
		t.Errorf("entries = %+v", entries)
	}
}

func TestLogFields(t *testing.T) {
	cfg, scope, _ := scopes(t)
	logs := &fakeLogs{fields: map[string][]types.LogGroupField{
		engineGroup: {{Name: sdkaws.String("@message"), Percent: 100}, {Name: sdkaws.String("level"), Percent: 40}},
		auditGroup:  {{Name: sdkaws.String("level"), Percent: 70}, {Name: sdkaws.String("user"), Percent: 5}},
	}}
	c := testClient(cfg, logs, nil)
	fields, err := c.LogFields(context.Background(), scope, testRange)
	if err != nil {
		t.Fatal(err)
	}
	want := []Field{{"@message", 100}, {"level", 70}, {"user", 5}}
	if !slices.Equal(fields, want) {
		t.Errorf("fields = %v, want %v", fields, want)
	}
	if len(logs.fieldCalls) != 2 || *logs.fieldCalls[0].Time != testRange.To.Add(-8*time.Minute).Unix() {
		t.Errorf("calls = %+v", logs.fieldCalls)
	}
}

func TestInScopeResolvesAccountOnce(t *testing.T) {
	cfg, scope, _ := scopes(t)
	identity := &fakeIdentity{}
	c := newClient(cfg.Sources["aws"], nil, nil, identity)
	tests := []struct {
		identifier string
		want       bool
	}{
		{engineGroup, true},
		{"arn:aws:logs:eu-west-1:" + account + ":log-group:" + engineGroup, true},
		{"arn:aws:logs:eu-west-1:" + account + ":log-group:" + auditGroup + ":*", true},
		{"arn:aws:logs:eu-west-1:999999999999:log-group:" + engineGroup, false},
		{"arn:aws:logs:eu-central-1:" + account + ":log-group:" + engineGroup, false},
	}
	for _, tt := range tests {
		got, err := c.inScope(context.Background(), tt.identifier, scope.LogGroups())
		if err != nil || got != tt.want {
			t.Errorf("inScope(%q) = %v, %v; want %v", tt.identifier, got, err, tt.want)
		}
	}
	if identity.calls != 1 {
		t.Errorf("GetCallerIdentity called %d times, want 1", identity.calls)
	}
}

type fakeMetrics struct {
	dataPages  []*cloudwatch.GetMetricDataOutput
	dataInputs []cloudwatch.GetMetricDataInput
	listPages  []*cloudwatch.ListMetricsOutput
	listInputs []cloudwatch.ListMetricsInput
}

func (f *fakeMetrics) GetMetricData(_ context.Context, in *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	f.dataInputs = append(f.dataInputs, *in)
	return f.dataPages[len(f.dataInputs)-1], nil
}

func (f *fakeMetrics) ListMetrics(_ context.Context, in *cloudwatch.ListMetricsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) {
	f.listInputs = append(f.listInputs, *in)
	return f.listPages[len(f.listInputs)-1], nil
}

func at(minute int) time.Time { return testRange.From.Add(time.Duration(minute) * time.Minute) }

func TestMetricDataPaginates(t *testing.T) {
	cfg, _, scope := scopes(t)
	metrics := &fakeMetrics{dataPages: []*cloudwatch.GetMetricDataOutput{
		{
			MetricDataResults: []cwtypes.MetricDataResult{{Id: sdkaws.String("m0"), StatusCode: cwtypes.StatusCodePartialData, Timestamps: []time.Time{at(2), at(0)}, Values: []float64{3, 1}}},
			NextToken:         sdkaws.String("t1"),
		},
		{
			MetricDataResults: []cwtypes.MetricDataResult{{Id: sdkaws.String("m0"), StatusCode: cwtypes.StatusCodeComplete, Timestamps: []time.Time{at(1)}, Values: []float64{2}}},
		},
	}}
	c := testClient(cfg, nil, metrics)
	q := mustMetric(t, scope, `{"metric":"CPUUtilization","stat":"p99","dimensions":{"Engine":"aurora"}}`)
	matrix, used, err := c.MetricData(context.Background(), q, testRange, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if used != 2*time.Minute {
		t.Errorf("period = %s", used)
	}

	if len(metrics.dataInputs) != 2 || metrics.dataInputs[1].NextToken == nil || *metrics.dataInputs[1].NextToken != "t1" {
		t.Fatalf("inputs = %+v", metrics.dataInputs)
	}
	in := metrics.dataInputs[0]
	if len(in.MetricDataQueries) != 1 || in.ScanBy != cwtypes.ScanByTimestampAscending || !in.StartTime.Equal(testRange.From) || !in.EndTime.Equal(testRange.To) {
		t.Fatalf("input = %+v", in)
	}
	query := in.MetricDataQueries[0]
	stat := query.MetricStat
	if query.Expression != nil || *query.Id != "m0" || *stat.Period != 120 || *stat.Stat != "p99" || *stat.Metric.Namespace != "AWS/RDS" || *stat.Metric.MetricName != "CPUUtilization" {
		t.Errorf("query = %+v, stat = %+v", query, stat)
	}
	var dims []string
	for _, d := range stat.Metric.Dimensions {
		dims = append(dims, *d.Name+"="+*d.Value)
	}
	if !slices.Equal(dims, []string{"DBClusterIdentifier=engine", "Engine=aurora", "Role=WRITER"}) {
		t.Errorf("dimensions = %v", dims)
	}

	if len(matrix) != 1 {
		t.Fatalf("matrix = %v", matrix)
	}
	s := matrix[0]
	if s.Metric["stat"] != "p99" || s.Metric["DBClusterIdentifier"] != "engine" || s.Metric["Engine"] != "aurora" || len(s.Metric) != 4 {
		t.Errorf("labels = %v", s.Metric)
	}
	if len(s.Values) != 3 || s.Values[0].Value != 1 || s.Values[1].Value != 2 || s.Values[2].Value != 3 || !s.Values[0].Timestamp.Time().Equal(at(0)) {
		t.Errorf("values = %v", s.Values)
	}
}

func TestMetricDataForbidden(t *testing.T) {
	cfg, _, scope := scopes(t)
	metrics := &fakeMetrics{dataPages: []*cloudwatch.GetMetricDataOutput{
		{MetricDataResults: []cwtypes.MetricDataResult{{Id: sdkaws.String("m0"), StatusCode: cwtypes.StatusCodeForbidden}}},
	}}
	c := testClient(cfg, nil, metrics)
	_, _, err := c.MetricData(context.Background(), mustMetric(t, scope, `{"metric":"CPUUtilization","stat":"Average"}`), testRange, time.Minute)
	if e, ok := apierr.As(err); !ok || e.Code != api.CodeUpstreamError {
		t.Errorf("error = %v", err)
	}
}

func TestMetricNames(t *testing.T) {
	cfg, _, scope := scopes(t)
	metric := func(name string) cwtypes.Metric { return cwtypes.Metric{MetricName: sdkaws.String(name)} }
	metrics := &fakeMetrics{listPages: []*cloudwatch.ListMetricsOutput{
		{Metrics: []cwtypes.Metric{metric("FreeableMemory"), metric("CPUUtilization")}, NextToken: sdkaws.String("t1")},
		{Metrics: []cwtypes.Metric{metric("CPUUtilization"), metric("DatabaseConnections")}},
	}}
	c := testClient(cfg, nil, metrics)
	names, err := c.MetricNames(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"CPUUtilization", "DatabaseConnections", "FreeableMemory"}) {
		t.Errorf("names = %v", names)
	}
	in := metrics.listInputs[0]
	var filters []string
	for _, d := range in.Dimensions {
		filters = append(filters, *d.Name+"="+*d.Value)
	}
	if *in.Namespace != "AWS/RDS" || !slices.Equal(filters, []string{"DBClusterIdentifier=engine", "Role=WRITER"}) {
		t.Errorf("input = %s %v", *in.Namespace, filters)
	}
}

func TestPeriod(t *testing.T) {
	const year = 365 * 24 * time.Hour
	tests := []struct {
		step, rangeLength time.Duration
		want              time.Duration
	}{
		{0, time.Hour, time.Minute},
		{15 * time.Second, time.Hour, time.Minute},
		{time.Minute, time.Hour, time.Minute},
		{61 * time.Second, time.Hour, 2 * time.Minute},
		{time.Hour, time.Hour, time.Hour},
		{2 * time.Hour, 90*time.Minute + 30*time.Second, 90 * time.Minute},
		{time.Hour, 30 * time.Second, time.Minute},
		{200 * year, 200 * year, maxPeriod},
	}
	for _, tt := range tests {
		got := period(tt.step, tt.rangeLength)
		if got != tt.want {
			t.Errorf("period(%s, %s) = %s, want %s", tt.step, tt.rangeLength, got, tt.want)
		}
		if seconds := got / time.Second; seconds%60 != 0 || seconds > math.MaxInt32 {
			t.Errorf("period(%s, %s) = %d s does not fit", tt.step, tt.rangeLength, seconds)
		}
	}
}
