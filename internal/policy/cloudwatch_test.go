package policy

import (
	"maps"
	"strings"
	"testing"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

func cloudWatchScopes(t *testing.T) (authz.LogGroupScope, authz.CloudWatchMetricScope) {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  aws: { type: aws, region: eu-west-1 }
services:
  db:
    environments:
      production:
        logs: { source: aws, log_groups: [/aws/rds/cluster/engine/postgresql] }
        metrics: { source: aws, namespace: AWS/RDS, dimensions: { DBClusterIdentifier: engine } }
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
	return groups, metrics
}

func wantCloudWatchCode(t *testing.T, in string, err error, code api.ErrorCode) {
	t.Helper()
	e, ok := apierr.As(err)
	if !ok || e.Code != code {
		t.Errorf("%q: error = %v, want %s", in, err, code)
	}
}

func TestScopeInsightsRejectsSource(t *testing.T) {
	scope, _ := cloudWatchScopes(t)
	for _, in := range []string{
		`SOURCE logGroups() | fields @message`,
		`source logGroups(namePrefix: ['/aws']) | fields @message`,
		` Source logGroups()`,
		"# comment\nSOURCE logGroups()",
		"fields @message\n| sOuRcE logGroups()",
		`filter status >= 500 | join type=inner left=a right=b where a.id=b.id (SOURCE '/aws/lambda/other')`,
		`filter requestId in (SOURCE '/aws/lambda/other' | fields requestId)`,
		`fields svc | appendcols ( SOURCE lg | stats count(*) by svc )`,
		`filter source = "x"`,
		`filter x like /a\/ | SOURCE logGroups() | filter y like /b/`,
		`filter x = "a\" | SOURCE logGroups() | filter y = "b"`,
		`filter x = 1 | ` + strings.Repeat("a", maxInsightsQueryLength),
		`fields a / 2`,
	} {
		_, err := ScopeInsights(scope, in)
		wantCloudWatchCode(t, in, err, api.CodeInvalidQuery)
	}
}

func TestScopeInsightsAllowsOnlyRowCommands(t *testing.T) {
	scope, _ := cloudWatchScopes(t)
	tests := []struct{ in, want string }{
		{`fields x | lookup user_data id OUTPUT name`, "command lookup is not allowed"},
		{`fields ip | cidrlookup nets ip OUTPUT owner`, "command cidrlookup is not allowed"},
		{`fields @message | unmask @message`, "command unmask is not allowed"},
		{`SOURCE logGroups() | fields @message`, "SOURCE is not allowed"},
		{`filter x = 1 | join type=inner left=a right=b where a.id=b.id (fields id)`, "command join is not allowed"},
		{`fields svc | appendcols ( stats count(*) by svc )`, "command appendcols is not allowed"},
		{`fields a | addtotals`, "command addtotals is not allowed"},
		{`fields a | estimate`, "command estimate is not allowed"},
		{`filter x in (fields x | lookup t x OUTPUT y)`, "command lookup is not allowed"},
		{`filter x in (lookup t x OUTPUT y)`, "lookup is not allowed anywhere"},
		{`fields unmask(@message)`, "unmask is not allowed anywhere"},
		{`filter x in (cidrlookup t x OUTPUT y)`, "cidrlookup is not allowed anywhere"},
	}
	for _, tt := range tests {
		_, err := ScopeInsights(scope, tt.in)
		wantCloudWatchCode(t, tt.in, err, api.CodeInvalidQuery)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: error = %v, want containing %q", tt.in, err, tt.want)
		}
	}

	allowed := "fields a | display a | filter a = 1 | filterIndex a = 1 | where a = 1 | parse a \"*\" as b | " +
		"sort a | dedup a | unnest a into b | pattern @message | diff | anomaly | stats count(*) by a | limit 5"
	if _, err := ScopeInsights(scope, allowed); err != nil {
		t.Errorf("allowed commands: %v", err)
	}
}

func TestScopeInsightsAccepts(t *testing.T) {
	scope, _ := cloudWatchScopes(t)
	tests := []struct {
		in        string
		aggregate bool
	}{
		{`filter @message like /source/ | limit 5`, false},
		{"filter `source` = \"x\" | fields 'source'", false},
		{`fields @timestamp, @message | stats count(*) by bin(5m)`, true},
		{`parse @message /level=(?<level>\w+)/ | stats count(*) by level`, true},
	}
	for _, tt := range tests {
		q, err := ScopeInsights(scope, tt.in)
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		if q.String() != tt.in || q.Aggregates() != tt.aggregate {
			t.Errorf("%q: got %q aggregate=%v", tt.in, q.String(), q.Aggregates())
		}
	}
}

func TestInsightsSearch(t *testing.T) {
	scope, _ := cloudWatchScopes(t)
	tests := []struct {
		name string
		f    LogFilter
		want string
	}{
		{"empty", LogFilter{}, `fields @timestamp, @message, @logStream | sort @timestamp desc | limit 50`},
		{
			"contains",
			LogFilter{Contains: []string{"timeout", "a\\b\nc\td"}},
			`fields @timestamp, @message, @logStream | filter @message like "timeout" | filter @message like "a\\b\nc\td" | sort @timestamp desc | limit 50`,
		},
		{
			"quotes",
			LogFilter{Contains: []string{`say "hi"`, `it's`}},
			`fields @timestamp, @message, @logStream | filter @message like 'say "hi"' | filter @message like "it's" | sort @timestamp desc | limit 50`,
		},
		{
			"where",
			LogFilter{Where: []Where{
				{Field: "level", Value: "error"},
				{Field: "@logStream", Value: "x", Negate: true},
				{Field: "http.status-code", Value: "500"},
				{Field: "@aws.tag$", Value: ""},
				{Field: "detail.source", Value: "aws.ec2"},
				{Field: "and", Value: "x"},
			}},
			`fields @timestamp, @message, @logStream | filter level = "error" | filter @logStream != "x" | ` +
				"filter `http.status-code` = \"500\" | filter @`aws.tag$` = \"\" | filter `detail.source` = \"aws.ec2\" | filter `and` = \"x\" | " +
				`sort @timestamp desc | limit 50`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := InsightsSearch(scope, tt.f, 50)
			if err != nil {
				t.Fatal(err)
			}
			if q.String() != tt.want {
				t.Errorf("got  %s\nwant %s", q, tt.want)
			}
		})
	}
}

func TestInsightsSearchCapsLimit(t *testing.T) {
	scope, _ := cloudWatchScopes(t)
	q, err := InsightsSearch(scope, LogFilter{}, 50000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(q.String(), "| limit 10000") {
		t.Errorf("query = %s", q)
	}
}

func TestInsightsSearchRejects(t *testing.T) {
	scope, _ := cloudWatchScopes(t)
	tests := []struct {
		name string
		f    LogFilter
	}{
		{"pipeline", LogFilter{Pipeline: "| json"}},
		{"both quotes", LogFilter{Contains: []string{`a"b'c`}}},
		{"control character", LogFilter{Contains: []string{"a\x01b"}}},
		{"backtick in field", LogFilter{Where: []Where{{Field: "a`b", Value: "x"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := InsightsSearch(scope, tt.f, 10)
			wantCloudWatchCode(t, tt.name, err, api.CodeInvalidRequest)
		})
	}
}

func TestInsightsSearchKeepsValuesInStrings(t *testing.T) {
	scope, _ := cloudWatchScopes(t)
	value := `x" | SOURCE logGroups() | filter b = "`
	q, err := InsightsSearch(scope, LogFilter{Contains: []string{value}, Where: []Where{{Field: "a", Value: value}}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := `fields @timestamp, @message, @logStream | filter @message like '` + value + `' | filter a = '` + value + `' | sort @timestamp desc | limit 10`
	if q.String() != want {
		t.Errorf("got  %s\nwant %s", q, want)
	}
}

func TestScopeCloudWatchMetric(t *testing.T) {
	_, scope := cloudWatchScopes(t)
	tests := []struct {
		in   string
		want map[string]string
	}{
		{`{"metric":"CPUUtilization","stat":"Average"}`, map[string]string{"DBClusterIdentifier": "engine"}},
		{`{"metric":"CPUUtilization","stat":"p99","dimensions":{"Role":"WRITER"}}`, map[string]string{"DBClusterIdentifier": "engine", "Role": "WRITER"}},
		{`{"metric":"CPUUtilization","stat":"Sum","dimensions":{"DBClusterIdentifier":"engine"}}`, map[string]string{"DBClusterIdentifier": "engine"}},
	}
	for _, tt := range tests {
		m, err := ScopeCloudWatchMetric(scope, tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if m.Namespace() != "AWS/RDS" || m.Metric() != "CPUUtilization" || !maps.Equal(m.Dimensions(), tt.want) {
			t.Errorf("%s: got %s", tt.in, m)
		}
	}

	m, _ := ScopeCloudWatchMetric(scope, `{"metric":"CPUUtilization","stat":"Average"}`)
	m.Dimensions()["DBClusterIdentifier"] = "other"
	if m.Dimensions()["DBClusterIdentifier"] != "engine" {
		t.Error("Dimensions returned the metric's own map")
	}
	if got := m.String(); got != `{"namespace":"AWS/RDS","metric":"CPUUtilization","stat":"Average","dimensions":{"DBClusterIdentifier":"engine"}}` {
		t.Errorf("String() = %s", got)
	}
}

func TestScopeCloudWatchMetricRejects(t *testing.T) {
	_, scope := cloudWatchScopes(t)
	for _, in := range []string{
		`{"metric":"CPUUtilization","stat":"Average","dimensions":{"DBClusterIdentifier":"billing"}}`,
		`{"metric":"CPUUtilization","stat":"Average","dimensions":{"DBClusterIdentifier":""}}`,
		`{"metric":"CPUUtilization","stat":"Average","dimensions":{"Role":""}}`,
		`{"metric":"CPUUtilization","stat":"Average","namespace":"AWS/EC2"}`,
		`{"metric":"CPUUtilization","stat":"Average","expression":"SEARCH('{AWS/RDS} CPU', 'Average')"}`,
		`{"metric":"CPUUtilization"}`,
		`not json`,
	} {
		_, err := ScopeCloudWatchMetric(scope, in)
		wantCloudWatchCode(t, in, err, api.CodeInvalidQuery)
	}
}
