package telemetry

import (
	"strings"
	"testing"
)

func TestDecodeCloudflareMetricQuery(t *testing.T) {
	tests := []struct {
		in, wantErr string
	}{
		{`{"metric":"requests"}`, ""},
		{`{"metric":"cpu_time_p99","by":["status","scriptVersion"]}`, ""},
		{`{}`, "metric is required"},
		{`{"metric":"bytes"}`, `unknown metric "bytes"`},
		{`{"metric":"requests","by":["scriptName"]}`, `unknown dimension "scriptName"`},
		{`{"metric":"requests","scriptName":"other"}`, "unknown field"},
		{`{"metric":"requests"} {}`, "single JSON object"},
		{`[]`, "invalid query JSON"},
	}
	for _, tt := range tests {
		_, err := DecodeCloudflareMetricQuery(tt.in)
		checkError(t, tt.in, err, tt.wantErr)
	}
}

func TestDecodeCloudWatchMetricQuery(t *testing.T) {
	tests := []struct {
		in, wantErr string
	}{
		{`{"metric":"CPUUtilization","stat":"Average"}`, ""},
		{`{"metric":"CPUUtilization","stat":"p99.9","dimensions":{"Role":"WRITER"}}`, ""},
		{`{"stat":"Average"}`, "metric is required"},
		{`{"metric":"CPUUtilization"}`, "stat is required"},
		{`{"metric":"CPUUtilization","stat":"Median"}`, `unknown stat "Median"`},
		{`{"metric":"CPUUtilization","stat":"p"}`, `unknown stat "p"`},
		{`{"metric":"CPUUtilization","stat":"Sum","namespace":"AWS/EC2"}`, "unknown field"},
	}
	for _, tt := range tests {
		_, err := DecodeCloudWatchMetricQuery(tt.in)
		checkError(t, tt.in, err, tt.wantErr)
	}
}

func checkError(t *testing.T, in string, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Errorf("%s: %v", in, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: error = %v, want containing %q", in, err, want)
	}
}
