package shape

import (
	"math"
	"sort"
	"time"

	"github.com/grafana/loki/v3/pkg/pattern/drain"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/connector/loki"
)

const maxLineLength = 1000

// LogSample is a set of log lines with deduplicated stream labels, newest line first.
type LogSample struct {
	Streams []map[string]string `json:"streams"`
	Lines   []api.LogLine       `json:"lines"`
}

// Flatten merges streams into one list sorted newest first. Lines are redacted and cut
// to maxLineLength.
func Flatten(streams []loki.Stream, redactor *Redactor) LogSample {
	sample := LogSample{Streams: make([]map[string]string, len(streams))}
	for i, s := range streams {
		sample.Streams[i] = s.Labels
		for _, e := range s.Entries {
			sample.Lines = append(sample.Lines, api.LogLine{Time: e.Time, Stream: i, Line: cut(redactor.Redact(e.Line))})
		}
	}
	sort.SliceStable(sample.Lines, func(i, j int) bool { return sample.Lines[i].Time.After(sample.Lines[j].Time) })
	return sample
}

func cut(line string) string {
	if len(line) <= maxLineLength {
		return line
	}
	return line[:maxLineLength] + "…"
}

// FitLines keeps lines from the start until their size reaches budget bytes. It always
// keeps at least one line.
func FitLines(lines []api.LogLine, budget int) (kept []api.LogLine, truncated bool) {
	const overhead = 64
	size := 0
	for i, line := range lines {
		size += len(line.Line) + overhead
		if size > budget && i > 0 {
			return lines[:i], true
		}
	}
	return lines, false
}

// Groups clusters sampled lines into patterns with Drain. Assignment maps each line to its
// group index, or -1 when Drain skipped the line.
type Groups struct {
	Groups     []api.LogGroup
	Assignment []int
	Ungrouped  int
}

// jsonFields are the message fields Drain tokenizes in JSON lines (Loki's defaults).
type jsonFields struct{}

func (jsonFields) PatternIngesterTokenizableJSONFields(string) []string {
	return []string{"log", "message", "msg", "msg_", "_msg", "content"}
}

func GroupLines(lines []api.LogLine, total int64) Groups {
	type cluster struct {
		first, last time.Time
		example     string
	}
	trainers := map[string]*drain.Drain{}
	byCluster := map[*drain.LogCluster]*cluster{}
	lineCluster := make([]*drain.LogCluster, len(lines))
	for i, line := range lines {
		format := drain.DetectLogFormat(line.Line)
		trainer, ok := trainers[format]
		if !ok {
			config := drain.DefaultConfig()
			// No eviction: clusters must stay alive until every line is assigned.
			config.MaxClusters = 0
			trainer = drain.New("", config, jsonFields{}, format, nil)
			trainers[format] = trainer
		}
		c := trainer.Train(line.Line, line.Time.UnixNano())
		if c == nil {
			continue
		}
		lineCluster[i] = c
		info, ok := byCluster[c]
		if !ok {
			info = &cluster{first: line.Time, last: line.Time, example: line.Line}
			byCluster[c] = info
		}
		info.first = minTime(info.first, line.Time)
		info.last = maxTime(info.last, line.Time)
	}

	clusters := make([]*drain.LogCluster, 0, len(byCluster))
	for c := range byCluster {
		clusters = append(clusters, c)
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].SampleCount != clusters[j].SampleCount {
			return clusters[i].SampleCount > clusters[j].SampleCount
		}
		return clusters[i].String() < clusters[j].String()
	})

	result := Groups{Groups: make([]api.LogGroup, len(clusters)), Assignment: make([]int, len(lines))}
	index := map[*drain.LogCluster]int{}
	for i, c := range clusters {
		info := byCluster[c]
		index[c] = i
		result.Groups[i] = api.LogGroup{
			Index:          i,
			Pattern:        c.String(),
			SampleCount:    int(c.SampleCount),
			EstimatedCount: estimate(int(c.SampleCount), len(lines), total),
			Example:        info.example,
			FirstSeen:      info.first,
			LastSeen:       info.last,
		}
	}
	for i, c := range lineCluster {
		if c == nil {
			result.Assignment[i] = -1
			result.Ungrouped++
			continue
		}
		result.Assignment[i] = index[c]
	}
	return result
}

func estimate(count, sampleSize int, total int64) int64 {
	if sampleSize == 0 {
		return 0
	}
	return int64(math.Round(float64(count) / float64(sampleSize) * float64(total)))
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
