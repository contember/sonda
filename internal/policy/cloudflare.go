package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

const (
	CloudflareViewEvents       = "events"
	CloudflareViewCalculations = "calculations"
	CloudflareViewInvocations  = "invocations"
	CloudflareViewTraces       = "traces"

	cloudflareMaxLimit = 2000
	// Cloudflare nests filter groups at most 4 deep; the scope wrapper takes one level.
	cloudflareMaxAgentDepth  = 3
	cloudflareTraceByIDLimit = cloudflareMaxLimit
	cloudflareKeysLimit      = 1000
)

var (
	cloudflareOperations = []string{
		"eq", "neq", "gt", "gte", "lt", "lte", "includes", "not_includes", "starts_with", "ends_with",
		"regex", "exists", "is_null", "in", "not_in",
	}
	cloudflareHavingOperations = []string{"eq", "neq", "gt", "gte", "lt", "lte"}
	cloudflareTypes            = []string{"string", "number", "boolean"}
	cloudflareCombinations     = []string{"and", "or"}
)

// CloudflareQuery is a Workers Observability query whose filters are AND-combined with the scope filter.
type CloudflareQuery struct {
	view       string
	limit      int
	parameters cloudflareParameters
}

func (q CloudflareQuery) View() string { return q.view }

// WithLimit caps the number of returned rows at limit.
func (q CloudflareQuery) WithLimit(limit int) CloudflareQuery {
	if q.limit == 0 || q.limit > limit {
		q.limit = limit
	}
	return q
}

// Body is the full request body of the telemetry query endpoint over the range.
func (q CloudflareQuery) Body(r api.TimeRange) ([]byte, error) {
	queryID := make([]byte, 8)
	_, _ = rand.Read(queryID)
	return json.Marshal(cloudflareBody{
		QueryID:    "sonda-" + hex.EncodeToString(queryID),
		Timeframe:  cloudflareTimeframe{From: r.From.UnixMilli(), To: r.To.UnixMilli()},
		View:       q.view,
		Limit:      q.limit,
		Dry:        true,
		Parameters: q.parameters,
	})
}

// String is the canonical JSON of the scoped query, for the audit log and the response.
func (q CloudflareQuery) String() string {
	data, err := json.Marshal(cloudflareDisplay{View: q.view, Limit: q.limit, Parameters: q.parameters})
	if err != nil {
		return err.Error()
	}
	return string(data)
}

type cloudflareBody struct {
	QueryID   string              `json:"queryId"`
	Timeframe cloudflareTimeframe `json:"timeframe"`
	View      string              `json:"view"`
	Limit     int                 `json:"limit,omitempty"`
	// Dry runs are not saved to the account's query history, so reads leave no trace there.
	Dry        bool                 `json:"dry"`
	Parameters cloudflareParameters `json:"parameters"`
}

type cloudflareDisplay struct {
	View       string               `json:"view"`
	Limit      int                  `json:"limit,omitempty"`
	Parameters cloudflareParameters `json:"parameters"`
}

type cloudflareTimeframe struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

type cloudflareParameters struct {
	FilterCombination string                  `json:"filterCombination"`
	Filters           []cloudflareFilter      `json:"filters"`
	Needle            *cloudflareNeedle       `json:"needle,omitempty"`
	Calculations      []cloudflareCalculation `json:"calculations,omitempty"`
	GroupBys          []cloudflareGroupBy     `json:"groupBys,omitempty"`
	Havings           []cloudflareHaving      `json:"havings,omitempty"`
	OrderBy           *cloudflareOrderBy      `json:"orderBy,omitempty"`
}

// cloudflareFilter is a leaf (key, operation, type, value) or a group (filterCombination, filters).
type cloudflareFilter struct {
	Kind              string             `json:"kind,omitempty"`
	FilterCombination string             `json:"filterCombination,omitempty"`
	Filters           []cloudflareFilter `json:"filters,omitempty"`
	Key               string             `json:"key,omitempty"`
	Operation         string             `json:"operation,omitempty"`
	Type              string             `json:"type,omitempty"`
	Value             *cloudflareValue   `json:"value,omitempty"`
}

type cloudflareNeedle struct {
	Value     cloudflareValue `json:"value"`
	IsRegex   bool            `json:"isRegex,omitempty"`
	MatchCase bool            `json:"matchCase,omitempty"`
}

type cloudflareCalculation struct {
	Operator string `json:"operator"`
	Key      string `json:"key,omitempty"`
	KeyType  string `json:"keyType,omitempty"`
	Alias    string `json:"alias,omitempty"`
}

type cloudflareGroupBy struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type cloudflareHaving struct {
	Key       string  `json:"key"`
	Operation string  `json:"operation"`
	Value     float64 `json:"value"`
}

type cloudflareOrderBy struct {
	Value string `json:"value"`
	Order string `json:"order,omitempty"`
}

// cloudflareValue is a JSON string, number or boolean.
type cloudflareValue struct {
	raw json.RawMessage
}

func (v *cloudflareValue) UnmarshalJSON(data []byte) error {
	switch data[0] {
	case '{', '[', 'n':
		return errors.New("value must be a string, number or boolean")
	}
	v.raw = slices.Clone(data)
	return nil
}

func (v cloudflareValue) MarshalJSON() ([]byte, error) { return v.raw, nil }

func textValue(s string) *cloudflareValue {
	raw, _ := json.Marshal(s) // a Go string always encodes
	return &cloudflareValue{raw: raw}
}

func numberValue(f float64) *cloudflareValue {
	return &cloudflareValue{raw: json.RawMessage(strconv.FormatFloat(f, 'f', -1, 64))}
}

// cloudflareInput is the subset of a telemetry query an agent may send. Everything else, like
// queryId, datasets, timeframe or offset, is rejected as an unknown field.
type cloudflareInput struct {
	View              string                  `json:"view"`
	Filters           []cloudflareFilter      `json:"filters"`
	FilterCombination string                  `json:"filterCombination"`
	Needle            *cloudflareNeedle       `json:"needle"`
	Calculations      []cloudflareCalculation `json:"calculations"`
	GroupBys          []cloudflareGroupBy     `json:"groupBys"`
	Havings           []cloudflareHaving      `json:"havings"`
	OrderBy           *cloudflareOrderBy      `json:"orderBy"`
	Limit             int                     `json:"limit"`
}

// ScopeCloudflareQuery decodes an agent's telemetry query and wraps its filters in a group
// that is AND-combined with the scope filter. The view defaults to the first allowed view.
func ScopeCloudflareQuery(scope authz.CloudflareScope, text string, allowedViews ...string) (CloudflareQuery, error) {
	in, err := decodeCloudflareInput(text)
	if err != nil {
		return CloudflareQuery{}, apierr.InvalidQuery("invalid Cloudflare query: %v", err)
	}
	if in.View == "" {
		in.View = allowedViews[0]
	}
	if !slices.Contains(allowedViews, in.View) {
		return CloudflareQuery{}, apierr.InvalidQuery("view %q is not allowed here, expected one of %s", in.View, strings.Join(allowedViews, ", "))
	}
	if err := validateCloudflareInput(in); err != nil {
		return CloudflareQuery{}, apierr.InvalidQuery("invalid Cloudflare query: %v", err)
	}
	filters, err := normalizeFilters(in.Filters, 1)
	if err != nil {
		return CloudflareQuery{}, apierr.InvalidQuery("invalid Cloudflare query: %v", err)
	}
	parameters := scopedParameters(scope, in.FilterCombination, filters)
	parameters.Needle = in.Needle
	parameters.Calculations = in.Calculations
	parameters.GroupBys = in.GroupBys
	parameters.Havings = in.Havings
	parameters.OrderBy = in.OrderBy
	return CloudflareQuery{view: in.View, limit: in.Limit, parameters: parameters}, nil
}

func decodeCloudflareInput(text string) (cloudflareInput, error) {
	var in cloudflareInput
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return in, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return in, errors.New("query must be a single JSON object")
	}
	return in, nil
}

func validateCloudflareInput(in cloudflareInput) error {
	if in.Limit < 0 || in.Limit > cloudflareMaxLimit {
		return fmt.Errorf("limit must be between 0 and %d", cloudflareMaxLimit)
	}
	if in.Needle != nil && in.Needle.Value.raw == nil {
		return errors.New("needle value is required")
	}
	if in.FilterCombination != "" && !slices.Contains(cloudflareCombinations, in.FilterCombination) {
		return fmt.Errorf("filterCombination must be and or or, got %q", in.FilterCombination)
	}
	for _, c := range in.Calculations {
		if c.Operator == "" {
			return errors.New("calculation operator is required")
		}
		if c.KeyType != "" && !slices.Contains(cloudflareTypes, c.KeyType) {
			return fmt.Errorf("calculation keyType must be string, number or boolean, got %q", c.KeyType)
		}
	}
	for _, g := range in.GroupBys {
		if g.Value == "" || !slices.Contains(cloudflareTypes, g.Type) {
			return fmt.Errorf("groupBy needs a value and a type of string, number or boolean")
		}
	}
	for _, h := range in.Havings {
		if h.Key == "" || !slices.Contains(cloudflareHavingOperations, h.Operation) {
			return fmt.Errorf("having needs a key and an operation of %s", strings.Join(cloudflareHavingOperations, ", "))
		}
	}
	if in.OrderBy != nil && (in.OrderBy.Value == "" || !slices.Contains([]string{"", "asc", "desc"}, in.OrderBy.Order)) {
		return errors.New("orderBy needs a value and an order of asc or desc")
	}
	return nil
}

// normalizeFilters validates filters at the given depth and drops the optional leaf kind.
func normalizeFilters(filters []cloudflareFilter, depth int) ([]cloudflareFilter, error) {
	if depth > cloudflareMaxAgentDepth {
		return nil, fmt.Errorf("filter groups nest more than %d levels deep", cloudflareMaxAgentDepth)
	}
	normalized := make([]cloudflareFilter, 0, len(filters))
	for _, f := range filters {
		switch f.Kind {
		case "group":
			if f.Key != "" || f.Operation != "" || f.Type != "" || f.Value != nil {
				return nil, errors.New("a filter group cannot have key, operation, type or value")
			}
			if !slices.Contains(cloudflareCombinations, f.FilterCombination) {
				return nil, fmt.Errorf("filter group filterCombination must be and or or, got %q", f.FilterCombination)
			}
			if len(f.Filters) == 0 {
				return nil, errors.New("filter group needs filters")
			}
			children, err := normalizeFilters(f.Filters, depth+1)
			if err != nil {
				return nil, err
			}
			normalized = append(normalized, cloudflareFilter{Kind: "group", FilterCombination: f.FilterCombination, Filters: children})
		case "", "filter":
			if f.FilterCombination != "" || f.Filters != nil {
				return nil, errors.New(`a filter leaf cannot have filterCombination or filters; use kind "group"`)
			}
			if f.Key == "" {
				return nil, errors.New("filter key is required")
			}
			if !slices.Contains(cloudflareOperations, f.Operation) {
				return nil, fmt.Errorf("filter operation %q is not one of %s", f.Operation, strings.Join(cloudflareOperations, ", "))
			}
			if !slices.Contains(cloudflareTypes, f.Type) {
				return nil, fmt.Errorf("filter type must be string, number or boolean, got %q", f.Type)
			}
			normalized = append(normalized, cloudflareFilter{Key: f.Key, Operation: f.Operation, Type: f.Type, Value: f.Value})
		default:
			return nil, fmt.Errorf(`filter kind must be "filter" or "group", got %q`, f.Kind)
		}
	}
	return normalized, nil
}

// scopedParameters puts the scope filter first and the agent's filters, if any, into one group.
func scopedParameters(scope authz.CloudflareScope, combination string, filters []cloudflareFilter) cloudflareParameters {
	scoped := []cloudflareFilter{scopeFilter(scope)}
	if len(filters) > 0 {
		if combination == "" {
			combination = "and"
		}
		scoped = append(scoped, cloudflareFilter{Kind: "group", FilterCombination: combination, Filters: filters})
	}
	return cloudflareParameters{FilterCombination: "and", Filters: scoped}
}

func scopeFilter(scope authz.CloudflareScope) cloudflareFilter {
	return cloudflareFilter{Key: "$metadata.service", Operation: "eq", Type: "string", Value: textValue(scope.Script())}
}

// CloudflareLogSearch translates a backend-neutral log search into an events query and a
// count query with the same filters. The first contains text becomes the needle.
func CloudflareLogSearch(scope authz.CloudflareScope, f LogFilter, limit int) (events, count CloudflareQuery, err error) {
	if strings.TrimSpace(f.Pipeline) != "" {
		return CloudflareQuery{}, CloudflareQuery{}, apierr.InvalidRequest("pipeline is supported only for Loki sources")
	}
	var filters []cloudflareFilter
	var needle *cloudflareNeedle
	for i, text := range f.Contains {
		if i == 0 {
			needle = &cloudflareNeedle{Value: *textValue(text), MatchCase: true}
			continue
		}
		filters = append(filters, cloudflareFilter{Key: "$metadata.message", Operation: "includes", Type: "string", Value: textValue(text)})
	}
	filters = append(filters, whereFilters(f.Where)...)

	parameters := scopedParameters(scope, "and", filters)
	parameters.Needle = needle
	countParameters := parameters
	countParameters.Calculations = []cloudflareCalculation{{Operator: "count"}}
	events = CloudflareQuery{view: CloudflareViewEvents, limit: min(limit, cloudflareMaxLimit), parameters: parameters}
	count = CloudflareQuery{view: CloudflareViewCalculations, parameters: countParameters}
	return events, count, nil
}

// CloudflareTraceSearch translates a backend-neutral trace search into a traces query over
// spans of the scoped script.
func CloudflareTraceSearch(scope authz.CloudflareScope, f TraceFilter, limit int) (CloudflareQuery, error) {
	var filters []cloudflareFilter
	if f.MinDuration > 0 {
		filters = append(filters, cloudflareFilter{Key: "$metadata.duration", Operation: "gte", Type: "number", Value: numberValue(milliseconds(f.MinDuration))})
	}
	if f.MaxDuration > 0 {
		filters = append(filters, cloudflareFilter{Key: "$metadata.duration", Operation: "lte", Type: "number", Value: numberValue(milliseconds(f.MaxDuration))})
	}
	if f.Errors {
		filters = append(filters, cloudflareFilter{Key: "$metadata.error", Operation: "exists", Type: "string"})
	}
	if f.Name != "" {
		filters = append(filters, cloudflareFilter{Key: "$metadata.spanName", Operation: "includes", Type: "string", Value: textValue(f.Name)})
	}
	filters = append(filters, whereFilters(f.Where)...)
	return CloudflareQuery{view: CloudflareViewTraces, limit: min(limit, cloudflareMaxLimit), parameters: scopedParameters(scope, "and", filters)}, nil
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func whereFilters(where []Where) []cloudflareFilter {
	filters := make([]cloudflareFilter, 0, len(where))
	for _, w := range where {
		operation := "eq"
		if w.Negate {
			operation = "neq"
		}
		filters = append(filters, cloudflareFilter{Key: w.Field, Operation: operation, Type: "string", Value: textValue(w.Value)})
	}
	return filters
}

// CloudflareTraceByID fetches the events of one trace. It is not scoped by service, because a
// trace spans services; the caller checks that the trace contains a span of the scoped script.
func CloudflareTraceByID(_ authz.CloudflareScope, id string) CloudflareQuery {
	return CloudflareQuery{
		view:  CloudflareViewEvents,
		limit: cloudflareTraceByIDLimit,
		parameters: cloudflareParameters{
			FilterCombination: "and",
			Filters:           []cloudflareFilter{{Key: "$metadata.traceId", Operation: "eq", Type: "string", Value: textValue(id)}},
		},
	}
}

type cloudflareKeysBody struct {
	From    int64              `json:"from"`
	To      int64              `json:"to"`
	Filters []cloudflareFilter `json:"filters"`
	Limit   int                `json:"limit"`
}

// CloudflareKeys is the request body that lists the event fields of the scoped script.
func CloudflareKeys(scope authz.CloudflareScope, r api.TimeRange) ([]byte, error) {
	return json.Marshal(cloudflareKeysBody{
		From:    r.From.UnixMilli(),
		To:      r.To.UnixMilli(),
		Filters: []cloudflareFilter{scopeFilter(scope)},
		Limit:   cloudflareKeysLimit,
	})
}
