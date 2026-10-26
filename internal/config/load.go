package config

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"go.yaml.in/yaml/v3"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/logql"
	"github.com/contember/sonda/internal/telemetry"
)

type rawConfig struct {
	Server   rawServer             `yaml:"server"`
	Admin    *rawAdmin             `yaml:"admin"`
	Grafana  *rawGrafana           `yaml:"grafana"`
	Sources  map[string]rawSource  `yaml:"sources"`
	Services map[string]rawService `yaml:"services"`
	Limits   rawLimits             `yaml:"limits"`
	Redact   []string              `yaml:"redact"`
}

type rawServer struct {
	Listen   string `yaml:"listen"`
	Database string `yaml:"database"`
}

type rawAdmin struct {
	Token string `yaml:"token"`
}

type rawGrafana struct {
	URL string `yaml:"url"`
}

type rawSource struct {
	Type                 string            `yaml:"type"`
	URL                  string            `yaml:"url"`
	Org                  string            `yaml:"org"`
	Auth                 rawAuth           `yaml:"auth"`
	Headers              map[string]string `yaml:"headers"`
	GrafanaDatasourceUID string            `yaml:"grafana_datasource_uid"`
	AccountID            string            `yaml:"account_id"`
	Region               string            `yaml:"region"`
	RoleARN              string            `yaml:"role_arn"`
	ExternalID           string            `yaml:"external_id"`
	MaxScanBytes         string            `yaml:"max_scan_bytes"`
	CAFile               string            `yaml:"ca_file"`
}

type rawAuth struct {
	Type     string `yaml:"type"`
	Token    string `yaml:"token"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type rawService struct {
	Description  string                    `yaml:"description"`
	Repository   string                    `yaml:"repository"`
	Environments map[string]rawEnvironment `yaml:"environments"`
	// Signals are decoded as nodes, because a signal is either a PromQL string or a mapping.
	Signals map[string]yaml.Node `yaml:"signals"`
}

type rawEnvironment struct {
	Errors    *rawErrorBinding    `yaml:"errors"`
	Logs      *rawBinding         `yaml:"logs"`
	Metrics   *rawBinding         `yaml:"metrics"`
	Traces    *rawBinding         `yaml:"traces"`
	Workloads *rawWorkloadBinding `yaml:"workloads"`
	Alerts    *rawBinding         `yaml:"alerts"`
}

type rawWorkloadBinding struct {
	Source    string            `yaml:"source"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels"`
}

type rawErrorBinding struct {
	Source      string `yaml:"source"`
	Project     string `yaml:"project"`
	Environment string `yaml:"environment"`
}

// rawBinding holds the fields of every log, metric and trace binding variant; the source
// type decides which of them are allowed.
type rawBinding struct {
	Source      string            `yaml:"source"`
	Selector    string            `yaml:"selector"`
	Script      string            `yaml:"script"`
	LogGroups   []string          `yaml:"log_groups"`
	Namespace   string            `yaml:"namespace"`
	Dimensions  map[string]string `yaml:"dimensions"`
	Service     string            `yaml:"service"`
	Project     string            `yaml:"project"`
	Environment string            `yaml:"environment"`

	DurableObjectNamespaces map[string]string `yaml:"durable_object_namespaces"`
	D1Databases             map[string]string `yaml:"d1_databases"`
	Queues                  map[string]string `yaml:"queues"`
	R2Buckets               map[string]string `yaml:"r2_buckets"`
}

func (raw rawBinding) cloudflareResources() map[telemetry.CloudflareResource]map[string]string {
	return map[telemetry.CloudflareResource]map[string]string{
		telemetry.CloudflareDurableObjectNamespaces: raw.DurableObjectNamespaces,
		telemetry.CloudflareD1Databases:             raw.D1Databases,
		telemetry.CloudflareQueues:                  raw.Queues,
		telemetry.CloudflareR2Buckets:               raw.R2Buckets,
	}
}

type rawLimits struct {
	MaxRange          string `yaml:"max_range"`
	MaxLogLines       *int   `yaml:"max_log_lines"`
	MaxResponseBytes  *int   `yaml:"max_response_bytes"`
	QueryTimeout      string `yaml:"query_timeout"`
	ConcurrentQueries *int   `yaml:"concurrent_queries"`
	RequestsPerMinute *int   `yaml:"requests_per_minute"`
}

func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, os.LookupEnv)
}

// Parse validates the YAML configuration. lookupEnv resolves ${NAME} references, which are
// allowed only in source URLs, credentials, account IDs, role ARNs, headers and the admin token.
func Parse(data []byte, lookupEnv func(string) (string, bool)) (*Config, error) {
	var raw rawConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	v := &validator{lookupEnv: lookupEnv}
	cfg := v.config(raw)
	if err := errors.Join(v.errs...); err != nil {
		return nil, err
	}
	return cfg, nil
}

type validator struct {
	lookupEnv func(string) (string, bool)
	errs      []error
}

func (v *validator) fail(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

func (v *validator) config(raw rawConfig) *Config {
	cfg := &Config{
		Server: Server{
			Listen:   valueOr(raw.Server.Listen, ":8080"),
			Database: valueOr(raw.Server.Database, "sonda.db"),
		},
		Sources:  map[string]*Source{},
		Services: map[string]*Service{},
		Redact:   raw.Redact,
	}
	if raw.Admin != nil {
		cfg.Admin = v.admin(*raw.Admin)
	}
	if raw.Grafana != nil {
		v.url("grafana.url", raw.Grafana.URL)
		cfg.Grafana = &Grafana{URL: raw.Grafana.URL}
	}
	for _, pattern := range raw.Redact {
		if _, err := regexp.Compile(pattern); err != nil {
			v.fail("redact: invalid pattern %q: %v", pattern, err)
		}
	}
	for name, rs := range raw.Sources {
		cfg.Sources[name] = v.source(name, rs)
	}
	for name, rs := range raw.Services {
		cfg.Services[name] = v.service(name, rs, cfg.Sources)
	}
	cfg.Limits = v.limits("limits", raw.Limits, DefaultLimits)
	return cfg
}

// minAdminTokenLength keeps the admin token out of reach of guessing.
const minAdminTokenLength = 32

func (v *validator) admin(raw rawAdmin) *Admin {
	token := v.expand("admin.token", raw.Token)
	if len(token) < minAdminTokenLength {
		v.fail("admin.token must have at least %d characters (generate one with `openssl rand -hex 32`)", minAdminTokenLength)
	}
	return &Admin{Token: token}
}

const (
	defaultCloudflareURL = "https://api.cloudflare.com/client/v4"
	defaultMaxScanBytes  = 10 * humanize.GByte
)

func (v *validator) source(name string, raw rawSource) *Source {
	path := "sources." + name
	src := &Source{
		Name:                 name,
		Type:                 SourceType(raw.Type),
		URL:                  v.expand(path+".url", raw.URL),
		Headers:              map[string]string{},
		SentryOrg:            raw.Org,
		GrafanaDatasourceUID: raw.GrafanaDatasourceUID,
		CloudflareAccountID:  v.expand(path+".account_id", raw.AccountID),
	}
	v.onlyFor(path+".org", raw.Org != "", src.Type, SourceSentry)
	v.onlyFor(path+".account_id", raw.AccountID != "", src.Type, SourceCloudflare)
	v.onlyFor(path+".region", raw.Region != "", src.Type, SourceAWS)
	v.onlyFor(path+".role_arn", raw.RoleARN != "", src.Type, SourceAWS)
	v.onlyFor(path+".external_id", raw.ExternalID != "", src.Type, SourceAWS)
	v.onlyFor(path+".max_scan_bytes", raw.MaxScanBytes != "", src.Type, SourceAWS)
	v.onlyFor(path+".ca_file", raw.CAFile != "", src.Type, SourceKubernetes)
	switch src.Type {
	case SourceSentry:
		if src.URL == "" {
			src.URL = "https://sentry.io"
		}
		if raw.Org == "" {
			v.fail("%s.org is required for sentry sources", path)
		}
	case SourceLoki, SourcePrometheus, SourceTempo, SourceGrafana:
	case SourceCloudflare:
		if src.URL == "" {
			src.URL = defaultCloudflareURL
		}
		if raw.AccountID == "" {
			v.fail("%s.account_id is required for cloudflare sources", path)
		}
		if raw.Auth.Type != string(AuthBearer) {
			v.fail("%s.auth must be bearer for cloudflare sources", path)
		}
	case SourceAWS:
		src.AWS = v.awsSource(path, raw)
		src.Auth = Auth{Type: AuthNone}
		return src
	case SourceKubernetes:
		if src.URL == "" {
			return v.inClusterSource(path, src, raw)
		}
		if raw.Auth.Type != string(AuthBearer) {
			v.fail("%s.auth must be bearer for kubernetes sources with a url", path)
		}
		if raw.CAFile != "" {
			src.RootCAs = v.caFile(path+".ca_file", raw.CAFile)
		}
	default:
		v.fail("%s.type must be sentry, loki, prometheus, tempo, cloudflare, aws, kubernetes or grafana, got %q", path, raw.Type)
	}
	v.url(path+".url", src.URL)
	src.Auth = v.auth(path+".auth", raw.Auth)
	for header, value := range raw.Headers {
		src.Headers[header] = v.expand(path+".headers."+header, value)
	}
	return src
}

// In-cluster Kubernetes paths, mounted into every pod with a service account.
const (
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// inClusterSource connects a Kubernetes source without a url to the API server of the cluster
// Sonda runs in, with the pod's service account.
func (v *validator) inClusterSource(path string, src *Source, raw rawSource) *Source {
	if raw.Auth != (rawAuth{}) || raw.CAFile != "" {
		v.fail("%s: auth and ca_file require a url; without one, the source uses the pod's service account", path)
	}
	host, hostOK := v.lookupEnv("KUBERNETES_SERVICE_HOST")
	port, portOK := v.lookupEnv("KUBERNETES_SERVICE_PORT")
	if !hostOK || !portOK {
		v.fail("%s.url is required outside a Kubernetes pod (KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set)", path)
		return src
	}
	src.URL = "https://" + net.JoinHostPort(host, port)
	src.Auth = Auth{Type: AuthBearer, TokenFile: inClusterTokenFile}
	src.RootCAs = v.caFile(path, inClusterCAFile)
	for header, value := range raw.Headers {
		src.Headers[header] = v.expand(path+".headers."+header, value)
	}
	return src
}

// caFile reads PEM certificates the source's server certificate must chain to.
func (v *validator) caFile(path, file string) *x509.CertPool {
	data, err := os.ReadFile(file)
	if err != nil {
		v.fail("%s: %v", path, err)
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		v.fail("%s: %s contains no PEM certificate", path, file)
		return nil
	}
	return pool
}

// awsSource validates an AWS source. It talks to AWS through the SDK, which resolves the
// endpoint and credentials, so url, auth and headers do not apply.
func (v *validator) awsSource(path string, raw rawSource) *AWSSource {
	if raw.URL != "" {
		v.fail("%s.url is not allowed for aws sources", path)
	}
	if raw.Auth != (rawAuth{}) {
		v.fail("%s.auth is not allowed for aws sources; credentials come from the AWS credential chain", path)
	}
	if len(raw.Headers) > 0 {
		v.fail("%s.headers is not allowed for aws sources", path)
	}
	if raw.Region == "" {
		v.fail("%s.region is required for aws sources", path)
	}
	aws := &AWSSource{
		Region:       raw.Region,
		RoleARN:      v.expand(path+".role_arn", raw.RoleARN),
		ExternalID:   v.expand(path+".external_id", raw.ExternalID),
		MaxScanBytes: defaultMaxScanBytes,
	}
	if raw.ExternalID != "" && raw.RoleARN == "" {
		v.fail("%s.external_id is allowed only with role_arn", path)
	}
	if raw.MaxScanBytes != "" {
		aws.MaxScanBytes = v.byteSize(path+".max_scan_bytes", raw.MaxScanBytes)
	}
	return aws
}

// onlyFor reports a source field that is set on a source of another type.
func (v *validator) onlyFor(path string, set bool, sourceType, allowed SourceType) {
	if set && sourceType != allowed {
		v.fail("%s is allowed only for %s sources", path, allowed)
	}
}

func (v *validator) auth(path string, raw rawAuth) Auth {
	auth := Auth{
		Type:     AuthType(valueOr(raw.Type, string(AuthNone))),
		Token:    v.expand(path+".token", raw.Token),
		Username: v.expand(path+".username", raw.Username),
		Password: v.expand(path+".password", raw.Password),
	}
	switch auth.Type {
	case AuthNone:
		if auth.Token != "" || auth.Username != "" || auth.Password != "" {
			v.fail("%s: credentials given but type is none", path)
		}
	case AuthBearer:
		if auth.Token == "" {
			v.fail("%s.token is required for bearer auth", path)
		}
	case AuthBasic:
		if auth.Username == "" || auth.Password == "" {
			v.fail("%s: username and password are required for basic auth", path)
		}
	default:
		v.fail("%s.type must be none, bearer or basic, got %q", path, raw.Type)
	}
	return auth
}

func (v *validator) service(name string, raw rawService, sources map[string]*Source) *Service {
	path := "services." + name
	svc := &Service{
		Name:         name,
		Description:  raw.Description,
		Repository:   raw.Repository,
		Environments: map[string]*Environment{},
	}
	if len(raw.Environments) == 0 {
		v.fail("%s.environments: at least one environment is required", path)
	}
	for envName, re := range raw.Environments {
		envPath := path + ".environments." + envName
		env := &Environment{Name: envName}
		if re.Errors != nil {
			env.Errors = v.errorBinding(envPath+".errors", *re.Errors, sources)
		}
		if re.Logs != nil {
			env.Logs = v.logBinding(envPath+".logs", *re.Logs, sources)
		}
		if re.Metrics != nil {
			env.Metrics = v.metricBinding(envPath+".metrics", *re.Metrics, sources)
		}
		if re.Traces != nil {
			env.Traces = v.traceBinding(envPath+".traces", *re.Traces, sources)
		}
		if re.Workloads != nil {
			env.Workloads = v.workloadBinding(envPath+".workloads", *re.Workloads, sources)
		}
		if re.Alerts != nil {
			env.Alerts = v.alertBinding(envPath+".alerts", *re.Alerts, sources)
		}
		if len(env.Capabilities()) == 0 {
			v.fail("%s: at least one of errors, logs, metrics, traces, workloads or alerts is required", envPath)
		}
		svc.Environments[envName] = env
	}
	svc.Signals = v.signals(path+".signals", raw.Signals, svc.Environments)
	return svc
}

// signals validates the signals in the dialect of the service's metrics backend, which all
// metrics environments must share.
func (v *validator) signals(path string, raw map[string]yaml.Node, envs map[string]*Environment) map[string]Signal {
	signals := map[string]Signal{}
	if len(raw) == 0 {
		return signals
	}
	var metrics *MetricBinding
	var types []SourceType
	for _, env := range envs {
		if env.Metrics != nil && env.Metrics.Source != nil && !slices.Contains(types, env.Metrics.Source.Type) {
			metrics = env.Metrics
			types = append(types, env.Metrics.Source.Type)
		}
	}
	switch {
	case len(types) == 0:
		v.fail("%s: signals require an environment with metrics", path)
		return signals
	case len(types) > 1:
		names := make([]string, len(types))
		for i, t := range types {
			names[i] = string(t)
		}
		slices.Sort(names)
		v.fail("%s: signals require all metrics environments to use one source type, got %s", path, strings.Join(names, ", "))
		return signals
	}
	dialect := metrics.Dialect()
	for name, node := range raw {
		query, err := signalQuery(node, dialect)
		if err != nil {
			v.fail("%s.%s: %v", path, name, err)
			continue
		}
		if dialect == api.DialectCloudflareMetric {
			v.signalResources(path+"."+name, query, envs)
		}
		signals[name] = Signal{Dialect: dialect, Query: query}
	}
	return signals
}

// signalResources requires the resource kind a Cloudflare signal reads in every metrics
// environment, so the signal does not fail in some of them only.
func (v *validator) signalResources(path, query string, envs map[string]*Environment) {
	q, err := telemetry.DecodeCloudflareMetricQuery(query)
	if err != nil {
		v.fail("%s: %v", path, err)
		return
	}
	kind := telemetry.CloudflareMetrics[q.Metric].Resource
	if kind == telemetry.CloudflareScript {
		return
	}
	for envName, env := range envs {
		if env.Metrics != nil && len(env.Metrics.CloudflareResources[kind]) == 0 {
			v.fail("%s: metric %s needs %s in the metrics binding of environment %s", path, q.Metric, kind, envName)
		}
	}
}

// signalQuery returns the signal as query text of the dialect: PromQL as written, or the
// canonical JSON of a structured metric query.
func signalQuery(node yaml.Node, dialect api.Dialect) (string, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		if dialect != api.DialectPromQL {
			return "", fmt.Errorf("a string signal is PromQL, but the metrics dialect is %s; use a mapping", dialect)
		}
		if _, err := parser.NewParser(parser.Options{}).ParseExpr(node.Value); err != nil {
			return "", fmt.Errorf("invalid PromQL: %v", err)
		}
		return node.Value, nil
	case yaml.MappingNode:
		// The mapping goes through JSON, so it gets the same strict decoding as a native query.
		var fields map[string]any
		if err := node.Decode(&fields); err != nil {
			return "", err
		}
		text, err := json.Marshal(fields)
		if err != nil {
			return "", err
		}
		switch dialect {
		case api.DialectCloudflareMetric:
			return canonical(string(text), telemetry.DecodeCloudflareMetricQuery)
		case api.DialectCloudWatchMetric:
			return canonical(string(text), telemetry.DecodeCloudWatchMetricQuery)
		}
		return "", fmt.Errorf("a mapping signal needs cloudflare or aws metrics, but the metrics dialect is %s", dialect)
	}
	return "", errors.New("must be a PromQL string or a mapping")
}

// canonical decodes a structured query and encodes it again, so the stored text holds only
// known fields in a stable order.
func canonical[T any](text string, decode func(string) (T, error)) (string, error) {
	query, err := decode(text)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(query)
	return string(encoded), err
}

func (v *validator) errorBinding(path string, raw rawErrorBinding, sources map[string]*Source) *ErrorBinding {
	src := v.sourceRef(path+".source", raw.Source, sources, SourceSentry)
	if raw.Project == "" {
		v.fail("%s.project is required", path)
	}
	if raw.Environment == "" {
		v.fail("%s.environment is required", path)
	}
	return &ErrorBinding{Source: src, Project: raw.Project, Environment: raw.Environment}
}

func (v *validator) logBinding(path string, raw rawBinding, sources map[string]*Source) *LogBinding {
	src := v.sourceRef(path+".source", raw.Source, sources, SourceLoki, SourceCloudflare, SourceAWS)
	binding := &LogBinding{Source: src}
	if src == nil {
		// The source type is unknown, but the fields can still be checked on their own.
		if raw.Selector != "" {
			v.selector(path, raw.Selector, parseLogSelector)
		}
		if raw.LogGroups != nil {
			v.logGroups(path, raw.LogGroups)
		}
		return binding
	}
	switch src.Type {
	case SourceLoki:
		v.bindingFields(path, raw, src, "selector")
		binding.Selector = v.selector(path, raw.Selector, parseLogSelector)
	case SourceCloudflare:
		v.bindingFields(path, raw, src, "script")
		binding.Script = v.script(path, raw.Script)
	case SourceAWS:
		v.bindingFields(path, raw, src, "log_groups")
		binding.LogGroups = v.logGroups(path, raw.LogGroups)
	}
	return binding
}

func (v *validator) metricBinding(path string, raw rawBinding, sources map[string]*Source) *MetricBinding {
	src := v.sourceRef(path+".source", raw.Source, sources, SourcePrometheus, SourceCloudflare, SourceAWS)
	binding := &MetricBinding{Source: src}
	if src == nil {
		// The source type is unknown, but the fields can still be checked on their own.
		if raw.Selector != "" {
			v.selector(path, raw.Selector, parseMetricSelector)
		}
		if raw.Dimensions != nil {
			v.dimensions(path, raw.Dimensions)
		}
		return binding
	}
	switch src.Type {
	case SourcePrometheus:
		v.bindingFields(path, raw, src, "selector")
		binding.Selector = v.selector(path, raw.Selector, parseMetricSelector)
	case SourceCloudflare:
		v.bindingFields(path, raw, src, "script", "durable_object_namespaces", "d1_databases", "queues", "r2_buckets")
		binding.Script = v.script(path, raw.Script)
		binding.CloudflareResources = v.cloudflareResources(path, raw)
	case SourceAWS:
		v.bindingFields(path, raw, src, "namespace", "dimensions")
		if raw.Namespace == "" {
			v.fail("%s.namespace is required for aws sources", path)
		}
		binding.Namespace = raw.Namespace
		binding.Dimensions = v.dimensions(path, raw.Dimensions)
	}
	return binding
}

// alertBinding takes a Prometheus selector; alerts carry the labels of the series their rule
// evaluated, plus the rule's own labels.
func (v *validator) alertBinding(path string, raw rawBinding, sources map[string]*Source) *AlertBinding {
	src := v.sourceRef(path+".source", raw.Source, sources, SourcePrometheus, SourceGrafana)
	if src != nil {
		v.bindingFields(path, raw, src, "selector")
	}
	return &AlertBinding{Source: src, Selector: v.selector(path, raw.Selector, parseMetricSelector)}
}

func (v *validator) traceBinding(path string, raw rawBinding, sources map[string]*Source) *TraceBinding {
	src := v.sourceRef(path+".source", raw.Source, sources, SourceTempo, SourceCloudflare, SourceSentry)
	binding := &TraceBinding{Source: src}
	if src == nil {
		return binding
	}
	switch src.Type {
	case SourceTempo:
		v.bindingFields(path, raw, src, "service")
		if raw.Service == "" {
			v.fail("%s.service is required for tempo sources", path)
		}
		binding.ServiceName = raw.Service
	case SourceCloudflare:
		v.bindingFields(path, raw, src, "script")
		binding.Script = v.script(path, raw.Script)
	case SourceSentry:
		v.bindingFields(path, raw, src, "project", "environment")
		if raw.Project == "" {
			v.fail("%s.project is required for sentry sources", path)
		}
		if raw.Environment == "" {
			v.fail("%s.environment is required for sentry sources", path)
		}
		binding.Project, binding.Environment = raw.Project, raw.Environment
	}
	return binding
}

var (
	// kubernetesNamespace is a DNS-1123 label.
	kubernetesNamespace = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// kubernetesLabelKey is an optional DNS subdomain prefix and a name of at most 63 characters.
	kubernetesLabelKey   = regexp.MustCompile(`^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
	kubernetesLabelValue = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
)

// workloadBinding requires a namespace and at least one exact label. Empty values are rejected,
// so the scope never selects every object without the label.
func (v *validator) workloadBinding(path string, raw rawWorkloadBinding, sources map[string]*Source) *WorkloadBinding {
	src := v.sourceRef(path+".source", raw.Source, sources, SourceKubernetes)
	if !kubernetesNamespace.MatchString(raw.Namespace) {
		v.fail("%s.namespace %q must be a Kubernetes namespace name", path, raw.Namespace)
	}
	if len(raw.Labels) == 0 {
		v.fail("%s.labels must have at least one label, e.g. app.kubernetes.io/name: engine-api", path)
	}
	for key, value := range raw.Labels {
		if !kubernetesLabelKey.MatchString(key) {
			v.fail("%s.labels: %q is not a valid label key", path, key)
		}
		if !kubernetesLabelValue.MatchString(value) {
			v.fail("%s.labels.%s: %q must be a non-empty label value", path, key, value)
		}
	}
	return &WorkloadBinding{Source: src, Namespace: raw.Namespace, Labels: raw.Labels}
}

// bindingFields reports set fields that do not belong to the binding variant of the source.
func (v *validator) bindingFields(path string, raw rawBinding, src *Source, allowed ...string) {
	fields := []struct {
		name string
		set  bool
	}{
		{"selector", raw.Selector != ""},
		{"script", raw.Script != ""},
		{"log_groups", raw.LogGroups != nil},
		{"namespace", raw.Namespace != ""},
		{"dimensions", raw.Dimensions != nil},
		{"service", raw.Service != ""},
		{"project", raw.Project != ""},
		{"environment", raw.Environment != ""},
		{"durable_object_namespaces", raw.DurableObjectNamespaces != nil},
		{"d1_databases", raw.D1Databases != nil},
		{"queues", raw.Queues != nil},
		{"r2_buckets", raw.R2Buckets != nil},
	}
	for _, field := range fields {
		if field.set && !slices.Contains(allowed, field.name) {
			v.fail("%s.%s is not allowed for %s sources", path, field.name, src.Type)
		}
	}
}

func (v *validator) selector(path, raw string, parse func(string) ([]*labels.Matcher, error)) *Selector {
	matchers, err := parse(raw)
	if err != nil {
		v.fail("%s.selector: %v", path, err)
	} else if !restrictsScope(matchers) {
		v.fail("%s.selector %q must contain an = or =~ matcher that rejects the empty value, e.g. app=\"name\"", path, raw)
	}
	return &Selector{Text: raw, Matchers: matchers}
}

func (v *validator) script(path, raw string) string {
	if raw == "" {
		v.fail("%s.script is required for cloudflare sources", path)
	}
	return raw
}

var (
	cloudflareHexID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	cloudflareUUID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	r2BucketName      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	cloudflareIDForms = map[telemetry.CloudflareResource]struct {
		pattern     *regexp.Regexp
		description string
	}{
		telemetry.CloudflareDurableObjectNamespaces: {cloudflareHexID, "a namespace ID of 32 hex characters"},
		telemetry.CloudflareD1Databases:             {cloudflareUUID, "a database UUID"},
		telemetry.CloudflareQueues:                  {cloudflareHexID, "a queue ID of 32 hex characters, not the queue name"},
		telemetry.CloudflareR2Buckets:               {r2BucketName, "a bucket name"},
	}
)

// cloudflareResources validates the name-to-ID maps of a Cloudflare metrics binding. IDs must
// have the exact form Cloudflare uses, so a name given in place of an ID fails here instead of
// matching no data.
func (v *validator) cloudflareResources(path string, raw rawBinding) map[telemetry.CloudflareResource]map[string]string {
	resources := map[telemetry.CloudflareResource]map[string]string{}
	for kind, named := range raw.cloudflareResources() {
		if named == nil {
			continue
		}
		if len(named) == 0 {
			v.fail("%s.%s must not be empty", path, kind)
			continue
		}
		form := cloudflareIDForms[kind]
		seen := map[string]string{}
		for name, id := range named {
			switch {
			case name == "":
				v.fail("%s.%s: empty resource name", path, kind)
			case !form.pattern.MatchString(id):
				v.fail("%s.%s.%s: %q must be %s", path, kind, name, id, form.description)
			case seen[id] != "":
				v.fail("%s.%s: %s and %s have the same ID %q", path, kind, min(seen[id], name), max(seen[id], name), id)
			}
			seen[id] = name
		}
		resources[kind] = named
	}
	return resources
}

// maxLogGroups is the limit of log groups in one Logs Insights query.
const maxLogGroups = 50

// logGroups requires exact names, because a pattern would widen the scope as groups are added.
// An ARN is rejected too: the Logs Insights post-check compares names within the source's
// account and region.
func (v *validator) logGroups(path string, raw []string) []string {
	if len(raw) == 0 || len(raw) > maxLogGroups {
		v.fail("%s.log_groups must have 1 to %d entries", path, maxLogGroups)
	}
	seen := map[string]bool{}
	for _, group := range raw {
		switch {
		case group == "":
			v.fail("%s.log_groups: empty log group name", path)
		case strings.Contains(group, "*"):
			v.fail("%s.log_groups: %q must be an exact name, not a pattern", path, group)
		case strings.HasPrefix(group, "arn:"):
			v.fail("%s.log_groups: %q must be a log group name, not an ARN", path, group)
		case seen[group]:
			v.fail("%s.log_groups: duplicate log group %q", path, group)
		}
		seen[group] = true
	}
	return raw
}

// maxDimensionFilters is the limit of dimension filters in one ListMetrics call.
const maxDimensionFilters = 10

func (v *validator) dimensions(path string, raw map[string]string) map[string]string {
	if len(raw) == 0 || len(raw) > maxDimensionFilters {
		v.fail("%s.dimensions must have 1 to %d entries for aws sources", path, maxDimensionFilters)
	}
	for name, value := range raw {
		if name == "" || value == "" {
			v.fail("%s.dimensions: names and values must not be empty", path)
		}
	}
	return raw
}

func (v *validator) sourceRef(path, name string, sources map[string]*Source, want ...SourceType) *Source {
	src, ok := sources[name]
	if !ok {
		v.fail("%s: unknown source %q", path, name)
		return nil
	}
	if !slices.Contains(want, src.Type) {
		v.fail("%s: source %q has type %s, expected %s", path, name, src.Type, joinTypes(want))
	}
	return src
}

func joinTypes(types []SourceType) string {
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = string(t)
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

func (v *validator) limits(path string, raw rawLimits, base Limits) Limits {
	limits := base
	if raw.MaxRange != "" {
		limits.MaxRange = v.duration(path+".max_range", raw.MaxRange)
	}
	if raw.QueryTimeout != "" {
		limits.QueryTimeout = v.duration(path+".query_timeout", raw.QueryTimeout)
	}
	v.positive(path+".max_log_lines", raw.MaxLogLines, &limits.MaxLogLines)
	v.positive(path+".max_response_bytes", raw.MaxResponseBytes, &limits.MaxResponseBytes)
	v.positive(path+".concurrent_queries", raw.ConcurrentQueries, &limits.ConcurrentQueries)
	v.positive(path+".requests_per_minute", raw.RequestsPerMinute, &limits.RequestsPerMinute)
	return limits
}

func (v *validator) duration(path, raw string) time.Duration {
	d, err := model.ParseDuration(raw)
	if err != nil || d <= 0 {
		v.fail("%s: invalid duration %q", path, raw)
	}
	return time.Duration(d)
}

func (v *validator) byteSize(path, raw string) int64 {
	size, err := humanize.ParseBytes(raw)
	if err != nil || size == 0 || size > math.MaxInt64 {
		v.fail("%s: invalid size %q, expected a size like 10GB", path, raw)
		return 0
	}
	return int64(size)
}

func (v *validator) positive(path string, raw *int, target *int) {
	if raw == nil {
		return
	}
	if *raw <= 0 {
		v.fail("%s must be positive", path)
		return
	}
	*target = *raw
}

func (v *validator) url(path, raw string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		v.fail("%s: invalid URL %q", path, raw)
	}
}

var envReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func (v *validator) expand(path, raw string) string {
	return envReference.ReplaceAllStringFunc(raw, func(ref string) string {
		name := envReference.FindStringSubmatch(ref)[1]
		value, ok := v.lookupEnv(name)
		if !ok {
			v.fail("%s: environment variable %s is not set", path, name)
		}
		return value
	})
}

func parseLogSelector(selector string) ([]*labels.Matcher, error) {
	return logql.ParseSelector(selector)
}

func parseMetricSelector(selector string) ([]*labels.Matcher, error) {
	return parser.NewParser(parser.Options{}).ParseMetricSelector(selector)
}

// restrictsScope requires a positive matcher, because a negative one like job!="" still
// selects nearly everything.
func restrictsScope(matchers []*labels.Matcher) bool {
	return slices.ContainsFunc(matchers, func(m *labels.Matcher) bool {
		positive := m.Type == labels.MatchEqual || m.Type == labels.MatchRegexp
		return positive && !m.Matches("")
	})
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
