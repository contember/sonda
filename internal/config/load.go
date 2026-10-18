package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"go.yaml.in/yaml/v3"
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
	Signals      map[string]string         `yaml:"signals"`
}

type rawEnvironment struct {
	Errors  *rawErrorBinding    `yaml:"errors"`
	Logs    *rawSelectorBinding `yaml:"logs"`
	Metrics *rawSelectorBinding `yaml:"metrics"`
}

type rawErrorBinding struct {
	Source      string `yaml:"source"`
	Project     string `yaml:"project"`
	Environment string `yaml:"environment"`
}

type rawSelectorBinding struct {
	Source   string `yaml:"source"`
	Selector string `yaml:"selector"`
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
// allowed only in source URLs, credentials, headers and the admin token.
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

func (v *validator) source(name string, raw rawSource) *Source {
	path := "sources." + name
	src := &Source{
		Name:                 name,
		Type:                 SourceType(raw.Type),
		URL:                  v.expand(path+".url", raw.URL),
		Headers:              map[string]string{},
		SentryOrg:            raw.Org,
		GrafanaDatasourceUID: raw.GrafanaDatasourceUID,
	}
	switch src.Type {
	case SourceSentry:
		if src.URL == "" {
			src.URL = "https://sentry.io"
		}
		if raw.Org == "" {
			v.fail("%s.org is required for sentry sources", path)
		}
	case SourceLoki, SourcePrometheus:
		if raw.Org != "" {
			v.fail("%s.org is allowed only for sentry sources", path)
		}
	default:
		v.fail("%s.type must be sentry, loki or prometheus, got %q", path, raw.Type)
	}
	v.url(path+".url", src.URL)
	src.Auth = v.auth(path+".auth", raw.Auth)
	for header, value := range raw.Headers {
		src.Headers[header] = v.expand(path+".headers."+header, value)
	}
	return src
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
		Signals:      map[string]string{},
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
			env.Logs = v.selectorBinding(envPath+".logs", *re.Logs, sources, SourceLoki, parseLogSelector)
		}
		if re.Metrics != nil {
			env.Metrics = v.selectorBinding(envPath+".metrics", *re.Metrics, sources, SourcePrometheus, parseMetricSelector)
		}
		if len(env.Capabilities()) == 0 {
			v.fail("%s: at least one of errors, logs or metrics is required", envPath)
		}
		svc.Environments[envName] = env
	}
	for signal, expr := range raw.Signals {
		if _, err := parser.NewParser(parser.Options{}).ParseExpr(expr); err != nil {
			v.fail("%s.signals.%s: invalid PromQL: %v", path, signal, err)
		}
		svc.Signals[signal] = expr
	}
	return svc
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

func (v *validator) selectorBinding(
	path string,
	raw rawSelectorBinding,
	sources map[string]*Source,
	sourceType SourceType,
	parse func(string) ([]*labels.Matcher, error),
) *SelectorBinding {
	src := v.sourceRef(path+".source", raw.Source, sources, sourceType)
	matchers, err := parse(raw.Selector)
	if err != nil {
		v.fail("%s.selector: %v", path, err)
	} else if !restrictsScope(matchers) {
		v.fail("%s.selector %q must contain an = or =~ matcher that rejects the empty value, e.g. app=\"name\"", path, raw.Selector)
	}
	return &SelectorBinding{Source: src, Selector: raw.Selector, Matchers: matchers}
}

func (v *validator) sourceRef(path, name string, sources map[string]*Source, want SourceType) *Source {
	src, ok := sources[name]
	if !ok {
		v.fail("%s: unknown source %q", path, name)
		return nil
	}
	if src.Type != want {
		v.fail("%s: source %q has type %s, expected %s", path, name, src.Type, want)
	}
	return src
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
	return syntax.ParseMatchers(selector, true)
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
