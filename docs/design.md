# Sonda — Technical Design (v1)

Status: implemented (v1). Deviations found during implementation are folded into this text.

Sonda is a self-hostable, read-only gateway that gives AI agents one credential and one
service-centric interface to production telemetry in Sentry, Loki, Prometheus, Cloudflare
Workers Observability, AWS CloudWatch and Grafana Tempo, and to application data in
Contember projects.
It stores no telemetry and no data. It queries sources on demand, enforces per-service
authorization, and returns compact, evidence-carrying responses.

## 1. Decisions

| Topic | Decision | Rejected alternative | Reason |
|---|---|---|---|
| Interface | HTTP API + `sonda` CLI | MCP server | No context cost until used. One contract (HTTP) for agents, bots and CI. MCP can be a thin adapter later. |
| Language | Go | TypeScript/Bun | The Prometheus PromQL parser and the AWS SDK are Go. Single static binary. |
| Binaries | `sonda-server` and `sonda` (CLI), one Go module | One binary with subcommands | The CLI imports only the `api` package, so it does not link the parsers, connectors or database drivers. |
| Native queries | Allowed, in each backend's own dialect, scoped to one service by `policy` | Plain passthrough; string concatenation | Passthrough leaks other services. String concatenation protects only one selector. |
| Query languages | Native dialect per backend (LogQL, PromQL, TraceQL, Logs Insights, Cloudflare query JSON, structured metric JSON) plus backend-neutral `logs search` and `traces search` | One Sonda query language translated to every backend | Agents already know the native dialects. A translated language covers only the common subset; the neutral search covers the common case. `describe` reports the dialect per capability. |
| TraceQL scoping | Own lexer `internal/traceql` | Tempo's parser | Tempo is AGPL-licensed, like Loki. Sonda is MIT. Same approach as `internal/logql`. |
| Logs Insights scoping | Own lexer `internal/insights` and an allowlist of commands | Rely on the `logGroupIdentifiers` API parameter alone | The query text can read other log groups itself (`SOURCE`, `join`, `appendcols`). AWS does not document which wins. |
| CloudWatch metrics | Only `MetricStat`, from JSON `{metric, stat, dimensions}` | `Expression`, `SEARCH`, Metrics Insights | They cannot be scoped (section 6). |
| Cloudflare queries | A JSON subset of the Workers Observability query, AND-wrapped with the script filter | Passthrough of the full request body | `queryId` runs a saved query and `datasets` changes what is read; both could bypass the filters. |
| Cloudflare metrics | Fixed catalog over GraphQL `workersInvocationsAdaptive`, query built by the server | Agent-written GraphQL | GraphQL can name any script or account. The server sets `scriptName` and `accountTag` as variables. |
| Data queries | Agent-written GraphQL for the Contember Content API, checked by `internal/gqlguard` against the API key's own schema | A fixed catalog of queries; plain passthrough | Questions about data are open-ended. Unlike Cloudflare GraphQL, the scope is not in the query: the server sets the project and stage in the URL, and the key's role decides what exists. The guard adds limits and field rules on top. |
| Write protection for data | A read-only Contember role, plus Sonda refusing any key whose schema can write | Trust the configuration | Two independent layers. A key with write rights would make every guard bug a write bug. |
| Code structure | Small backend interfaces per capability in `query` (`logBackend`, `metricBackend`, `traceBackend`) | Use cases calling concrete clients directly | Each capability has several backends. The use cases stay shared; each backend binds its typed scope and client. |
| Trace visibility | Spans of services without a `traces` grant become stubs | Reject traces that cross services; return them in full | A trace is useful only as a whole. Stubs show where time went without revealing names, attributes or events. |
| Configuration | Sources, services and limits in one YAML file, loaded at startup | Everything in a database | Reviewable in git. These change rarely and define the security boundary (bindings). |
| Identities | In the identity store, managed at runtime in the admin UI | In the YAML file | Tokens are created, rotated and revoked often; a restart for each change is impractical. |
| Identity store | `identities.Store` interface, implemented by `store` for SQLite and Postgres | SQLite only | Another database can be added without touching `authz` or the UI. |
| Admin UI | Server-rendered `html/template` + htmx, embedded in `sonda-server` | React SPA | No JS toolchain, one binary. The UI is a few forms and tables. |
| Provider secrets | Environment variable references in YAML; the AWS default credential chain | Encrypted in the database | No key management in v1. |
| Internal storage | SQLite (`modernc.org/sqlite`, pure Go) by default; Postgres (`pgx`) when `server.database` is a `postgres://` URL | SQLite only | SQLite needs no extra service. Postgres suits deployments without a persistent volume. Both hold identities, the audit log and result handles in the same tables and run the same queries; only the schema types and the unique-violation check differ. Metadata caches live in memory. |
| Loki/Prometheus/Tempo access | Direct connection to the native HTTP API | Through Grafana (`/api/ds/query` or the datasource proxy) | No dependency on Grafana, full API (e.g. `detected_fields`), clearer upstream errors. The Grafana datasource proxy still works as a plain `url` when Grafana is the only reachable endpoint. |
| Range limit | Reject ranges over `max_range` with `limit_exceeded` | Silently shorten the range | A shortened range would make counts look complete when they are not. |
| Native query capability | Same capability as the structured tools (`logs`, `metrics`, `traces`) | Separate `logs:native` / `metrics:native` | Native queries are scoped the same way; cost is bounded by limits. |
| Workspaces | One server = one workspace | Multi-workspace in v1 | No current need. Nothing in the model prevents adding it later. |

## 2. Domain model

```text
Source ──< Binding >── Environment ──< Service
                                         │
Identity ──< Grant (services × environments × capabilities)
```

- **Source**: a connection to a backend. Types:

  | Type | Backend | Capabilities | Connection |
  |---|---|---|---|
  | `sentry` | Sentry | errors | `url`, `org`, auth |
  | `loki` | Loki | logs | `url`, auth, headers |
  | `prometheus` | Prometheus, Mimir, Thanos, VictoriaMetrics, Grafana Cloud | metrics | `url`, auth, headers |
  | `cloudflare` | Workers Observability, GraphQL Analytics | logs, metrics, traces | `account_id`, bearer token; `url` defaults to `https://api.cloudflare.com/client/v4` |
  | `aws` | CloudWatch Logs Insights, CloudWatch metrics | logs, metrics | `region`, optional `role_arn` + `external_id`, `max_scan_bytes` (default 10 GB) |
  | `tempo` | Grafana Tempo | traces | `url`, auth, headers |
  | `contember` | Contember Content API | data | `url` (engine base URL), bearer API key, headers |

  Auth is `none`, `bearer` or `basic`. Extra headers carry e.g. `X-Scope-OrgID` for
  multi-tenant Loki, Mimir or Tempo. AWS has no URL, auth or headers: credentials come from
  the default credential chain (IRSA, environment, profile), or from assuming `role_arn`.
- **Grafana** (optional): base URL and a datasource UID per source. Used only to build Explore
  links in responses. Sonda does not query Grafana.
- **Service**: a logical application. Has a description, an optional repository, environments and
  signals.
- **Environment**: per service, maps each capability to a source and a binding. The binding is
  the scope. Its fields depend on the source type; fields of another type are rejected.

  | Capability | Source type | Binding |
  |---|---|---|
  | `errors` | `sentry` | `project` + Sentry `environment` |
  | `logs` | `loki` | `selector`, e.g. `{app="engine", namespace="prod"}` |
  | `logs` | `cloudflare` | `script` (Worker script name) |
  | `logs` | `aws` | `log_groups`: 1 to 50 unique, exact names (not ARNs), no `*` |
  | `metrics` | `prometheus` | `selector`, e.g. `{job="engine", namespace="prod"}` |
  | `metrics` | `cloudflare` | `script` |
  | `metrics` | `aws` | `namespace` + `dimensions` (1 to 10) |
  | `traces` | `tempo` | `service` (`resource.service.name`) |
  | `traces` | `cloudflare` | `script` |
  | `data` | `contember` | `project` + `stage` (default `live`), optional `entities` allow list and `deny_fields` (`Entity.field` or `*.field`) |

- **Dialect**: each binding has the query dialect of its native query endpoint: `logql`,
  `promql`, `traceql`, `cloudflare-query`, `cloudflare-metric`, `logs-insights`,
  `cloudwatch-metric`, `contember-graphql`. `describe` returns it per capability with the source type.
- **Signal**: a named metrics query stored without scope, in the native dialect of the
  service's metrics backend. For Prometheus it is a PromQL string, e.g. `error_rate`; Sonda
  injects the environment selector the same way as for native queries. For Cloudflare and
  CloudWatch it is a mapping (`{metric: errors, by: [status]}`,
  `{metric: CPUUtilization, stat: Average}`). All metrics environments of a service with
  signals must use the same source type.
- **Identity**: an agent service account. Authenticated by a bearer token. The identity store
  keeps only the SHA-256 of the token. Managed in the admin UI (section 11), not in the config.
- **Grant**: one `(service, environment, capability)`. Capabilities: `errors`, `logs`,
  `metrics`, `traces`, `data`. `data` is never implied by another grant. A native query requires the same capability as the structured tool for
  that signal type. A `traces` grant also makes the service's spans visible in full inside
  traces fetched through other services (section 8). A grant for a service or capability that
  is no longer configured has no effect.
- **Limits**: server defaults from the config plus per-identity overrides from the store. The
  data limits (`data_max_rows`, `data_max_depth`, `data_max_fields`, `data_max_query_bytes`)
  have no overrides yet: an override is a column in the identity store, and the store has no
  migrations.

### Example configuration

```yaml
admin:
  token: "${SONDA_ADMIN_TOKEN}"

sources:
  sentry:
    type: sentry
    url: https://sentry.io
    org: acme
    auth: { type: bearer, token: "${SENTRY_TOKEN}" }
  loki-prod:
    type: loki
    url: http://loki-gateway.monitoring.svc:3100
    auth: { type: none }
    headers: { X-Scope-OrgID: prod }
    grafana_datasource_uid: loki-prod
  prom-prod:
    type: prometheus
    url: https://prometheus-prod-01-eu-west-0.grafana.net/api/prom
    auth: { type: basic, username: "123456", password: "${GRAFANA_CLOUD_METRICS_TOKEN}" }
    grafana_datasource_uid: prom-prod
  tempo-prod:
    type: tempo
    url: http://tempo.monitoring.svc:3200
    headers: { X-Scope-OrgID: prod }
    grafana_datasource_uid: tempo-prod
  cloudflare:
    type: cloudflare
    account_id: "${CF_ACCOUNT_ID}"
    auth: { type: bearer, token: "${CF_API_TOKEN}" }
  aws-prod:
    type: aws
    region: eu-west-1
    role_arn: "${SONDA_AWS_ROLE_ARN}"
    max_scan_bytes: 10GB

grafana:
  url: https://grafana.example.com

services:
  engine-api:
    description: GraphQL API of the content engine
    repository: github.com/acme/engine
    environments:
      production:
        errors:  { source: sentry, project: engine, environment: production }
        logs:    { source: loki-prod, selector: '{app="engine", namespace="prod"}' }
        metrics: { source: prom-prod, selector: '{job="engine", namespace="prod"}' }
        traces:  { source: tempo-prod, service: engine-api }
    signals:
      error_rate: sum(rate(http_requests_total{code=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))
      p95_latency: histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))
  web-worker:
    environments:
      production:
        logs:    { source: cloudflare, script: web-worker }
        metrics: { source: cloudflare, script: web-worker }
        traces:  { source: cloudflare, script: web-worker }
    signals:
      errors: { metric: errors, by: [status] }
  engine-db:
    environments:
      production:
        logs:    { source: aws-prod, log_groups: [/aws/rds/cluster/engine/postgresql] }
        metrics: { source: aws-prod, namespace: AWS/RDS, dimensions: { DBClusterIdentifier: engine } }
    signals:
      cpu: { metric: CPUUtilization, stat: Average }

limits:
  max_range: 7d
  max_log_lines: 500
  max_response_bytes: 65536
  query_timeout: 30s
  concurrent_queries: 4
  requests_per_minute: 60
```

Config validation at startup fails on: unknown fields, unknown source references, unset
environment variables, a source type not allowed for the capability, binding fields of another
source type, unparsable selectors or signals, selectors without an `=` or `=~` matcher that
rejects the empty value (e.g. `{job!=""}` selects nearly everything), log group lists that are
empty, longer than 50, duplicated, or contain `*` or ARNs, CloudWatch bindings with no or more
than 10 dimensions,
signals whose form does not match the metrics backend, data bindings without a valid project
slug or with `deny_fields` not in `Entity.field` or `*.field` form, a Contember source without
a bearer key, and an admin token shorter than 32 characters. The full example is `sonda.example.yaml`.

## 3. Components

```text
cmd/sonda-server   main: load config, open the database, start HTTP server and admin UI
cmd/sonda          CLI: thin HTTP client over the api package

api/               request/response types shared by server and CLI (public package)
internal/client    HTTP client used by the CLI
internal/config    YAML loading, env expansion, validation → typed Config
internal/identities  identity and grant types, Store interface, token generation
internal/authz     token → Identity; (Identity, service, env, capability) → Scope or error; trace visibility
internal/policy    query scoping per dialect; backend-neutral filters; time range and step
internal/logql     LogQL lexer that finds and rewrites stream selectors
internal/traceql   TraceQL lexer that finds and rewrites spanset filters
internal/insights  Logs Insights lexer that splits a query into stages
internal/gqlguard  GraphQL checker for the Contember Content API: normalizes and validates a query against the role's schema
internal/telemetry backend-neutral records: log streams, spans, trace summaries, structured metric queries
internal/connector
  upstream/        HTTP client per source: auth, headers, error mapping
  sentry/          Sentry REST client
  loki/            Loki HTTP API client
  prometheus/      Prometheus HTTP API client (prometheus/client_golang)
  cloudflare/      Workers Observability and GraphQL Analytics client
  aws/             CloudWatch Logs and CloudWatch client (aws-sdk-go-v2)
  tempo/           Tempo HTTP API client
  contember/       Contember Content API client (introspection and checked queries)
internal/query     use cases: overview, errors, logs, metrics, traces, data, results; one backend per source type
internal/shape     grouping (Drain), redaction, truncation, series summaries, trace trees, source links
internal/audit     per-request record of service, environment and upstream queries
internal/store     SQLite or Postgres: identities (implements identities.Store), audit log, result handles
internal/httpapi   routing, authentication, rate and concurrency limits, audit, JSON encoding
internal/admin     admin UI: sign-in, identity management, audit log viewer
```

Boundaries:

- `httpapi` parses requests into `api` types and calls `query`. Nothing reaches a connector
  without a scope from `authz`.
- `authz` is the only way to get a scope: `ErrorScope`, `LogScope`, `MetricScope`,
  `TraceScope` and `DataScope`, which resolve to one typed variant per source type
  (`SelectorScope`, `CloudflareScope`, `LogGroupScope`, `CloudWatchMetricScope`,
  `TempoScope`, `ContemberScope`). Connector methods
  take a scope or a `policy` value, never a service name from the request. A usable scope
  cannot be built outside `authz` (fields are unexported; accessors return copies).
- `policy` is the only code that turns agent text into upstream query text.
- Connectors know nothing about identities or services. They execute scoped queries and return
  typed results, using `telemetry` types where several backends share a shape.
- `shape` turns connector results into compact responses. It has no I/O.
- `admin` writes identities only through `identities.Store` and accepts only grants for
  capabilities configured in the YAML file.

## 4. Connector contracts

Connectors are concrete clients, one per source type. The use cases in `query` reach them
through small backend interfaces, one per capability:

```go
type logBackend interface {
	dialect() api.Dialect
	search(ctx, r api.TimeRange, f policy.LogFilter, limit int) (logSearch, error)
	query(ctx, r api.TimeRange, text string, limit int, step string) (logQuery, error)
	fields(ctx, r api.TimeRange) (api.LogFields, error)
}
type metricBackend interface {
	dialect() api.Dialect
	names(ctx, r api.TimeRange) ([]api.MetricInfo, error)
	query(ctx, r api.TimeRange, text string, step time.Duration) (metricQuery, error)
}
type traceBackend interface {
	dialect() api.Dialect
	search(ctx, r api.TimeRange, f policy.TraceFilter, limit int) (traceSearch, error)
	query(ctx, r api.TimeRange, text string, limit int) (traceSearch, error)
	trace(ctx, r api.TimeRange, id string) (traceFetch, error)
}
type dataBackend interface {
	dialect() api.Dialect
	schema(ctx) (*gqlguard.Schema, gqlguard.Rules, error)
	query(ctx, text string, variables json.RawMessage) (dataQuery, error)
}
```

An implementation lives in `query/<capability>_<backend>.go`. It binds the typed scope and the
client, calls `policy` to scope agent text, records each upstream query for the audit log, and
returns the source link. The shared parts stay in the use cases: range, limits, `where`
parsing, redaction, Drain grouping, result handles, truncation and `meta`.

```go
// sentry.Client
ListIssues(ctx, scope authz.ErrorScope, r api.TimeRange, query, sort string, limit int) ([]Issue, error)
GetIssue(ctx, scope authz.ErrorScope, id string) (Issue, error)
LatestEvent(ctx, scope authz.ErrorScope, id string) (Event, error)
Releases(ctx, scope authz.ErrorScope, limit int) ([]Release, error)

// loki.Client
Lines(ctx, q policy.LogQL, r api.TimeRange, limit int) ([]telemetry.LogStream, error)
Matrix(ctx, q policy.LogQL, r api.TimeRange, step time.Duration) (model.Matrix, error)
Instant(ctx, q policy.LogQL, at time.Time) (model.Vector, error)
Series(ctx, scope authz.SelectorScope, r api.TimeRange) ([]map[string]string, error)
DetectedFields(ctx, scope authz.SelectorScope, r api.TimeRange) ([]Field, error)

// prometheus.Client
QueryRange(ctx, q policy.PromQL, r api.TimeRange, step time.Duration) (model.Matrix, error)
MetricNames(ctx, scope authz.SelectorScope, r api.TimeRange) ([]string, error)
Metadata(ctx) (map[string][]v1.Metadata, error)
```

| Client | Upstream calls | Input |
|---|---|---|
| `cloudflare` | `POST /accounts/{account}/workers/observability/telemetry/query` (events, calculations, invocations, traces), `…/telemetry/keys`, `POST /graphql` | `policy` Cloudflare query, `CloudflareScope`, `telemetry.CloudflareMetricQuery` |
| `aws` | Logs: `StartQuery`, `GetQueryResults`, `StopQuery`, `ListLogGroupsForQuery`, `GetLogGroupFields`. Metrics: `GetMetricData`, `ListMetrics`. STS: `GetCallerIdentity` | `policy` Insights query and CloudWatch metric, `LogGroupScope`, `CloudWatchMetricScope` |
| `tempo` | `GET /api/search`, `GET /api/v2/traces/{id}` | `policy` TraceQL, trace ID |
| `contember` | `POST /content/{project}/{stage}`: introspection, and queries without variables | `ContemberScope`, `policy.ContemberGraphQL` |

- `policy` values (`policy.LogQL`, `policy.PromQL`, `policy.TraceQL`, the Cloudflare query,
  the Insights query, the CloudWatch metric, `policy.ContemberGraphQL`) can only be
  constructed by `policy`. A connector
  cannot receive raw agent text.
- Metadata calls are scoped. Loki and Prometheus pass the scope selector as `match[]` /
  `query`; without it, an agent would see names of other services. Loki labels come from the
  `series` endpoint, which is scoped by design; the `labels` endpoint is not used. Prometheus
  `metadata` is not scoped, so it is only used to look up names returned by the scoped
  `label/__name__/values` call. Cloudflare `keys` carries the script filter. CloudWatch
  `GetLogGroupFields` is called per scoped log group, `ListMetrics` with the scope's namespace
  and dimensions. Cloudflare metric names are a fixed catalog.
- Lookups by ID are fetched unscoped and checked before anything is returned: a Sentry issue
  must be of the scope's project, a trace must contain a span of the service (section 8).
- One shared HTTP client per source (`upstream`) applies auth and extra headers, for Cloudflare
  too. Connectors do not know how a source authenticates. The AWS connector uses the SDK with
  the default credential chain.
- A new backend adds a client, a `policy` scoping function and backend implementations in
  `query`. No generic plugin system.

### Loki, Prometheus and Tempo specifics

- Endpoints used: Prometheus `query_range`, `label/__name__/values`, `metadata`; Loki
  `query_range`, `query`, `series`, `detected_fields` (skipped on Loki versions without it);
  Tempo `api/search` (always with `start` and `end`; without them Tempo searches only recent
  data) and `api/v2/traces/{id}`.
- Read-only credentials: Grafana Cloud access policy tokens with `logs:read` / `metrics:read` /
  `traces:read`. Self-hosted backends without auth must be reachable only from Sonda's network.

### Sentry specifics

- Use project-scoped endpoints (`/api/0/projects/{org}/{project}/issues/`). The agent's free-text
  query cannot escape the project. An org-level endpoint with a `project:` filter could.
- Lookups by ID (`GetIssue`) fetch first, then check that the issue's project equals the scope's
  project. Otherwise return `not_found`, not `forbidden`. IDs must be numeric.
- The environment grant also holds for single issues: the latest event is fetched with the
  scope's environment, and an issue without events there is `not_found`.
- List results are filtered by project slug again, as defense in depth.
- Verified against sentry.io: a `project:` or `environment:` term in the agent's query combines
  with the endpoint's project and the `environment` parameter by AND; it cannot widen them.
- Required token scopes: `org:read`, `project:read`, `event:read`, `project:releases`.

## 5. Authorization

Request flow:

1. Authenticate: bearer token → SHA-256 → identity store lookup → Identity with effective
   limits. Changes in the admin UI apply to the next request. A constant-time compare is not
   needed: timing can reveal at most the hash, not the token.
2. Authorize: `(identity, service, environment, capability)` against the grants → `Scope`.
3. Limit: reject ranges over `max_range`, cap lines at `max_log_lines`, apply `query_timeout`,
   rate and concurrency limits.
4. For native queries and signals: scope the query text (section 6).
5. Execute through the connector with the scope.
6. Post-check: results fetched by ID (Sentry issues, traces), Cloudflare events and the log
   groups a Logs Insights query scanned.
7. Write the audit record: identity, endpoint, service, environment, final upstream query,
   duration, result size, outcome.

Rules:

- Deny by default. An unknown service and a forbidden service return the same error.
- Discovery (`services`, `describe`) lists only services the identity has a grant for.
- Result handles belong to the identity that created them. Another identity gets `not_found`.
- Rate limit (token bucket, burst of ten seconds' worth) and concurrency limit are per identity,
  in memory. Requests over either limit fail with `rate_limited` instead of queueing. A limiter
  is recreated with a full budget when the identity's limits change.

## 6. Native query enforcement

Every native query is scoped by `policy`, in the way that the dialect allows:

| Dialect | Scoping | Verification |
|---|---|---|
| PromQL | Scope matchers injected into every selector of the AST | Re-parse, every selector carries the matchers |
| LogQL | Scope matchers injected into every stream selector by `internal/logql` | Re-lex, every selector carries the matchers; Loki oracle tests |
| TraceQL | Scope condition added to every spanset filter by `internal/traceql` | Re-lex, every filter ends with the condition; Tempo oracle tests |
| Cloudflare query | Agent filters wrapped in a group, AND-combined with the script filter | Post-check of every event, aggregate and trace |
| Logs Insights | Allowlist of commands, `SOURCE` and other cross-group words rejected; log groups set by the API parameter | Post-check with `ListLogGroupsForQuery` |
| Cloudflare metric | No agent query text: the server builds GraphQL from a catalog | Post-check of every row's script |
| CloudWatch metric | No agent query text: `MetricStat` with the scope's namespace and dimensions | — |
| Contember GraphQL | Project and stage in the URL, set by the server; the key's read-only role; `internal/gqlguard` rules | The normalized query is parsed and validated again, and the rules run on that text |

Anything a scoping lexer or decoder does not understand is rejected with `invalid_query`, so
scoping fails closed.

One native query is scoped to exactly one service and environment. Services may use different
label sets, so a union cannot be expressed as one injected scope.

The binding is a security setting. If a service's logs or metrics lack the selector label, or a
log group or script is shared with another service, the scope cannot protect them. Config review
must check this.

### PromQL and LogQL

Sonda finds every selector of the query, appends the scope matchers to it (skipping matchers
the selector already has), and serializes the query back. It then re-parses the result and
checks that every selector carries all scope matchers, so a serialization bug cannot silently
drop the scope. Matchers combine with AND, so:

- `app=~".*"` from the agent is narrowed by the injected `app="engine"`.
- `app="other"` from the agent yields an empty result. No data leaks.
- Queries with several selectors (`or`, binary operations, subqueries) are covered, because every
  selector node gets the matchers.

- **PromQL** is parsed with the Prometheus parser (Apache-2.0). Selectors are rewritten in the
  AST, which is serialized back. The parser API changes between Prometheus versions
  (`parser.ParseExpr` → `parser.NewParser(opts).ParseExpr`), so the version is pinned.
- **LogQL** is not parsed with Loki's parser: it is AGPL-licensed and pulls hundreds of
  packages. `internal/logql` only lexes the query. Outside strings, comments and ranges, a brace
  always opens a stream selector, so the lexer finds every selector without parsing the rest of
  the language. It mirrors the lexical rules of Loki's lexer: `"…"` strings with Go escapes,
  raw strings, `#`, `//` and `/* */` comments, and `[…]` read verbatim up to `]`. It rejects
  what it does not understand (single-quoted literals, unbalanced parentheses, invalid UTF-8),
  so it fails closed. Each selector is replaced by its serialized matchers and each comment by
  a space; the rest of the query is kept byte for byte. Loki validates the rest when it runs
  the query and reports errors as `invalid_query`.
- The lexer's security property: every selector Loki executes carries the scope matchers.
  `internal/logql` tests check it against a running Loki, so no Loki code is linked:
  `/loki/api/v1/format_query` prints a query from Loki's AST without comments, which shows the
  selectors as Loki parses them. A corpus of queries and a fuzz target
  (`go test ./internal/logql -fuzz FuzzScope`) use it. A second test stores lines of another
  service and checks that scoped queries do not return them, which does not depend on the
  formatter. The tests run when `SONDA_TEST_LOKI_URL` is set; CI runs them against a Loki
  service container.

### TraceQL

- TraceQL is not parsed with Tempo's parser, for the same reason as LogQL: Tempo is
  AGPL-licensed. `internal/traceql` only lexes the query, in the style of `internal/logql`.
  Outside strings, a `{` always opens a spanset filter.
- A pipeline must start with a filter. The query start, and every `(` that is not a call
  (`by(…)`, `select(…)`, `count()`, …), must lead to a `{`, because a pipeline without a filter
  reads spans of all services.
- `rootName` and `parent` are rejected anywhere outside strings: they read the root span or the
  parent span, which may belong to another service.
- Lexical rules: `"…"` strings with Go escapes, and backquoted raw strings only after
  whitespace or an operator. Rejected: comments (`//`, `/* */`, `#`), single-quoted literals,
  unbalanced braces, parentheses or quotes, a `{` inside a filter, invalid UTF-8 and NUL.
- Rewrite: each filter `{X}` becomes `{ (X) && resource.service.name = "<service>" }`, and an
  empty `{}` becomes `{ resource.service.name = "<service>" }`. Everything outside the filters
  is kept byte for byte. The result is re-lexed, and every filter must end with the scope
  condition at top level.
- Structural operators (`>>`, `<`, `~`, …) relate filters, and each filter is scoped. A TraceQL
  query therefore sees only spans of the service; other services' spans are reached through
  `trace <id>` (section 8).
- Tempo validates the rest when it runs the query; its 400 errors become `invalid_query`.
  TraceQL metrics (`| rate()`, …) are not supported by the search endpoint and fail the same way.
- The lexer's security property: every spanset filter Tempo evaluates carries the scope
  condition. Tempo has no formatter endpoint, so the oracle in `internal/traceql` checks
  results: it runs against Tempo with traces of two services from `dev/seed-traces.sh`, some
  crossing both. A corpus of tricky queries (structural operators, pipelines, `select`/`by`,
  strings with braces, raw strings, empty filters, nested parentheses) must match only spans of
  the scoped service, and traces of the other service alone must never appear. The tests run
  when `SONDA_TEST_TEMPO_URL` is set; CI runs them against Tempo 2.10.8. A fuzz target
  (`go test ./internal/traceql -fuzz FuzzScope`) checks that every output re-lexes and carries
  the condition.

### Cloudflare Workers Observability

- The agent writes a JSON subset of the query body: `view`, `filters`, `filterCombination`,
  `needle`, `calculations`, `groupBys`, `havings`, `orderBy`, `limit` (at most 2000). It is
  decoded into typed structs with unknown fields disallowed, so `queryId`, `datasets`,
  `timeframe`, `parameters`, `offset` and any other key are `invalid_query`. Exactly one JSON
  value is accepted.
- `view` defaults to `events` for logs and `traces` for traces. Logs accept `events`,
  `calculations` and `invocations`; traces accept `traces`.
- Filter leaves take an operation from an allowlist and a `type` of `string`, `number` or
  `boolean`. Groups (`kind: group`) nest at most 3 levels, because Cloudflare allows 4 and the
  wrapper adds one.
- The server sends:

  ```json
  {"filterCombination": "and", "filters": [
    {"key": "$metadata.service", "operation": "eq", "type": "string", "value": "<script>"},
    {"kind": "group", "filterCombination": "<agent's, default and>", "filters": ["<agent's filters>"]}
  ]}
  ```

  The group is omitted when the agent gave no filters. `needle`, calculations, group-bys,
  havings and the order pass through. `parameters` is always sent, `queryId` is a random
  `sonda-…` ID, `datasets` is never sent, and the timeframe comes from the range. Every query
  is sent with `dry: true`, so it is not saved in the account's query history.
- Post-check (defense in depth). A violation drops the whole response with an `internal`
  error, which the audit record holds:
  - An event's `$metadata.service` must equal the script. An event without it is accepted
    only when `$workers.scriptName` equals the script. When `$workers` is present, its
    `scriptName` must equal the script in every case.
  - Calculations (also the count of `logs search`) get a hidden group-by on
    `$metadata.service`. Every aggregate must be of the script; the group is removed from the
    result. A zero aggregate without the group is how Cloudflare reports no matches, so it is
    accepted and dropped.
  - Every trace summary must list the script among its services.
- The keys call (`logs fields`) carries the same script filter.
- Calculations return series; events and invocations return lines.

### CloudWatch Logs Insights

- `queryLanguage` is always `CWLI`. OpenSearch PPL and SQL can name log groups in the query
  text, so they are not accepted. Queries are limited to 10,000 characters.
- `internal/insights` splits the query into stages and collects its bare words. AWS publishes
  no grammar, so the lexer accepts only input on which every plausible reading of the
  delimiters agrees. It understands `"…"` and `'…'` strings, backquoted field names, regex
  literals `/…/`, `#` comments and `|` stages, also nested in parentheses. It rejects:
  - `/` as division, and any `/` it cannot read as a regex;
  - escaped closing delimiters in strings, names and regexes;
  - `/` or `[` inside a regex character class, and POSIX classes;
  - non-ASCII characters outside literals, unbalanced quotes or parentheses, invalid UTF-8, NUL.
- Every stage command, nested stages included, must be in an allowlist: `anomaly`, `dedup`,
  `diff`, `display`, `fields`, `filter`, `filterindex`, `limit`, `parse`, `pattern`, `sort`,
  `stats`, `unnest`, `where`. The bare words `source`, `join`, `appendcols` (read other log
  groups), `lookup`, `cidrlookup` (read account-wide tables) and `unmask` (reveals masked
  data) are rejected anywhere; a field of that name is written in backticks.
- Known gap: the first stage of a subquery directly follows `(` and cannot be told from an
  expression, so an unknown future command there is not caught by the allowlist. The
  post-check below covers it.
- The server sets `logGroupIdentifiers` to the binding's log groups.
- Post-check: after the query completes, `ListLogGroupsForQuery` must return only the scope's
  log groups. An ARN must also name the source's region and the account of Sonda's
  credentials (from STS `GetCallerIdentity`). Otherwise no row is returned and the request
  fails with `internal`.
- Scan limit: Logs Insights is billed by scanned bytes. While polling, a query that has scanned
  more than the source's `max_scan_bytes` is stopped (`StopQuery`) and the request fails with
  `limit_exceeded`. The check runs on each poll, so a query can scan a little more than the
  limit. A query is also stopped when the request ends (timeout or disconnect).
- A query with a `stats` stage returns series (by its `bin()` column, or one point at the
  range end); other queries return lines.
- The IAM restriction of `logs:StartQuery` to the configured log groups adds an independent
  layer (section 12).

### Cloudflare and CloudWatch metrics

Neither accepts query text from the agent:

- Cloudflare: `{metric, by}`. `metric` is one of `requests`, `errors`, `subrequests`,
  `cpu_time_p50`, `cpu_time_p99` (CPU time, ms), `duration_p50`, `duration_p99` (request
  duration, ms); `by` is from `status`, `scriptVersion`. The server builds the GraphQL query
  over `workersInvocationsAdaptive` with `accountTag`, `scriptName` and the range as
  variables, and checks the `scriptName` of every returned row. The time bucket is the finest
  of minute, 15 minutes, hour or day that is at least the step; the response reports it as the
  step. More than 10,000 rows (buckets × dimension values) is `limit_exceeded`.
- CloudWatch: `{metric, stat, dimensions}`. `stat` is `SampleCount`, `Average`, `Sum`,
  `Minimum`, `Maximum` or a percentile (`p99`, `p99.9`). The namespace and the scope dimensions
  come from the binding. An agent dimension with a scope key and a different value is
  `invalid_query`; others are added, up to 30 in all. Sonda sends one `MetricStat`. Its period
  is the step rounded up to whole minutes and capped at the range; the response reports it as
  the step. `Expression` is never sent: metric math, `SEARCH` and Metrics Insights select
  metrics across namespaces and dimensions, and no dimension can be added to them to restrict
  the result.

### Contember GraphQL

The `data` capability reads a Contember project through the Content API. The scope has two
layers, each of which must hold on its own:

1. **The API key's role.** The operator creates a Contember role with read permissions only,
   using ACL predicates to hide rows, and an API key for it. Contember generates the GraphQL
   schema per role, so such a key has no `Mutation` type at all. The project and stage come
   from the binding and are part of the URL; a query cannot name another project.
2. **Sonda.** The key's schema is introspected and cached for 10 minutes per source, project
   and stage. This shows only what the key may do in the bound project stage, so the key
   should have no other membership. Every load fails if the schema can write: any `Mutation` field, or the
   `validateCreate…`/`validateUpdate…` queries that Contember adds only for roles that may
   write. The binding then serves nothing. `serve` checks every binding in parallel, each
   with its own 15-second timeout, and refuses to start with such a key; an unreachable
   engine only logs a warning, and its first request repeats the check;
   `sonda-server check --online` reports it. Allow-listed entities and `deny_fields` that
   do not exist in the schema are treated the same way, at startup and on every request,
   because a typo in `deny_fields` would leave the field readable.

`internal/gqlguard` loads the introspection result into `gqlparser` (MIT) and checks each
query in three steps:

- **Parse and validate** the agent's document against the schema. Exactly one `query`
  operation; no directives anywhere (`@include`/`@skip` would make counting ambiguous). The
  fields written in the document are counted against `data_max_fields` before validation,
  because its overlapping-fields step is quadratic.
- **Normalize.** Fragments are inlined (Contember has no interfaces or unions, so a fragment
  applies only to its own type), aliases kept, the operation name dropped. Variables are
  inlined as literals, typed by their definitions; a missing nullable variable removes its
  argument, as GraphQL does. The field budget is checked while printing, so nested fragment
  spreads cannot blow up. The upstream request carries no variables.
- **Re-validate and check rules** on the normalized text, which is exactly what runs and what
  the audit log records:
  - Root fields only `get<E>`, `list<E>` and `paginate<E>` of entities. `transaction`,
    `schema`, `_info` and introspection (`__schema`, `__type`) are rejected; agents read the
    schema from `data/schema`. `_meta` is rejected on every entity.
  - The allow list applies at every level: root fields, relations, `paginate<Rel>`, the
    has-many-to-has-one reducers (`<rel>By…`), and relations inside inputs.
  - A denied field is rejected in a selection and as a key of `filter`, `by` and `orderBy`,
    through relations and `and`/`or`/`not`. Otherwise filtering, unique lookups, ordering or
    `totalCount` could test the values of a hidden field. A denied relation also blocks its
    derived fields and its other side (`Article.author` denies `Author.articles`), read from
    the relation model of the Content API's `schema` root field, which Sonda loads with the
    schema. Without that model no query runs.
  - Every `list<E>` and has-many relation needs `limit`, every paginate field `first`, as an
    integer after variables are inlined. Rows are budgeted: each list adds the product of the
    limits on its path, and the sum must stay within `data_max_rows` (default 500). Single
    rows (`get`, has-one, `<rel>By`) are not counted; the response reports the budget used as
    `data.rows`. Aliases
    count like any other field. `offset`/`skip` are at most 10,000.
  - Depth counts nested entity fields (default 5), fields count after inlining (default
    200). The query plus variables, and the normalized query again, are limited to
    `data_max_query_bytes` (16 KB): inlined variables and fragments can make it much larger.
  - Arguments outside `filter`, `by`, `orderBy`, `limit`, `first`, `offset` and `skip` are
    rejected, so a future Contember argument fails closed.

A fuzz target (`go test ./internal/gqlguard -fuzz FuzzCheck`) checks that every accepted
query is accepted again after normalization and normalizes to the same text. Integration
tests run against a Contember engine with a read-only and a write role when
`SONDA_TEST_CONTEMBER_URL` is set (`dev/seed-contember.sh`).

Responses: `data` holds the GraphQL data object with every string redacted, keys in query
order; response `extensions` are dropped, because a Contember engine in debug mode puts SQL
with bound values there. GraphQL errors of the agent's query become `invalid_query`; errors of
Sonda's own schema queries, and Contember 401/403/404 and 5xx, become `upstream_error`. There are no result handles: a response above `max_response_bytes`
fails with `limit_exceeded`, and the agent lowers its limits. Sonda reads at most twice
`max_response_bytes` of the upstream response before failing, so a wide query does not make
it read and redact megabytes it would refuse anyway. `meta.untrusted` marks
`data.data`. The normalized query is returned once, in `data.query`; the source entry
carries only the kind.

Not covered: cost inside one row budget (a `contains` filter on a large unindexed table, a
`totalCount` over millions of rows). Sonda's `query_timeout` cancels its own request, not
the database query, so set a statement timeout on the engine's database role.

### Backend-neutral search

`logs search` and `traces search` take structured filters that each backend translates. Values
are always quoted or sent as JSON values, never pasted into query text.

| Filter | Loki | Cloudflare | CloudWatch | Tempo |
|---|---|---|---|---|
| `contains` | `\|= "…"` | `needle`; further values as `$metadata.message includes` leaves | `filter @message like "…"` | — |
| `where k=v` / `k!=v` | `\| k="v"` (label names only) | `eq` / `neq` string leaves | `filter k = "v"` / `!=` | `k = "v"` / `!=`; `k` is an attribute (`.k`, `span.k`, `resource.k`), `name`, `statusMessage` or `rootServiceName` |
| `pipeline` | LogQL pipeline | `invalid_request` | `invalid_request` | — |
| `minDuration`, `maxDuration` | — | `$metadata.duration` `gte` / `lte` | — | `duration >=` / `<=` |
| `errors` | — | `$metadata.error exists` | — | `status = error` |
| `name` | — | `$metadata.spanName includes` | — | `name =~ ".*<quoted>.*"` |

Logs Insights strings cannot hold escaped quotes, so a CloudWatch value is quoted with the quote
kind it does not contain; a value with both kinds is `invalid_request`. A Logs Insights search
returns at most 10,000 lines.

The total of `logs search` is a Loki instant count query or `recordsMatched` of the same Logs
Insights query, both exact. Cloudflare's is a `calculations` count with the same filters, which
Cloudflare weights by each event's sampling rate, so it is an estimate.

## 7. Agent-efficient responses

Every response uses one envelope:

```json
{
  "data": { },
  "meta": {
    "service": "engine-api",
    "environment": "production",
    "range": { "from": "2026-10-16T10:00:00Z", "to": "2026-10-16T11:00:00Z" },
    "sources": [{ "kind": "loki", "url": "https://grafana.example.com/explore?…" }],
    "truncated": true,
    "sampled": true,
    "resultId": "res_8KcW…",
    "untrusted": ["data.groups[].pattern", "data.groups[].example"]
  }
}
```

- `sources` are deep links for a human to verify the finding: Sentry; Grafana Explore for Loki,
  Prometheus and Tempo when `grafana` is configured; the Workers Observability dashboard for
  Cloudflare; the Logs Insights console for CloudWatch Logs. Without a link, the source entry
  carries the upstream query and range instead of a URL.
- `untrusted` lists the fields that contain raw telemetry. Agents treat them as data, never as
  instructions.
- Log lines are cut to 1000 characters. Line lists stop at 3/4 of `max_response_bytes`; the
  rest stays behind a result handle and the response is marked `truncated`. Series are capped at
  30 and about 60 points each. A response still above `max_response_bytes` fails with
  `limit_exceeded`.

### Log search

1. Total of the matching lines in the range: exact for Loki and CloudWatch, an estimate for
   Cloudflare (section 6, backend-neutral search).
2. Sample: fetch up to `max_log_lines` of the newest matching lines. `sampleRange` reports the
   time span they cover.
3. Redact the lines, then group them into patterns with Drain (`internal/shape/drain.go`). A
   JSON line is grouped by its message field (`log`, `message`, `msg`, …). Tokens are split at
   whitespace and after the `=` of `key=value`, so a varying value becomes `<_>` and its key
   stays. Lines with fewer than 4 or more than 80 tokens are counted as `ungrouped`.
4. Return the total, the groups with sample-based counts and estimates (`sampled: true`), and a
   `resultId`.
5. The agent drills down with `resultId` + group index, or pages through raw lines.

Not used: Loki's patterns API (`/loki/api/v1/patterns`). It accepts only a stream selector, so
it ignores line filters, and it needs the pattern ingester enabled.

### Result handles

- Stored in the database: `id`, `identity`, `kind`, `created_at`, `expires_at`, payload (redacted lines
  and their group indexes). Expired rows are deleted on the next save.
- TTL: 30 minutes by default.
- They replace a general query cache in v1. An investigation reuses its own results; nothing is
  shared across identities.

### Metadata cache

Prometheus metric metadata (type and help of all metrics) is cached in memory per source for
10 minutes. It holds no per-service data: names come from the scoped call on every request.
Contember schemas are cached in memory per source, project and stage for 10 minutes; each
refresh repeats the write check.

## 8. Traces

The `traces` capability is served by Tempo and Cloudflare. Connectors return the neutral
`telemetry.Span` (trace, span and parent ID, service, name, kind, start, duration, status,
status message, attributes, events) and `telemetry.TraceSummary`. The span's service is the
OTel `service.name` for Tempo and the script name for Cloudflare.

| Endpoint | Purpose |
|---|---|
| `POST /v1/services/{s}/traces/search` | `minDuration`, `maxDuration`, `errors`, `name` (contains), `where[]`, `limit` → trace summaries with the matched spans of the service |
| `POST /v1/services/{s}/traces/query` | Native query: TraceQL, or Cloudflare query JSON with `view: traces` → trace summaries |
| `GET /v1/services/{s}/traces/{id}` | One trace as a span tree |

- Search and query return at most `limit` traces (default 20, maximum 50) and mark the
  response `truncated` when more matched. Matched spans are of the scoped service; Tempo
  reports no service per matched span, and every filter is scoped. Cloudflare returns no
  matched spans, and names the root service only when the trace involves one service.
- **Visibility.** `authz.TraceVisibility` decides which backend service names an identity sees
  in full: the names of trace bindings on the same source, in every service and environment the
  identity has a `traces` grant for. A span of any other service becomes a stub: span and
  parent ID, depth, service, start, duration and status. Name, kind, status message, attributes
  and events are dropped. Service names stay visible by design; they show where time went.
- In search results, `rootName` is cleared when the root service is not visible, and a matched
  span of a hidden service becomes a stub.
- **Trace by ID is fetched unscoped and checked, like a Sentry issue by ID.** Tempo returns a
  trace by ID (`/api/v2/traces/{id}`) without a service filter, and Cloudflare finds its spans
  with `$metadata.traceId eq <id>` and `$metadata.spanName exists` alone. Sonda checks the
  fetched spans before returning anything: the trace must contain a span of the scoped
  service, otherwise the response is `not_found` with the same message as a missing trace.
  Unlike an issue, a trace returns spans of other services on purpose, as stubs: visibility
  and stubs are applied in `shape` before the response is built. The Cloudflare event
  post-check is skipped for this query only, because other scripts' events are expected.
  A Cloudflare trace of 2000 or more events is `limit_exceeded`, because one fetch cannot
  return it whole.
- Trace IDs are 16 or 32 hex characters, normalized to lower case.
- The tree is ordered depth-first from the roots; spans whose parent is missing become roots;
  children are ordered by start time. A trace response holds at most 300 spans and is marked
  `truncated` beyond that.
- Span names, root names, status messages, event names, and attribute and event attribute
  values of visible spans are redacted. Attribute values are cut to 500 characters.
- `meta.untrusted` lists service names, span names, status messages, attributes and events.

## 9. HTTP API

All endpoints are `GET` unless stated. Time parameters: `from`, `to` (RFC 3339) or `since`
(duration, e.g. `1h`); data endpoints take none. Environment: `env`.

| Endpoint | Capability | Purpose |
|---|---|---|
| `/v1/services` | any grant | Services the identity can access |
| `/v1/services/{s}` | any grant | Environments, capabilities with backend and dialect, signals, repository |
| `/v1/services/{s}/overview` | any granted | Last releases, top issues, signal values. The usual first call. |
| `/v1/services/{s}/errors` | `errors` | Issues: title, count, users, first/last seen, link |
| `/v1/services/{s}/errors/{id}` | `errors` | Issue + latest event in `env` with stack trace (in-app frames, newest first) and trace ID |
| `/v1/services/{s}/releases` | `errors` | Releases and deploys in range |
| `POST /v1/services/{s}/logs/search` | `logs` | `contains`, `where`, Loki `pipeline` → total + groups |
| `POST /v1/services/{s}/logs/query` | `logs` | Native query in the backend's dialect (scoped) → lines or series |
| `/v1/services/{s}/logs/fields` | `logs` | Labels and fields of the lines |
| `/v1/services/{s}/metrics` | `metrics` | Metric names with type and help |
| `/v1/services/{s}/signals/{name}` | `metrics` | Signal series + summary (count, min, max, avg, first, last) |
| `POST /v1/services/{s}/metrics/query` | `metrics` | Native query in the backend's dialect (scoped) → series + summary |
| `POST /v1/services/{s}/traces/search` | `traces` | Duration, error, name and attribute filters → trace summaries |
| `POST /v1/services/{s}/traces/query` | `traces` | Native query in the backend's dialect (scoped) → trace summaries |
| `/v1/services/{s}/traces/{id}` | `traces` | Span tree; spans of services without a grant are stubs |
| `/v1/services/{s}/data/schema` | `data` | Entities, fields with types, relations with target and cardinality, unique fields and enums, without denied fields and entities. `entity` (repeatable) selects entities; a schema above 3/4 of `max_response_bytes` comes back as entity names only, marked `truncated` |
| `POST /v1/services/{s}/data/query` | `data` | `{env, query, variables}` → normalized query, row bound and redacted data |
| `/v1/results/{id}` | owner | Page through or drill into a stored result |

`metrics/query` takes the query as a string in every dialect; for Cloudflare and CloudWatch it
holds JSON.

Errors use one shape: `{ "error": { "code": "not_found", "message": "…" } }`. Codes:
`unauthenticated`, `not_found`, `invalid_request`, `invalid_query`, `limit_exceeded`,
`rate_limited`, `upstream_error`, `timeout`, `internal`. The environment may be omitted when the
identity has exactly one environment with the needed capability.

## 10. CLI

```text
sonda services
sonda describe engine-api
sonda overview engine-api -e production --since 1h
sonda errors engine-api -e production --since 24h
sonda error engine-api 4512345
sonda logs search engine-api -e production --since 1h --contains timeout --where level=error
sonda logs query engine-api -e production '{level="error"} |= "pool"'
sonda logs fields engine-api -e production
sonda metrics list engine-api -e production
sonda signal engine-api error_rate -e production --since 6h
sonda metrics query engine-api -e production 'sum(rate(http_requests_total[5m]))'
sonda metrics query engine-db '{"metric":"CPUUtilization","stat":"Average"}'
sonda traces search engine-api --since 1h --min-duration 500ms --errors
sonda traces query engine-api '{ status = error && duration > 500ms }'
sonda trace engine-api 4bf92f3577b34da6a3ce929d0e0e4736 --since 6h
sonda result res_8KcW --group 2
sonda data schema shop-api -e production
sonda data query shop-api '{ listOrder(limit: 5, filter: {status: {eq: failed}}) { id createdAt } }'
```

- Config: `SONDA_URL` and `SONDA_TOKEN`, or `~/.config/sonda/config.yaml`.
- Output: JSON when stdout is not a TTY, compact text on a TTY. `--format json|text` overrides.
  `describe` shows each capability with its source type and dialect, e.g.
  `logs(cloudflare: cloudflare-query)`. `trace` prints one line per span, indented by depth;
  stubs show as `[service]  (not granted)`.
- Exit codes: `0` success, `1` usage error, `2` not found / unauthenticated, `3` limit or rate limit,
  `4` upstream error.
- Ships with `skills/sonda/SKILL.md` that teaches agents the investigation flow: `overview` →
  `errors` → `trace` → `logs search` → drill-down, and the native dialects.

## 11. Admin UI

Served under `/admin` only when `admin.token` is set. Pages:

- **Identities**: list, create, edit grants and limit overrides, rotate the token, delete.
  Grants are a matrix of configured service environments × capabilities; unconfigured cells
  cannot be selected. A new or rotated token is shown once; only its SHA-256 is stored.
- **Audit log**: newest first, filterable by identity, 100 records per page.

Rules:

- Sign-in takes the admin token. The session cookie holds its expiry (12 h) signed with
  HMAC-SHA256 keyed by the admin token. No server-side session state; changing the token ends
  all sessions.
- Cookie: `HttpOnly`, `SameSite=Strict`, `Path=/admin`, `Secure` behind HTTPS.
  `http.CrossOriginProtection` rejects cross-origin form posts.
- Every state-changing admin request, including failed sign-ins, is written to the audit log
  under the identity `(admin)`. Identity names cannot contain parentheses.
- Sources and services are read-only here. They change only in the YAML file, with a restart.

## 12. Security

- Read-only: connectors implement only read calls. Provider tokens use read-only scopes or
  Viewer roles. The Contember connector sends POST requests, but only introspection and
  queries checked by `gqlguard`, with a key that Sonda verified cannot write.
- Provider credentials never appear in responses, errors or audit records.
- Limits: time range, lines, response bytes, timeout, concurrency, rate, scanned bytes for
  Logs Insights, and rows, depth, fields and query size for data.
- Audit log in the database records every request, including denied ones and admin actions.
- The admin UI can create tokens for any configured service. Protect the admin token like a
  provider credential and expose `/admin` only on a trusted network.
- Telemetry is untrusted: marked in `meta.untrusted`. Built-in rules redact bearer and basic
  tokens, URL credentials, AWS keys, JWTs, private keys and `password=`-style fields in log
  lines, Sentry titles, messages and tags, and span names, attributes, events and status
  messages; `redact` in the config adds patterns. Redaction reduces risk; it is not a
  guarantee. Stack frames and metric labels are not redacted.
- **Application data** is often personal. The role's ACL decides which rows and fields leave
  Contember; `deny_fields` narrows further. Query results and the audited query text (with
  inlined filter values) can contain personal data, and so can the audit log in the
  database. `check --online` warns about readable fields with names like `email` or `phone`.
  Redaction covers secrets, not personal data.
- Expensive expressions inside a query (e.g. `rate(x[90d])`) are not detected by Sonda. Upstream
  limits in Prometheus, Loki and Tempo remain necessary.
- Source headers such as `X-Scope-OrgID` are sent as configured. Sonda does not check their
  values: a `|` in a tenant header can make a cross-tenant query where Loki or Tempo allows
  that, but headers are admin configuration, not agent input.
- **Cloudflare token.** Cloudflare's documentation is unclear about the permission that
  `/workers/observability/telemetry/query` needs: the API reference names "Workers
  Observability Write", while the roles documentation says the read-only "Metadata
  Read-Only" access grants observability. This must be verified against a
  real account before production use; prefer the read-only permission if it works. GraphQL
  Analytics needs "Account Analytics Read".
- **AWS role.** Grant Sonda only these read-only actions: `logs:StartQuery`,
  `logs:GetQueryResults`, `logs:StopQuery`, `logs:ListLogGroupsForQuery`,
  `logs:GetLogGroupFields`, `cloudwatch:GetMetricData`, `cloudwatch:ListMetrics`, plus
  `kms:Decrypt` on the keys of encrypted log groups. `sts:GetCallerIdentity` needs no
  permission. With `role_arn`, the base credentials need `sts:AssumeRole` on that role.
  Restrict `logs:StartQuery` to the ARNs of the configured log groups. Then even a query that
  passed the command allowlist could not read other groups, independently of the
  `ListLogGroupsForQuery` post-check (section 6).

## 13. Out of scope for v1

- MCP adapter.
- Datadog, Elasticsearch.
- AWS X-Ray and Jaeger as trace backends. The `traceBackend` interface allows adding them.
- CloudWatch `Expression`, `SEARCH` and Metrics Insights, because they cannot be scoped
  (section 6).
- Cloudflare deployments as `releases`, and Workers Analytics Engine SQL.
- TraceQL metrics (`| rate()`, `quantile_over_time`, …).
- Correlation tools (`get_related_events`). The agent correlates using links, release versions,
  trace IDs and timestamps.
- General query-result cache shared across identities.
- Multi-workspace, SSO/OIDC for the admin UI, a token management API.
- Editing sources and services at runtime.
- Identity stores other than SQLite and Postgres (the `identities.Store` interface allows adding them).
- Data: mutations, the Contember System API (event history, a candidate for "who changed this
  record") and Tenant API, other databases (the `dataBackend` interface allows adding them),
  per-identity data limits, and result handles for data.

## 14. Open questions

1. If a deployment can reach only Grafana, does its datasource proxy pass all needed Loki
   endpoints (`query_range`, `query`, `series`, `detected_fields`)? This affects only that
   fallback, not the default direct connection.
2. The log sample is the newest lines. For long ranges, a sample spread over the range would
   describe older patterns better, at the cost of more upstream requests.
3. Which Cloudflare token permission does the Workers Observability query API need (section 12)?
4. How does Cloudflare combine `needle` with `filters`? Sonda assumes AND. The scope is not
   affected either way, because the script filter is in `filters` and the post-check verifies
   every event.
5. Does the Cloudflare keys endpoint take the range as `from`/`to` or as `timeframe`? Sonda
   sends `from`/`to`; a wrong guess affects only `logs fields`, not the scope.

Resolved: native queries use the same capability as the structured tools (section 1).
`overview` ranks issues by event count in the range and marks issues first seen in the range
with `new: true`.
