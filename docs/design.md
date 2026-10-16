# Sonda — Technical Design (v1)

Status: draft, before implementation.

Sonda is a self-hostable, read-only gateway that gives AI agents one credential and one
service-centric interface to production telemetry in Sentry and Grafana (Loki, Prometheus).
It stores no telemetry. It queries sources on demand, enforces per-service authorization, and
returns compact, evidence-carrying responses.

## 1. Decisions

| Topic | Decision | Rejected alternative | Reason |
|---|---|---|---|
| Interface | HTTP API + `sonda` CLI | MCP server | No context cost until used. One contract (HTTP) for agents, bots and CI. MCP can be a thin adapter later. |
| Language | Go | TypeScript/Bun | Mature PromQL and LogQL parsers exist only in Go. Single static binary. |
| Binaries | `sonda-server` and `sonda` (CLI), one Go module | One binary with subcommands | The CLI imports only the `api` package, so it does not link the parsers, connectors or SQLite. |
| Native queries | Allowed in v1, scoped to one service, with matcher injection | Plain passthrough; string concatenation | Passthrough leaks other services. String concatenation protects only one selector. |
| Configuration | One YAML file, loaded at startup | Configuration in a database | Reviewable in git, no admin UI needed. |
| Provider secrets | Environment variable references in YAML | Encrypted in the database | No key management in v1. |
| Internal storage | SQLite (`modernc.org/sqlite`, pure Go) | Postgres | No extra service to run. Holds only audit, result handles and metadata cache. |
| Grafana access | Native Loki/Prometheus HTTP API, through the Grafana datasource proxy or directly | Grafana `/api/ds/query` | Same request and response format for both paths, so one connector per backend. |
| Workspaces | One server = one workspace | Multi-workspace in v1 | No current need. Nothing in the model prevents adding it later. |

## 2. Domain model

```text
Source ──< Binding >── Environment ──< Service
                                         │
Identity ──< Grant (services × environments × capabilities)
```

- **Source**: a connection to a backend. Types: `sentry`, `loki`, `prometheus`. A Grafana instance
  contributes one `loki` and one `prometheus` source per datasource UID.
- **Service**: a logical application. Has a description, an optional repository, environments and
  signals.
- **Environment**: per service, maps each capability to a source and a scope:
  - `errors` → Sentry project slug + Sentry environment name.
  - `logs` → Loki source + label selector, e.g. `{app="engine", namespace="prod"}`.
  - `metrics` → Prometheus source + label selector, e.g. `{job="engine", namespace="prod"}`.
- **Signal**: a named PromQL expression defined by the admin per service, e.g. `error_rate`. It
  is written without service matchers. Sonda injects the environment selector the same way as for
  native queries.
- **Identity**: an agent service account. Authenticated by a bearer token. The config stores
  only the SHA-256 of the token.
- **Grant**: `services × environments × capabilities`. Capabilities: `errors`, `logs`, `metrics`.
  A native query requires the same capability as the structured tool for that signal type.
- **Limits**: defaults plus per-identity overrides.

### Example configuration

```yaml
sources:
  sentry:
    type: sentry
    url: https://sentry.io
    org: acme
    token: ${SENTRY_TOKEN}
  loki-prod:
    type: loki
    url: https://grafana.example.com/api/datasources/proxy/uid/loki-prod
    token: ${GRAFANA_TOKEN}
  prom-prod:
    type: prometheus
    url: https://grafana.example.com/api/datasources/proxy/uid/prom-prod
    token: ${GRAFANA_TOKEN}

services:
  engine-api:
    description: GraphQL API of the content engine
    repository: github.com/acme/engine
    environments:
      production:
        errors:  { source: sentry, project: engine, environment: production }
        logs:    { source: loki-prod, selector: '{app="engine", namespace="prod"}' }
        metrics: { source: prom-prod, selector: '{job="engine", namespace="prod"}' }
    signals:
      error_rate: sum(rate(http_requests_total{code=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))
      p95_latency: histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))

identities:
  coding-agent:
    token_sha256: 9f2c…
    grants:
      - services: [engine-api]
        environments: [production, staging]
        capabilities: [errors, logs, metrics]
    limits:
      requests_per_minute: 30

limits:
  max_range: 7d
  max_log_lines: 500
  max_response_bytes: 65536
  query_timeout: 30s
  concurrent_queries: 4
  requests_per_minute: 60
```

Config validation at startup fails on: unknown source references, unparsable selectors or
signals, empty selectors, and grants that reference unknown services or environments.

## 3. Components

```text
cmd/sonda-server   main: load config, open SQLite, start HTTP server
cmd/sonda          CLI: thin HTTP client over the api package

api/               request/response types shared by server and CLI (public package)
internal/config    YAML loading, env expansion, validation → typed Config
internal/authz     token → Identity; (Identity, service, env, capability) → Scope or error
internal/policy    PromQL/LogQL matcher injection; time-range and limit clamping
internal/connector
  sentry/          Sentry REST client
  loki/            Loki HTTP API client
  prometheus/      Prometheus HTTP API client
internal/query     use cases: overview, errors, logs search, metrics, results
internal/shape     grouping, sampling, truncation, source links
internal/store     SQLite: audit log, result handles, metadata cache
internal/httpapi   routing, auth middleware, rate limits, JSON encoding
```

Boundaries:

- `httpapi` parses requests into `api` types and calls `authz` first. Nothing reaches `query`
  without a `Scope`.
- `authz.Scope` is the only way to get a source, a Sentry project or a label selector. Connector
  methods take a `Scope`, never a service name from the request. A scope cannot be built outside
  `authz`.
- `policy` is the only code that turns user query text into upstream query text.
- Connectors know nothing about identities or services. They execute scoped queries and return
  typed results.
- `shape` turns connector results into compact responses. It has no I/O.

## 4. Connector contracts

```go
type ErrorSource interface {
    ListIssues(ctx context.Context, s ErrorScope, q IssueQuery) (IssuePage, error)
    GetIssue(ctx context.Context, s ErrorScope, issueID string) (Issue, error)
    LatestEvent(ctx context.Context, s ErrorScope, issueID string) (Event, error)
    ListReleases(ctx context.Context, s ErrorScope, r TimeRange) ([]Release, error)
}

type LogSource interface {
    QueryRange(ctx context.Context, s LogScope, q InjectedLogQL, r TimeRange, limit int) (LogResult, error)
    Count(ctx context.Context, s LogScope, q InjectedLogQL, r TimeRange) (int64, error)
    Labels(ctx context.Context, s LogScope, r TimeRange) ([]string, error)
    LabelValues(ctx context.Context, s LogScope, label string, r TimeRange) ([]string, error)
}

type MetricSource interface {
    QueryRange(ctx context.Context, s MetricScope, q InjectedPromQL, r TimeRange, step time.Duration) (Matrix, error)
    MetricNames(ctx context.Context, s MetricScope, r TimeRange) ([]MetricInfo, error)
    LabelValues(ctx context.Context, s MetricScope, label string, r TimeRange) ([]string, error)
}
```

- `InjectedLogQL` and `InjectedPromQL` are types that only `policy` can construct. A connector
  cannot receive raw user text.
- Metadata calls (`Labels`, `MetricNames`, `LabelValues`) pass the scope selector as `match[]` /
  `query`. Without it, an agent would see names of other services.
- New backends (Tempo, CloudWatch, Datadog) add a new interface or implement an existing one.
  No generic plugin system in v1.

### Sentry specifics

- Use project-scoped endpoints (`/api/0/projects/{org}/{project}/issues/`). The agent's free-text
  query cannot escape the project. An org-level endpoint with a `project:` filter could.
- Lookups by ID (`GetIssue`) fetch first, then check that the issue's project equals the scope's
  project. Otherwise return `not_found`, not `forbidden`.
- Required token scopes: `org:read`, `project:read`, `event:read`, `project:releases`.

## 5. Authorization

Request flow:

1. Authenticate: bearer token → SHA-256 → Identity. Constant-time compare.
2. Authorize: `(identity, service, environment, capability)` against the grants → `Scope`.
3. Clamp: time range to `max_range`, limit to `max_log_lines`, timeout to `query_timeout`.
4. For native queries and signals: inject the scope selector (section 6).
5. Execute through the connector with the scope.
6. Post-check results fetched by ID.
7. Write the audit record: identity, endpoint, service, environment, final upstream query,
   duration, result size, outcome.

Rules:

- Deny by default. An unknown service and a forbidden service return the same error.
- Discovery (`services`, `describe`) lists only services the identity has a grant for.
- Result handles belong to the identity that created them. Another identity gets `not_found`.
- Rate limit (token bucket) and concurrency limit are per identity, in memory.

## 6. Native query enforcement

Sonda parses the query, appends the scope matchers to every selector in the AST, and serializes
it back. Matchers combine with AND, so:

- `app=~".*"` from the agent is narrowed by the injected `app="engine"`.
- `app="other"` from the agent yields an empty result. No data leaks.
- Queries with several selectors (`or`, binary operations, subqueries) are covered, because every
  selector node gets the matchers.

One native query is scoped to exactly one service and environment. Services may use different
label sets, so a union cannot be expressed as one injected matcher.

The scope selector is a security setting. If a service's logs or metrics lack the label, the
filter cannot protect them. Config review must check this.

### Spike results (2026-10-16)

Verified in a throwaway module with `prometheus/prometheus v0.315.0` and `grafana/loki/v3 v3.7.8`:

| Input | Output after injecting `app="engine-api"` |
|---|---|
| `sum(rate(x{app="engine-api"}[5m])) or on() sum(rate(x{app="tenant-api"}[5m]))` | `… or on () sum(rate(x{app="engine-api",app="tenant-api"}[5m]))` → empty |
| `max_over_time(rate(foo[5m])[1h:1m])` | `max_over_time(rate(foo{app="engine-api"}[5m])[1h:1m])` |
| `sum(count_over_time({app="engine-api"}[5m])) / sum(count_over_time({app="tenant-api"} \|= "password"[5m]))` | second selector becomes `{app="tenant-api", app="engine-api"}` → empty |
| `{app=~".+"} \| json \| level="error"` | `{app=~".+", app="engine-api"} \| json \| level="error"` |

Costs:

| | PromQL parser | LogQL parser (Loki) |
|---|---|---|
| Linked packages | 262 | 888 |
| Spike binary size | — | 44 MB (both parsers) |
| Extra requirements | none | Go ≥ 1.26.5; copy Loki's `replace` directives for `hashicorp/memberlist` and `grafana/regexp` |

Loki pulls gRPC, OpenTelemetry, etcd and k8s client packages. This affects only `sonda-server`.
Mitigation: isolate the LogQL code in `internal/policy/logql`, pin the Loki version, and treat
each Loki upgrade as a deliberate change. If the cost becomes a problem, vendor the `syntax`
package alone.

The PromQL API changed between Prometheus versions (`parser.ParseExpr` →
`parser.NewParser(opts).ParseExpr`). Pin the version.

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
    "untrusted": ["data.groups[].pattern", "data.samples[].line"]
  }
}
```

- `sources` are deep links to Grafana Explore or Sentry, so a human can verify the finding.
- `untrusted` lists the fields that contain raw telemetry. Agents treat them as data, never as
  instructions.
- Responses above `max_response_bytes` are cut and marked `truncated`.

### Log search

1. Exact total: `sum(count_over_time(<selector + filter>[range]))`.
2. Sample: fetch up to `max_log_lines` lines.
3. Group the sample into patterns with Drain (`loki/pkg/pattern/drain`, already a dependency).
4. Return the total, the groups with sample-based counts (`sampled: true`), and a `resultId`.
5. The agent drills down with `resultId` + group index, or pages through raw lines.

Alternative: Loki's patterns API (`/loki/api/v1/patterns`). It gives counts over the full range
but needs the pattern ingester enabled. Use it when available, fall back to step 3.

### Result handles

- Stored in SQLite: `id`, `identity`, `scope`, `created_at`, `expires_at`, payload.
- TTL: 30 minutes by default.
- They replace a general query cache in v1. An investigation reuses its own results; nothing is
  shared across identities.

### Metadata cache

Metric names, label names and log fields per scope. TTL: 10 minutes. The cache key includes the
scope, so entries never cross services.

## 8. HTTP API

All endpoints are `GET` unless stated. Time parameters: `from`, `to` (RFC 3339) or `since`
(duration, e.g. `1h`). Environment: `env`.

| Endpoint | Capability | Purpose |
|---|---|---|
| `/v1/services` | any grant | Services the identity can access |
| `/v1/services/{s}` | any grant | Environments, capabilities, signals, repository |
| `/v1/services/{s}/overview` | any granted | Last releases, top issues, signal values. The usual first call. |
| `/v1/services/{s}/errors` | `errors` | Issues: title, count, users, first/last seen, link |
| `/v1/services/{s}/errors/{id}` | `errors` | Issue + latest event with stack trace (compacted) |
| `/v1/services/{s}/releases` | `errors` | Releases and deploys in range |
| `POST /v1/services/{s}/logs/search` | `logs` | Filter text and/or LogQL pipeline → total + groups |
| `POST /v1/services/{s}/logs/query` | `logs` | Native LogQL (injected) → lines or series |
| `/v1/services/{s}/logs/fields` | `logs` | Labels and detected fields |
| `/v1/services/{s}/metrics` | `metrics` | Metric names with type and help |
| `/v1/services/{s}/signals/{name}` | `metrics` | Signal series + summary (min/max/last/change) |
| `POST /v1/services/{s}/metrics/query` | `metrics` | Native PromQL (injected) → series + summary |
| `/v1/results/{id}` | owner | Page through or drill into a stored result |

Errors use one shape: `{ "error": { "code": "not_found", "message": "…" } }`. Codes:
`unauthenticated`, `not_found`, `invalid_query`, `limit_exceeded`, `rate_limited`,
`upstream_error`, `timeout`.

## 9. CLI

```text
sonda services
sonda describe engine-api
sonda overview engine-api -e production --since 1h
sonda errors engine-api -e production --since 24h
sonda error engine-api 4512345
sonda logs search engine-api -e production --since 1h --contains timeout
sonda logs query engine-api -e production '{level="error"} |= "pool"'
sonda logs fields engine-api -e production
sonda metrics list engine-api -e production
sonda signal engine-api error_rate -e production --since 6h
sonda metrics query engine-api -e production 'sum(rate(http_requests_total[5m]))'
sonda result res_8KcW --group 2
```

- Config: `SONDA_URL` and `SONDA_TOKEN`, or `~/.config/sonda/config.yaml`.
- Output: JSON when stdout is not a TTY, compact text on a TTY. `--format json|text` overrides.
- Exit codes: `0` success, `1` usage error, `2` not found / forbidden, `3` limit or rate limit,
  `4` upstream error.
- Ships with a `SKILL.md` that teaches agents the investigation flow: `overview` → `errors` →
  `logs search` → drill-down.

## 10. Security

- Read-only: connectors implement only read calls. Provider tokens use read-only scopes or
  Viewer roles.
- Provider credentials never appear in responses, errors or audit records.
- Limits: time range, lines, response bytes, timeout, concurrency, rate.
- Audit log in SQLite records every request, including denied ones.
- Telemetry is untrusted: marked in `meta.untrusted`. A configurable list of regexes redacts
  known secret patterns (bearer tokens, AWS keys, passwords in URLs). Redaction reduces risk; it
  is not a guarantee.
- Expensive expressions inside a query (e.g. `rate(x[90d])`) are not detected by Sonda. Upstream
  limits in Prometheus and Loki remain necessary.

## 11. Out of scope for v1

- MCP adapter.
- Traces (Tempo), CloudWatch, Datadog, Elasticsearch.
- Correlation tools (`get_related_events`). The agent correlates using links, release versions
  and timestamps.
- General query-result cache shared across identities.
- Admin UI, multi-workspace, OAuth, token management API.

## 12. Open questions

1. Does the Grafana datasource proxy pass all needed Loki endpoints (`query_range`, `labels`,
   `patterns`) in current Grafana and Grafana Cloud? If not, the Loki connector uses
   `/api/datasources/uid/{uid}/resources/…` or a direct Loki URL.
2. Should native queries require a separate capability (e.g. `logs:native`) for tighter control,
   or is the same capability enough? This design uses the same capability.
3. How should `overview` choose "top" issues: by event count in range, or by new-in-range first?
