# Sonda — Technical Design (v1)

Status: implemented (v1). Deviations found during implementation are folded into this text.

Sonda is a self-hostable, read-only gateway that gives AI agents one credential and one
service-centric interface to production telemetry in Sentry, Loki and Prometheus.
It stores no telemetry. It queries sources on demand, enforces per-service authorization, and
returns compact, evidence-carrying responses.

## 1. Decisions

| Topic | Decision | Rejected alternative | Reason |
|---|---|---|---|
| Interface | HTTP API + `sonda` CLI | MCP server | No context cost until used. One contract (HTTP) for agents, bots and CI. MCP can be a thin adapter later. |
| Language | Go | TypeScript/Bun | The Prometheus PromQL parser is Go. Single static binary. |
| Binaries | `sonda-server` and `sonda` (CLI), one Go module | One binary with subcommands | The CLI imports only the `api` package, so it does not link the parsers, connectors or database drivers. |
| Native queries | Allowed in v1, scoped to one service, with matcher injection | Plain passthrough; string concatenation | Passthrough leaks other services. String concatenation protects only one selector. |
| Configuration | Sources, services and limits in one YAML file, loaded at startup | Everything in a database | Reviewable in git. These change rarely and define the security boundary (selectors). |
| Identities | In the identity store, managed at runtime in the admin UI | In the YAML file | Tokens are created, rotated and revoked often; a restart for each change is impractical. |
| Identity store | `identities.Store` interface, implemented by `store` for SQLite and Postgres | SQLite only | Another database can be added without touching `authz` or the UI. |
| Admin UI | Server-rendered `html/template` + htmx, embedded in `sonda-server` | React SPA | No JS toolchain, one binary. The UI is a few forms and tables. |
| Provider secrets | Environment variable references in YAML | Encrypted in the database | No key management in v1. |
| Internal storage | SQLite (`modernc.org/sqlite`, pure Go) by default; Postgres (`pgx`) when `server.database` is a `postgres://` URL | SQLite only | SQLite needs no extra service. Postgres suits deployments without a persistent volume. Both hold identities, the audit log and result handles in the same tables and run the same queries; only the schema types and the unique-violation check differ. Metadata caches live in memory. |
| Loki/Prometheus access | Direct connection to the native HTTP API | Through Grafana (`/api/ds/query` or the datasource proxy) | No dependency on Grafana, full API (e.g. `detected_fields`), clearer upstream errors. The Grafana datasource proxy still works as a plain `url` when Grafana is the only reachable endpoint. |
| Range limit | Reject ranges over `max_range` with `limit_exceeded` | Silently shorten the range | A shortened range would make counts look complete when they are not. |
| Native query capability | Same capability as the structured tools (`logs`, `metrics`) | Separate `logs:native` / `metrics:native` | Native queries are scoped the same way; cost is bounded by limits. |
| Workspaces | One server = one workspace | Multi-workspace in v1 | No current need. Nothing in the model prevents adding it later. |

## 2. Domain model

```text
Source ──< Binding >── Environment ──< Service
                                         │
Identity ──< Grant (services × environments × capabilities)
```

- **Source**: a connection to a backend. Types: `sentry`, `loki`, `prometheus`. Each source has
  its own URL and auth (`none`, `bearer` or `basic`) and optional extra headers, e.g.
  `X-Scope-OrgID` for multi-tenant Loki or Mimir. Prometheus-compatible backends
  (Mimir, Thanos, VictoriaMetrics, Grafana Cloud) use the `prometheus` type.
- **Grafana** (optional): base URL and a datasource UID per source. Used only to build Explore
  links in responses. Sonda does not query Grafana.
- **Service**: a logical application. Has a description, an optional repository, environments and
  signals.
- **Environment**: per service, maps each capability to a source and a scope:
  - `errors` → Sentry project slug + Sentry environment name.
  - `logs` → Loki source + label selector, e.g. `{app="engine", namespace="prod"}`.
  - `metrics` → Prometheus source + label selector, e.g. `{job="engine", namespace="prod"}`.
- **Signal**: a named PromQL expression defined by the admin per service, e.g. `error_rate`. It
  is written without service matchers. Sonda injects the environment selector the same way as for
  native queries.
- **Identity**: an agent service account. Authenticated by a bearer token. The identity store
  keeps only the SHA-256 of the token. Managed in the admin UI (section 10), not in the config.
- **Grant**: one `(service, environment, capability)`. Capabilities: `errors`, `logs`,
  `metrics`. A native query requires the same capability as the structured tool for that signal
  type. A grant for a service or capability that is no longer configured has no effect.
- **Limits**: server defaults from the config plus per-identity overrides from the store.

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
    signals:
      error_rate: sum(rate(http_requests_total{code=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))
      p95_latency: histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))

limits:
  max_range: 7d
  max_log_lines: 500
  max_response_bytes: 65536
  query_timeout: 30s
  concurrent_queries: 4
  requests_per_minute: 60
```

Config validation at startup fails on: unknown fields, unknown source references, unset
environment variables, unparsable selectors or signals, selectors without an `=` or `=~` matcher
that rejects the empty value (e.g. `{job!=""}` selects nearly everything), and an admin token
shorter than 32 characters. The full example is `sonda.example.yaml`.

## 3. Components

```text
cmd/sonda-server   main: load config, open the database, start HTTP server and admin UI
cmd/sonda          CLI: thin HTTP client over the api package

api/               request/response types shared by server and CLI (public package)
internal/client    HTTP client used by the CLI
internal/config    YAML loading, env expansion, validation → typed Config
internal/identities  identity and grant types, Store interface, token generation
internal/authz     token → Identity; (Identity, service, env, capability) → Scope or error
internal/policy    PromQL/LogQL matcher injection and verification; time range and step
internal/logql     LogQL lexer that finds and rewrites stream selectors
internal/connector
  upstream/        HTTP client per source: auth, headers, error mapping
  sentry/          Sentry REST client
  loki/            Loki HTTP API client
  prometheus/      Prometheus HTTP API client (prometheus/client_golang)
internal/query     use cases: overview, errors, logs search, metrics, results
internal/shape     grouping (Drain), redaction, truncation, series summaries, source links
internal/audit     per-request record of service, environment and upstream queries
internal/store     SQLite or Postgres: identities (implements identities.Store), audit log, result handles
internal/httpapi   routing, authentication, rate and concurrency limits, audit, JSON encoding
internal/admin     admin UI: sign-in, identity management, audit log viewer
```

Boundaries:

- `httpapi` parses requests into `api` types and calls `authz` first. Nothing reaches `query`
  without a `Scope`.
- `authz.ErrorScope` and `authz.SelectorScope` are the only way to get a source, a Sentry project
  or a label selector. Connector methods take a scope, never a service name from the request. A
  usable scope cannot be built outside `authz` (fields are unexported; `Matchers()` returns a deep
  copy).
- `policy` is the only code that turns user query text into upstream query text.
- Connectors know nothing about identities or services. They execute scoped queries and return
  typed results.
- `shape` turns connector results into compact responses. It has no I/O.
- `admin` writes identities only through `identities.Store` and accepts only grants for
  capabilities configured in the YAML file.

## 4. Connector contracts

Connectors are concrete clients, one per source. There are no connector interfaces in v1;
they would have one implementation each.

```go
// sentry.Client
ListIssues(ctx, scope authz.ErrorScope, r api.TimeRange, query, sort string, limit int) ([]Issue, error)
GetIssue(ctx, scope authz.ErrorScope, id string) (Issue, error)
LatestEvent(ctx, scope authz.ErrorScope, id string) (Event, error)
Releases(ctx, scope authz.ErrorScope, limit int) ([]Release, error)

// loki.Client
Lines(ctx, q policy.LogQL, r api.TimeRange, limit int) ([]Stream, error)
Matrix(ctx, q policy.LogQL, r api.TimeRange, step time.Duration) (model.Matrix, error)
Instant(ctx, q policy.LogQL, at time.Time) (model.Vector, error)
Series(ctx, scope authz.SelectorScope, r api.TimeRange) ([]map[string]string, error)
DetectedFields(ctx, scope authz.SelectorScope, r api.TimeRange) ([]Field, error)

// prometheus.Client
QueryRange(ctx, q policy.PromQL, r api.TimeRange, step time.Duration) (model.Matrix, error)
MetricNames(ctx, scope authz.SelectorScope, r api.TimeRange) ([]string, error)
Metadata(ctx) (map[string][]v1.Metadata, error)
```

- `policy.LogQL` and `policy.PromQL` can only be constructed by `policy`. A connector cannot
  receive raw user text.
- Metadata calls pass the scope selector as `match[]` / `query`. Without it, an agent would see
  names of other services. Loki labels come from the `series` endpoint, which is scoped by
  design; the `labels` endpoint is not used. Prometheus `metadata` is not scoped, so it is only
  used to look up names returned by the scoped `label/__name__/values` call.
- New backends (Tempo, CloudWatch, Datadog) add a new client and use cases. No generic plugin
  system in v1.

### Loki and Prometheus specifics

- One shared HTTP client per source applies auth and extra headers. Connectors do not know how a
  source authenticates.
- Endpoints used: Prometheus `query_range`, `label/__name__/values`, `metadata`; Loki
  `query_range`, `query`, `series`, `detected_fields` (skipped on Loki versions without it).
- Read-only credentials: Grafana Cloud access policy tokens with `logs:read` / `metrics:read`.
  Self-hosted backends without auth must be reachable only from Sonda's network.

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
4. For native queries and signals: inject the scope selector (section 6).
5. Execute through the connector with the scope.
6. Post-check results fetched by ID.
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

Sonda finds every selector of the query, appends the scope matchers to it (skipping matchers
the selector already has), and serializes the query back. It then re-parses the result and
checks that every selector carries all scope matchers, so a serialization bug cannot silently
drop the scope. Matchers combine with AND, so:

- `app=~".*"` from the agent is narrowed by the injected `app="engine"`.
- `app="other"` from the agent yields an empty result. No data leaks.
- Queries with several selectors (`or`, binary operations, subqueries) are covered, because every
  selector node gets the matchers.

One native query is scoped to exactly one service and environment. Services may use different
label sets, so a union cannot be expressed as one injected matcher.

The scope selector is a security setting. If a service's logs or metrics lack the label, the
filter cannot protect them. Config review must check this.

### PromQL and LogQL

- **PromQL** is parsed with the Prometheus parser (Apache-2.0). Selectors are rewritten in the
  AST, which is serialized back.
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
Mitigation: pin the Loki version, keep the replace directives (commented in `go.mod`), and
treat each Loki upgrade as a deliberate change. If the cost becomes a problem, vendor the
`syntax` and `pattern/drain` packages alone. Final sizes: `sonda-server` 45 MB, `sonda` 10 MB.

Since then, Sonda links no Loki code (Loki is AGPL-licensed, Sonda is MIT): LogQL scoping
uses `internal/logql` and log grouping uses its own Drain implementation in `internal/shape`.
`sonda-server` is 28 MB, and the `replace` directives are gone.

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
    "untrusted": ["data.groups[].pattern", "data.groups[].example"]
  }
}
```

- `sources` are deep links to Sentry, and to Grafana Explore when `grafana` is configured, so a
  human can verify the finding. Without Grafana, the source entry carries the upstream query and
  range instead of a URL.
- `untrusted` lists the fields that contain raw telemetry. Agents treat them as data, never as
  instructions.
- Log lines are cut to 1000 characters. Line lists stop at 3/4 of `max_response_bytes`; the
  rest stays behind a result handle and the response is marked `truncated`. Series are capped at
  30 and about 60 points each. A response still above `max_response_bytes` fails with
  `limit_exceeded`.

### Log search

1. Exact total: `sum(count_over_time(<selector + filter>[range]))` as one instant query.
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

Only Prometheus metric metadata (type and help of all metrics) is cached, in memory per source,
for 10 minutes. It holds no per-service data: names come from the scoped call on every request.

## 8. HTTP API

All endpoints are `GET` unless stated. Time parameters: `from`, `to` (RFC 3339) or `since`
(duration, e.g. `1h`). Environment: `env`.

| Endpoint | Capability | Purpose |
|---|---|---|
| `/v1/services` | any grant | Services the identity can access |
| `/v1/services/{s}` | any grant | Environments, capabilities, signals, repository |
| `/v1/services/{s}/overview` | any granted | Last releases, top issues, signal values. The usual first call. |
| `/v1/services/{s}/errors` | `errors` | Issues: title, count, users, first/last seen, link |
| `/v1/services/{s}/errors/{id}` | `errors` | Issue + latest event in `env` with stack trace (in-app frames, newest first) |
| `/v1/services/{s}/releases` | `errors` | Releases and deploys in range |
| `POST /v1/services/{s}/logs/search` | `logs` | Filter text and/or LogQL pipeline → total + groups |
| `POST /v1/services/{s}/logs/query` | `logs` | Native LogQL (injected) → lines or series |
| `/v1/services/{s}/logs/fields` | `logs` | Labels and detected fields |
| `/v1/services/{s}/metrics` | `metrics` | Metric names with type and help |
| `/v1/services/{s}/signals/{name}` | `metrics` | Signal series + summary (count, min, max, avg, first, last) |
| `POST /v1/services/{s}/metrics/query` | `metrics` | Native PromQL (injected) → series + summary |
| `/v1/results/{id}` | owner | Page through or drill into a stored result |

Errors use one shape: `{ "error": { "code": "not_found", "message": "…" } }`. Codes:
`unauthenticated`, `not_found`, `invalid_request`, `invalid_query`, `limit_exceeded`,
`rate_limited`, `upstream_error`, `timeout`, `internal`. The environment may be omitted when the
identity has exactly one environment with the needed capability.

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
- Ships with `skills/sonda/SKILL.md` that teaches agents the investigation flow: `overview` →
  `errors` → `logs search` → drill-down.

## 10. Admin UI

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

## 11. Security

- Read-only: connectors implement only read calls. Provider tokens use read-only scopes or
  Viewer roles.
- Provider credentials never appear in responses, errors or audit records.
- Limits: time range, lines, response bytes, timeout, concurrency, rate.
- Audit log in the database records every request, including denied ones and admin actions.
- The admin UI can create tokens for any configured service. Protect the admin token like a
  provider credential and expose `/admin` only on a trusted network.
- Telemetry is untrusted: marked in `meta.untrusted`. Built-in rules redact bearer and basic
  tokens, URL credentials, AWS keys, JWTs, private keys and `password=`-style fields in log lines
  and Sentry titles, messages and tags; `redact` in the config adds patterns. Redaction reduces
  risk; it is not a guarantee. Stack frames and metric labels are not redacted.
- Expensive expressions inside a query (e.g. `rate(x[90d])`) are not detected by Sonda. Upstream
  limits in Prometheus and Loki remain necessary.

## 12. Out of scope for v1

- MCP adapter.
- Traces (Tempo), CloudWatch, Datadog, Elasticsearch.
- Correlation tools (`get_related_events`). The agent correlates using links, release versions
  and timestamps.
- General query-result cache shared across identities.
- Multi-workspace, SSO/OIDC for the admin UI, a token management API.
- Editing sources and services at runtime.
- Identity stores other than SQLite and Postgres (the `identities.Store` interface allows adding them).

## 13. Open questions

1. If a deployment can reach only Grafana, does its datasource proxy pass all needed Loki
   endpoints (`query_range`, `query`, `series`, `detected_fields`)? This affects only that
   fallback, not the default direct connection.
2. The log sample is the newest lines. For long ranges, a sample spread over the range would
   describe older patterns better, at the cost of more upstream requests.

Resolved: native queries use the same capability as the structured tools (section 1).
`overview` ranks issues by event count in the range and marks issues first seen in the range
with `new: true`.
