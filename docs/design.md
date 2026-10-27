# Sonda — Technical Design (v1)

Status: implemented (v1). Deviations found during implementation are folded into this text.

Sonda is a self-hostable, read-only gateway that gives AI agents one credential and one
service-centric interface to production telemetry in Sentry, Loki, Prometheus, Cloudflare
Workers Observability, AWS CloudWatch and Grafana Tempo.
It stores no telemetry. It queries sources on demand, enforces per-service authorization, and
returns compact, evidence-carrying responses.

## 1. Decisions

| Topic | Decision | Rejected alternative | Reason |
|---|---|---|---|
| Interface | HTTP API + `sonda` CLI | MCP server | No context cost until used. One contract (HTTP) for agents, bots and CI. MCP can be a thin adapter later. |
| Language | Go | TypeScript/Bun | The Prometheus PromQL parser and the AWS SDK are Go. Single static binary. |
| Binaries | `sonda-server` and `sonda` (CLI), one Go module | One binary with subcommands | The CLI imports only the `api` package, so it does not link the parsers, connectors or database drivers. |
| Native queries | Allowed, in each backend's own dialect, scoped to one service by `policy` | Plain passthrough; string concatenation | Passthrough leaks other services. String concatenation protects only one selector. |
| Query languages | Native dialect per backend (LogQL, PromQL, TraceQL, Logs Insights, Cloudflare query JSON, Vercel KQL, structured metric JSON) plus backend-neutral `logs search` and `traces search` | One Sonda query language translated to every backend | Agents already know the native dialects. A translated language covers only the common subset; the neutral search covers the common case. `describe` reports the dialect per capability. |
| TraceQL scoping | Own lexer `internal/traceql` | Tempo's parser | Tempo is AGPL-licensed, like Loki. Sonda is MIT. Same approach as `internal/logql`. |
| Logs Insights scoping | Own lexer `internal/insights` and an allowlist of commands | Rely on the `logGroupIdentifiers` API parameter alone | The query text can read other log groups itself (`SOURCE`, `join`, `appendcols`). AWS does not document which wins. |
| CloudWatch metrics | Only `MetricStat`, from JSON `{metric, stat, dimensions}` | `Expression`, `SEARCH`, Metrics Insights | They cannot be scoped (section 6). |
| Cloudflare queries | A JSON subset of the Workers Observability query, AND-wrapped with the script filter | Passthrough of the full request body | `queryId` runs a saved query and `datasets` changes what is read; both could bypass the filters. |
| Vercel logs | The Observability events API that the Vercel CLI's `logs` command uses | The documented per-deployment runtime logs stream | The stream covers one deployment and has no filter or range. The events API is not in Vercel's public OpenAPI spec, so it may change without notice. |
| Cloudflare metrics | Fixed catalog over GraphQL Analytics datasets of Workers, Durable Objects, D1, Queues and R2, query built by the server | Agent-written GraphQL | GraphQL can name any script, resource or account. The server sets `accountTag`, the bound script or resource IDs and the range as variables. |
| Code structure | Small backend interfaces per capability in `query` (`logBackend`, `metricBackend`, `traceBackend`) | Use cases calling concrete clients directly | Each capability has several backends. The use cases stay shared; each backend binds its typed scope and client. |
| Sentry traces | The spans dataset of the organization events endpoint, with the project and environment as parameters and a post-check of every span | Project-scoped endpoints | Sentry has no project-scoped span search. The parameters are ANDed with the query text, and the post-check catches a filter that Sentry did not apply. |
| Trace visibility | Spans of services without a `traces` grant become stubs | Reject traces that cross services; return them in full | A trace is useful only as a whole. Stubs show where time went without revealing names, attributes or events. |
| Configuration | Sources, services and limits in one YAML file, loaded at startup | Everything in a database | Reviewable in git. These change rarely and define the security boundary (bindings). |
| Identities | In the identity store, managed at runtime in the admin UI | In the YAML file | Tokens are created, rotated and revoked often; a restart for each change is impractical. |
| Identity store | `identities.Store` interface, implemented by `store` for SQLite and Postgres | SQLite only | Another database can be added without touching `authz` or the UI. |
| Admin UI | Server-rendered `html/template` + htmx, embedded in `sonda-server` | React SPA | No JS toolchain, one binary. The UI is a few forms and tables. |
| Provider secrets | Environment variable references in YAML; the AWS default credential chain | Encrypted in the database | No key management in v1. |
| Cloud credentials | Sonda is an OIDC issuer of its own identity (`identity.issuer`); an aws source with `credentials: identity` assumes its role with `AssumeRoleWithWebIdentity` | The workload identity of the hosting platform (IRSA, a platform OIDC token); a long-lived IAM access key | Works on any platform, needs no secret at deploy time, and AWS issues only short-lived sessions. The signing key and the issuer URL become the trust anchor (section 12). |
| Backends in a private network | Loki, Prometheus or Tempo in a Kubernetes cluster through the API server's service proxy, with `auth: eks` | A VPN or a relay inside the network | Nothing new runs in the private network; access is an IAM role, an EKS access entry and a Role on `services/proxy`. |
| Internal storage | SQLite (`modernc.org/sqlite`, pure Go) by default; Postgres (`pgx`) when `server.database` is a `postgres://` URL | SQLite only | SQLite needs no extra service. Postgres suits deployments without a persistent volume. Both hold identities, the audit log and result handles in the same tables and run the same queries; only the schema types and the unique-violation check differ. Metadata caches live in memory. |
| Loki/Prometheus/Tempo access | Direct connection to the native HTTP API | Through Grafana (`/api/ds/query` or the datasource proxy) | No dependency on Grafana, full API (e.g. `detected_fields`), clearer upstream errors. The Grafana datasource proxy still works as a plain `url` when Grafana is the only reachable endpoint. |
| Range limit | Reject ranges over `max_range` with `limit_exceeded` | Silently shorten the range | A shortened range would make counts look complete when they are not. |
| Native query capability | Same capability as the structured tools (`logs`, `metrics`, `traces`) | Separate `logs:native` / `metrics:native` | Native queries are scoped the same way; cost is bounded by limits. |
| Kubernetes access | Plain HTTP against the API server: pods and ReplicaSets by namespace and label selector, events of the namespace filtered by object | `client-go`; Kubernetes events through Loki | Three list calls need no client library. Events are not in the log pipelines we run, and the API keeps them for about an hour. |
| Kubernetes scope | A namespace and exact labels (`key: value`) | A free label selector | Exact labels are both the upstream selector and an exact post-check, and cannot express "everything except". |
| Workloads capability | A new capability `workloads` | Serve pods under `logs` or `metrics` | Pod state, rollouts and events are a separate kind of data; a grant should name it. |
| Alerts source | The Prometheus-compatible alerts API of Prometheus/Mimir (`/api/v1/alerts`) or of Grafana-managed alerting (a `grafana` source) | Alertmanager; Grafana's own alerting API | One response shape for both. Alertmanager holds only firing alerts, after grouping and silencing. |
| Alerts scope | A Prometheus `selector` over the alert labels, applied by Sonda | Upstream filtering | The alerts API has no label filter; it returns every alert the token can read, and Sonda drops those that do not match. |
| Alerts capability | A new capability `alerts` | Serve alerts under `metrics` | Alerts may come from another source than metrics (Grafana), and a grant should name it. |
| Access unit | A project owns services; grants are `(project, environment, capability)` | Grants per service; named sets of service grants; a project with several bindings per capability instead of services | A product spans several platforms, and its agents need all of them. Grants per service must be repeated for every new service. A project with several bindings per capability would lose the one dialect per capability that native queries and signals rely on. |
| Workspaces | One server = one workspace | Multi-workspace in v1 | No current need. Nothing in the model prevents adding it later. |

## 2. Domain model

```text
Source ──< Binding >── Environment ──< Service >── Project
                                                     │
Identity ──< Grant (projects × environments × capabilities)
```

- **Source**: a connection to a backend. Types:

  | Type | Backend | Capabilities | Connection |
  |---|---|---|---|
  | `sentry` | Sentry | errors, traces | `url`, `org`, auth |
  | `loki` | Loki | logs | `url`, auth, headers |
  | `prometheus` | Prometheus, Mimir, Thanos, VictoriaMetrics, Grafana Cloud | metrics, alerts | `url`, auth, headers |
  | `cloudflare` | Workers Observability, GraphQL Analytics | logs, metrics, traces | `account_id`, bearer token; `url` defaults to `https://api.cloudflare.com/client/v4` |
  | `aws` | CloudWatch Logs Insights, CloudWatch metrics | logs, metrics | `region`, `credentials` (`default` or `identity`), `role_arn` (optional with `default`) + `external_id`, `max_scan_bytes` (default 10 GB) |
  | `tempo` | Grafana Tempo | traces | `url`, auth, headers |
  | `kubernetes` | Kubernetes API server | workloads | `url`, bearer token; without `url`, the pod's service account (in-cluster) |
  | `grafana` | Grafana-managed alerting | alerts | `url`, auth, headers |
  | `vercel` | Vercel Observability events | logs | `team_id` (`team_…`, not the slug), bearer token; `url` defaults to `https://api.vercel.com` |

  Auth is `none`, `bearer`, `basic` or `eks` (`cluster` and `aws_source`: an EKS token signed
  with the credentials of that aws source). Extra headers carry e.g. `X-Scope-OrgID` for
  multi-tenant Loki, Mimir or Tempo. `ca_file` (any source with a `url`) names PEM certificates
  the server certificate must chain to, instead of the system roots. AWS has no URL, auth or
  headers: with `credentials: default`, credentials come from the default credential chain
  (IRSA, environment, profile), or from assuming `role_arn` with it; with
  `credentials: identity`, Sonda assumes `role_arn` with a token of its own identity.
- **Sonda's identity** (optional `identity` section): `issuer`, the public https URL of this
  Sonda. Sonda then serves an OIDC discovery document and signs tokens of its own workload
  identity (section 4).
- **Grafana** (optional): base URL and a datasource UID per source. Used only to build Explore
  links in responses. Sonda queries Grafana only through a `grafana` source, for alerts.
- **Project**: a product whose services may run on several platforms. Has a description and
  services. Identities are granted access per project.
- **Service**: a logical application in one project. Has a description, an optional repository,
  environments and signals. Service names are unique across projects, so queries, audit records
  and result handles address a service by name alone.
- **Environment**: per service, maps each capability to a source and a binding. The binding is
  the scope. Its fields depend on the source type; fields of another type are rejected.

  | Capability | Source type | Binding |
  |---|---|---|
  | `errors` | `sentry` | `project` + Sentry `environment` |
  | `logs` | `loki` | `selector`, e.g. `{app="engine", namespace="prod"}` |
  | `logs` | `cloudflare` | `script` (Worker script name) |
  | `logs` | `aws` | `log_groups`: 1 to 50 unique, exact names (not ARNs), no `*` |
  | `logs` | `vercel` | `project` (the ID `prj_…`; Vercel returns nothing for a name) + Vercel `environment`, e.g. `production`, `preview` |
  | `metrics` | `prometheus` | `selector`, e.g. `{job="engine", namespace="prod"}` |
  | `metrics` | `cloudflare` | `script`; optional `durable_object_namespaces`, `d1_databases`, `queues`, `r2_buckets` (resource name → ID) |
  | `metrics` | `aws` | `namespace` + `dimensions` (1 to 10) |
  | `traces` | `tempo` | `service` (`resource.service.name`) |
  | `traces` | `cloudflare` | `script` |
  | `traces` | `sentry` | `project` + Sentry `environment` |
  | `workloads` | `kubernetes` | `namespace` + `labels` (1 or more exact `key: value` pairs, values not empty) |
  | `alerts` | `prometheus`, `grafana` | `selector` over the alert labels, e.g. `{service="engine"}` |

- **Dialect**: each binding has the query dialect of its native query endpoint: `logql`,
  `promql`, `traceql`, `cloudflare-query`, `cloudflare-metric`, `logs-insights`,
  `cloudwatch-metric`, `sentry-search`, `vercel-kql`. `describe` returns it per capability with the source type.
- **Signal**: a named metrics query stored without scope, in the native dialect of the
  service's metrics backend. For Prometheus it is a PromQL string, e.g. `error_rate`; Sonda
  injects the environment selector the same way as for native queries. For Cloudflare and
  CloudWatch it is a mapping (`{metric: errors, by: [status]}`,
  `{metric: CPUUtilization, stat: Average}`). All metrics environments of a service with
  signals must use the same source type.
- **Identity**: an agent service account. Authenticated by a bearer token. The identity store
  keeps only the SHA-256 of the token. Managed in the admin UI (section 11), not in the config.
- **Grant**: one `(project, environment, capability)`. It covers every service of the project
  that configures the capability in that environment, including services added to the project
  later. It never covers another environment or capability. Capabilities: `errors`, `logs`,
  `metrics`, `traces`, `workloads`, `alerts`. A native query requires the same capability as the structured tool for
  that signal type. A `traces` grant also makes the project's spans visible in full inside
  traces fetched through other services (section 8). A grant for a project or capability that
  is no longer configured has no effect.
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

projects:
  engine:
    description: Content engine
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

Config validation at startup fails on: unknown fields, unknown source references, a project
without services, a service name used in two projects, unset
environment variables, a source type not allowed for the capability, binding fields of another
source type, unparsable selectors or signals, selectors without an `=` or `=~` matcher that
rejects the empty value (e.g. `{job!=""}` selects nearly everything), log group lists that are
empty, longer than 50, duplicated, or contain `*` or ARNs, CloudWatch bindings with no or more
than 10 dimensions,
signals whose form does not match the metrics backend, and an admin token shorter than 32
characters. The full example is `sonda.example.yaml`.

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
internal/telemetry backend-neutral records: log streams, spans, trace summaries, structured metric queries
internal/issuer    OIDC issuer of Sonda's own identity: signing keys, discovery, JWKS, tokens
internal/connector
  upstream/        HTTP client per source: auth, headers, error mapping
  awsauth/         AWS configuration per aws source (default chain or Sonda's identity), EKS tokens
  sentry/          Sentry REST client: issues, events, releases, spans
  loki/            Loki HTTP API client
  prometheus/      Prometheus HTTP API client (prometheus/client_golang)
  cloudflare/      Workers Observability and GraphQL Analytics client
  aws/             CloudWatch Logs and CloudWatch client (aws-sdk-go-v2)
  tempo/           Tempo HTTP API client
  kubernetes/      Kubernetes API client: pods, ReplicaSets, events
  alerting/        Prometheus-compatible alerts API client (Prometheus, Mimir, Grafana)
  vercel/          Vercel Observability events client: runtime logs
internal/query     use cases: overview, errors, logs, metrics, traces, workloads, alerts, results; one backend per source type
internal/shape     grouping (Drain), redaction, truncation, series summaries, trace trees, source links
internal/audit     per-request record of service, environment and upstream queries
internal/store     SQLite or Postgres: identities (implements identities.Store), audit log, result handles, signing keys
internal/httpapi   routing, authentication, rate and concurrency limits, audit, JSON encoding
internal/admin     admin UI: sign-in, identity management, audit log viewer
```

Boundaries:

- `httpapi` parses requests into `api` types and calls `query`. Nothing reaches a connector
  without a scope from `authz`.
- `authz` is the only way to get a scope: `ErrorScope`, `LogScope`, `MetricScope`,
  `TraceScope`, `WorkloadScope` and `AlertScope` (a `SelectorScope`), which resolve to one typed variant per source type (`SelectorScope`,
  `CloudflareScope`, `LogGroupScope`, `CloudWatchMetricScope`, `TempoScope`, `VercelScope`). Connector methods
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
| `vercel` | `POST /v1/observability/events` (event `vercel.log`) | `policy` Vercel query, `VercelScope` |

- `policy` values (`policy.LogQL`, `policy.PromQL`, `policy.TraceQL`, the Cloudflare query,
  the Insights query, the CloudWatch metric, the Vercel query) can only be constructed by `policy`. A connector
  cannot receive raw agent text.
- Metadata calls are scoped. Loki and Prometheus pass the scope selector as `match[]` /
  `query`; without it, an agent would see names of other services. Loki labels come from the
  `series` endpoint, which is scoped by design; the `labels` endpoint is not used. Prometheus
  `metadata` is not scoped, so it is only used to look up names returned by the scoped
  `label/__name__/values` call. Cloudflare `keys` carries the script filter. CloudWatch
  `GetLogGroupFields` is called per scoped log group, `ListMetrics` with the scope's namespace
  and dimensions. Cloudflare metric names are a fixed catalog. Vercel log fields are a fixed
  list, because Vercel has no endpoint for the fields seen in a range.
- Lookups by ID are fetched unscoped and checked before anything is returned: a Sentry issue
  must be of the scope's project, a trace must contain a span of the service (section 8).
- One shared HTTP client per source (`upstream`) applies auth and extra headers, for Cloudflare
  too, and only to requests to the source's own origin, so a redirect never carries them to
  another host. Connectors do not know how a source authenticates. The AWS connector uses the
  SDK with the configuration from `awsauth`, one per aws source, which EKS tokens share.
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

- Issues are listed by the organization endpoint (`/api/0/organizations/{org}/issues/`) with the
  numeric project ID as the `project` parameter, resolved once from the slug. The project
  endpoint (`/api/0/projects/{org}/{project}/issues/`) ignores `start` and `end`: it returned
  issues last seen outside the range, with counts not limited to it. A `project:` term in the
  query text cannot widen the parameter; Sentry rejects a project that is not selected.
- Lookups by ID (`GetIssue`) fetch first, then check that the issue's project equals the scope's
  project. Otherwise return `not_found`, not `forbidden`. IDs must be numeric.
- The environment grant also holds for single issues: the latest event is fetched with the
  scope's environment, and an issue without events there is `not_found`.
- List results are filtered by project slug again, as defense in depth.
- An errors binding may add `query`, Sentry search terms for services that share a project.
  They go before the agent's query in every issue search and in the event search of a single
  issue. Issue search has no `OR` (Sentry rejects it), so all terms are ANDed and the agent can
  only narrow them; an unbalanced quote is rejected by Sentry, and the scope's terms come first
  so they cannot end up inside one. An issue without matching events is `not_found`. List
  counts cover the matching events in the range; the totals of a single issue and the releases
  are project-wide.
- Verified against sentry.io: a `project:` or `environment:` term in the agent's query combines
  with the endpoint's project and the `environment` parameter by AND; it cannot widen them.
- Required token scopes: `org:read`, `project:read`, `event:read`, `project:releases`.
- Spans: `GET /api/0/organizations/{org}/events/?dataset=spans` with `projectSlug` and
  `environment`, which Sentry ANDs with the query text (the project goes into the request
  meta, the environment into the filter). Every returned span must have the scope's project
  and environment; one outside them fails the request with `internal`. A search reads the 500
  newest matching spans, groups them into traces (at most 3 matched spans each), and names each
  trace by its root transaction from a second query `is_transaction:true trace:[…]` across all
  projects (`project=-1`). Trace by ID is `trace:<id>` across all projects, at most 2000
  spans; the trace must contain a span of the scope's project in the scope's environment.

### Kubernetes specifics

- Endpoints used: `GET /api/v1/namespaces/{ns}/pods` and
  `/apis/apps/v1/namespaces/{ns}/replicasets` with `labelSelector` built from the binding's
  labels, and `/api/v1/namespaces/{ns}/events` without one, each paged with `limit` and
  `continue`. Lists stop at 500 pods, 500 ReplicaSets and 2000 events and mark the response
  `truncated`.
- Every returned pod and ReplicaSet is checked against the namespace and every label; one
  outside them fails the request with `internal`. Events carry no labels, so `query` keeps only
  events of the scope's pods and ReplicaSets, the Deployments that own those ReplicaSets, and
  pods named `<ReplicaSet>-<5 characters>`. The last rule keeps events of crashed pods that no
  longer exist; the fixed suffix length keeps out pods of a longer ReplicaSet name.
- Pods and rollouts are the current state, whatever the range; events are those overlapping
  the range. Kubernetes keeps events for about an hour by default (`--event-ttl`).
- In-cluster: without `url`, the source connects to `KUBERNETES_SERVICE_HOST`/`PORT`, trusts the
  mounted `ca.crt` and reads the mounted service account token on every request, because the
  kubelet rotates it. With `url`, a bearer token is required (a service account token secret
  works for EKS) and `ca_file` names the cluster CA.

### Sonda's identity and EKS

- With `identity.issuer`, Sonda serves `<issuer>/.well-known/openid-configuration` and
  `<issuer>/.well-known/jwks.json`. A relying party fetches both from the issuer URL, so it
  must be Sonda's public https address.
- Tokens are RS256 JWTs with `iss` the issuer, `sub` `sonda`, `aud` the relying party
  (`sts.amazonaws.com` for AWS) and a lifetime of 5 minutes. They never leave Sonda except to
  the relying party.
- The signing key is a 2048-bit RSA key in the `signing_keys` table, created on the first
  start; its ID is the RFC 7638 thumbprint. Sonda signs with the newest key and the JWKS lists
  all keys, so replicas that started with different keys still verify. Rotation is not
  automated in v1.
- In AWS: an IAM OIDC identity provider for the issuer URL with audience `sts.amazonaws.com`,
  and a role whose trust policy allows `sts:AssumeRoleWithWebIdentity` for that provider with
  conditions on `<issuer host and path>:aud` = `sts.amazonaws.com` and `:sub` = `sonda`. Each
  AWS account can trust the issuer directly, so no role chaining is needed.
- `auth: eks` sends `k8s-aws-v1.` + a presigned STS `GetCallerIdentity` URL with the signed
  header `x-k8s-aws-id: <cluster>`, as `aws eks get-token` does. EKS accepts it for 15 minutes
  after signing; Sonda reuses it for 10.
- A Loki, Prometheus or Tempo inside the cluster is reached through the API server's service
  proxy: `url` is `https://<endpoint>/api/v1/namespaces/<ns>/services/<scheme>:<service>:<port>/proxy`
  and `ca_file` is the cluster CA. The cluster needs an access entry for the role, mapped to a
  Kubernetes group, and a Role that allows `get` on `services/proxy` with `resourceNames` set to
  `<scheme>:<service>:<port>` (Prometheus also needs `create`: its client POSTs queries). The
  same role and `auth: eks` serve a `kubernetes` source.

### Alerts specifics

- Endpoints used: Prometheus `GET /api/v1/alerts` (for Mimir, the source `url` includes its
  `/prometheus` prefix) and Grafana `GET /api/prometheus/grafana/api/v1/alerts`, which returns the
  alert instances of Grafana-managed rules in the token's organization.
- The API cannot filter by labels. Sonda reads all alerts and keeps those whose labels match
  every matcher of the binding's selector; a missing label matches as the empty value. The
  selector must contain an `=` or `=~` matcher that rejects the empty value, as for metrics.
- States: Prometheus reports `firing` and `pending`; Grafana reports `Alerting`, `Pending`,
  `Recovering`, `NoData`, `Error` and `Normal`, optionally followed by a reason, e.g.
  `Alerting (Error)`. Sonda returns `firing` (for `Alerting`), `pending`, `recovering`, `nodata`
  and `error`, with the reason in `stateReason`, and drops `Normal` and `inactive`.
- Alerts are the current state; there is no range. Firing alerts sort first, then by `activeAt`,
  newest first. Responses hold at most 100 alerts and mark more as `truncated`.
- Annotations whose names start with `__` (Grafana's dashboard and panel references) are
  dropped. Annotation values are redacted; labels, annotations and values are marked untrusted.

## 5. Authorization

Request flow:

1. Authenticate: bearer token → SHA-256 → identity store lookup → Identity with effective
   limits. Changes in the admin UI apply to the next request. A constant-time compare is not
   needed: timing can reveal at most the hash, not the token.
2. Authorize: `(identity, project of the service, environment, capability)` against the grants
   → `Scope`.
3. Limit: reject ranges over `max_range`, cap lines at `max_log_lines`, apply `query_timeout`,
   rate and concurrency limits.
4. For native queries and signals: scope the query text (section 6).
5. Execute through the connector with the scope.
6. Post-check: results fetched by ID (Sentry issues, traces), Cloudflare events, Vercel logs
   and the log groups a Logs Insights query scanned.
7. Write the audit record: identity, endpoint, service, environment, final upstream query,
   duration, result size, outcome. The same fields go to the server log as a `request` line.

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
| Vercel KQL | Agent filter in parentheses, AND-combined with the environment; the project in the request scope | Post-check of every log's project and environment |
| Logs Insights | Allowlist of commands, `SOURCE` and other cross-group words rejected; log groups set by the API parameter | Post-check with `ListLogGroupsForQuery` |
| Cloudflare metric | No agent query text: the server builds GraphQL from a catalog | Post-check of every row's script or resource ID |
| CloudWatch metric | No agent query text: `MetricStat` with the scope's namespace and dimensions | — |

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

### Vercel runtime logs

- A request names the team as `ownerId` and the binding's project as the only entry of
  `projectIds`. Vercel enforces it: a filter that names another project returns nothing.
- The filter is `environment:"<env>" AND (<agent KQL>)`. The agent KQL must have balanced
  parentheses outside double-quoted strings, closed strings and no trailing escape, read as
  Vercel reads them: `\` escapes the next character inside and outside strings, and only `"`
  delimits a string. Otherwise the group could be closed from inside and the environment
  bypassed.
- Post-check: every returned log must have the binding's project and environment, otherwise
  the request fails with `internal`.
- A query returns lines only. Vercel's aggregations (`/v2/observability/query`) need the
  Observability Plus add-on.
- How far back logs are kept depends on the Vercel plan (a day on Pro). Vercel rejects an older
  range with HTTP 400, which Sonda returns as `invalid_query` with Vercel's message. A slow
  query fails with HTTP 504 after about 12 seconds, returned as `upstream_error`.

### Cloudflare and CloudWatch metrics

Neither accepts query text from the agent:

- Cloudflare: `{metric, by}`. Each catalog metric reads one GraphQL dataset and allows its own
  `by` dimensions:

  | Metrics | Dataset | Scope | `by` |
  |---|---|---|---|
  | `requests`, `errors`, `subrequests`, `cpu_time_p50`, `cpu_time_p99` (µs), `duration_p50`, `duration_p99` (ms) | `workersInvocationsAdaptive` | `script` | `status`, `scriptVersion` |
  | `do_requests`, `do_errors`, `do_wall_time_p50`, `do_wall_time_p99` (ms) | `durableObjectsInvocationsAdaptiveGroups` | `durable_object_namespaces` | `status` |
  | `do_cpu_time` (µs), `do_exceeded_cpu_errors`, `do_exceeded_memory_errors`, `do_fatal_internal_errors`, `do_sql_rows_read`, `do_sql_rows_written` | `durableObjectsPeriodicGroups` | `durable_object_namespaces` | |
  | `do_sql_stored_bytes` | `durableObjectsSqlStorageGroups` | `durable_object_namespaces` | |
  | `d1_read_queries`, `d1_write_queries`, `d1_rows_read`, `d1_rows_written`, `d1_query_time_p50`, `d1_query_time_p99` (ms) | `d1AnalyticsAdaptiveGroups` | `d1_databases` | `databaseRole` |
  | `queue_backlog_messages`, `queue_backlog_bytes` | `queueBacklogAdaptiveGroups` | `queues` | |
  | `queue_consumer_concurrency` | `queueConsumerMetricsAdaptiveGroups` | `queues` | |
  | `queue_operations`, `queue_lag_time` (ms), `queue_retries` | `queueMessageOperationsAdaptiveGroups` | `queues` | `actionType`, `outcome`, `consumerType` |
  | `r2_requests` | `r2OperationsAdaptiveGroups` | `r2_buckets` | `actionType`, `actionStatus` |
  | `r2_stored_bytes`, `r2_objects` | `r2StorageAdaptiveGroups` | `r2_buckets` | `storageClass` |

  The server builds the GraphQL query with `accountTag`, the range and the scope as variables:
  the script, or the IDs of the bound resources of the metric's kind (`<field>_in`). It checks
  the script or resource ID of every returned row. A metric of a kind the binding does not
  bind is `invalid_query`; `metrics list` shows only the bound kinds. Resource metrics have one
  series per resource, labeled `namespace`, `database`, `queue` or `bucket` with the resource
  name from the binding. The account-wide `durableObjectsStorageGroups` has no namespace
  dimension, so it is not in the catalog. The time bucket is the finest of minute, 15 minutes,
  hour or day that is at least the step; the response reports it as the step. More than 10,000
  rows (buckets × resources × dimension values) is `limit_exceeded`.
- CloudWatch: `{metric, stat, dimensions}`. `stat` is `SampleCount`, `Average`, `Sum`,
  `Minimum`, `Maximum` or a percentile (`p99`, `p99.9`). The namespace and the scope dimensions
  come from the binding. An agent dimension with a scope key and a different value is
  `invalid_query`; others are added, up to 30 in all. Sonda sends one `MetricStat`. Its period
  is the step rounded up to whole minutes and capped at the range; the response reports it as
  the step. `Expression` is never sent: metric math, `SEARCH` and Metrics Insights select
  metrics across namespaces and dimensions, and no dimension can be added to them to restrict
  the result.

### Backend-neutral search

`logs search` and `traces search` take structured filters that each backend translates. Values
are always quoted or sent as JSON values, never pasted into query text.

| Filter | Loki | Cloudflare | CloudWatch | Vercel | Tempo |
|---|---|---|---|---|---|
| `contains` | `\|= "…"` | `needle`; further values as `$metadata.message includes` leaves | `filter @message like "…"` | one bare term, every character but letters and digits escaped | — |
| `where k=v` / `k!=v` | `\| k="v"` (label names only) | `eq` / `neq` string leaves | `filter k = "v"` / `!=` | `k:"v"` / `NOT k:"v"` | `k = "v"` / `!=`; `k` is an attribute (`.k`, `span.k`, `resource.k`), `name`, `statusMessage` or `rootServiceName` |
| `pipeline` | LogQL pipeline | `invalid_request` | `invalid_request` | `invalid_request` | — |
| `minDuration`, `maxDuration` | — | `$metadata.duration` `gte` / `lte` | — | — | `duration >=` / `<=` |
| `errors` | — | `$metadata.error exists` | — | — | `status = error` |
| `name` | — | `$metadata.spanName includes` | — | — | `name =~ ".*<quoted>.*"` |

Logs Insights strings cannot hold escaped quotes, so a CloudWatch value is quoted with the quote
kind it does not contain; a value with both kinds is `invalid_request`. A Logs Insights search
returns at most 10,000 lines.

Vercel matches a bare term against whole words of the message, case-insensitive, and ignores
punctuation; several words are a phrase. So `contains` on Vercel finds words, not substrings.
`and`, `or` and `not` alone are operators, so their first letter is escaped too.

The total of `logs search` is a Loki instant count query or `recordsMatched` of the same Logs
Insights query, both exact. Cloudflare's is a `calculations` count with the same filters, which
Cloudflare weights by each event's sampling rate, so it is an estimate. Vercel reports no total:
when more logs match than the sample, Sonda pages through them with only the scope fields
selected, up to 10,000, and then marks the total with `totalLowerBound`.

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
  Cloudflare; the Logs Insights console for CloudWatch Logs. Vercel has no link, because its
  dashboard addresses teams and projects by slug, not ID. Without a link, the source entry
  carries the upstream query and range instead of a URL.
- `untrusted` lists the fields that contain raw telemetry. Agents treat them as data, never as
  instructions.
- Log lines are cut to 1000 characters. Line lists stop at 3/4 of `max_response_bytes`; the
  rest stays behind a result handle and the response is marked `truncated`. Series are capped at
  30 and about 60 points each. A response still above `max_response_bytes` fails with
  `limit_exceeded`.

### Log search

1. Total of the matching lines in the range: exact for Loki and CloudWatch, an estimate for
   Cloudflare, exact up to 10,000 for Vercel (section 6, backend-neutral search).
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

## 8. Traces

The `traces` capability is served by Tempo, Cloudflare and Sentry. Connectors return the neutral
`telemetry.Span` (trace, span and parent ID, service, name, kind, start, duration, status,
status message, attributes, events) and `telemetry.TraceSummary`. The span's service is the
OTel `service.name` for Tempo, the script name for Cloudflare and the project slug for Sentry.

| Endpoint | Purpose |
|---|---|
| `POST /v1/services/{s}/traces/search` | `minDuration`, `maxDuration`, `errors`, `name` (contains), `where[]`, `limit` → trace summaries with the matched spans of the service |
| `POST /v1/services/{s}/traces/query` | Native query: TraceQL, Cloudflare query JSON with `view: traces`, or Sentry search syntax → trace summaries |
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
  A Cloudflare trace of 2000 or more events, or a Sentry trace of 2000 or more spans, is
  `limit_exceeded`, because one fetch cannot return it whole. A Sentry trace by ID must also
  contain a span in the scope's environment.
- Trace IDs are 16 or 32 hex characters, normalized to lower case; Sentry takes only 32.
- The tree is ordered depth-first from the roots; spans whose parent is missing become roots;
  children are ordered by start time. A trace response holds at most 300 spans and is marked
  `truncated` beyond that.
- Span names, root names, status messages, event names, and attribute and event attribute
  values of visible spans are redacted. Attribute values are cut to 500 characters.
- `meta.untrusted` lists service names, span names, status messages, attributes and events.

## 9. HTTP API

All endpoints are `GET` unless stated. Time parameters: `from`, `to` (RFC 3339) or `since`
(duration, e.g. `1h`). Environment: `env`.

| Endpoint | Capability | Purpose |
|---|---|---|
| `/v1/services` | any grant | Services the identity can access, with their project, environments and granted capabilities with their source types |
| `/v1/services/{s}` | any grant | Project, environments, capabilities with backend and dialect, signals, repository |
| `/v1/services/{s}/overview` | any granted | Last releases, top issues, signal values, workload health, active alerts. The usual first call. |
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
| `/v1/services/{s}/workloads` | `workloads` | Pods (phase, readiness, restarts, container states, last termination) and rollouts now; events of the service's objects in range |
| `/v1/services/{s}/alerts` | `alerts` | Active alerts now: name, state, active since, value, labels, annotations. Takes only `env`. |
| `/v1/results/{id}` | owner | Page through or drill into a stored result |

`metrics/query` takes the query as a string in every dialect; for Cloudflare and CloudWatch it
holds JSON.

Errors use one shape: `{ "error": { "code": "not_found", "message": "…" } }`. Codes:
`unauthenticated`, `not_found`, `invalid_request`, `invalid_query`, `limit_exceeded`,
`rate_limited`, `upstream_error`, `timeout`, `internal`. `upstream_error` and `timeout` are HTTP
503, not 502/504, because proxies such as Cloudflare replace 502/504 bodies. The environment may
be omitted when the identity has exactly one environment with the needed capability.

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
sonda workloads engine-api -e production --since 1h
sonda alerts engine-api -e production
sonda result res_8KcW --group 2
```

- Config: `SONDA_URL` and `SONDA_TOKEN`, or `~/.config/sonda/config.yaml` written by `sonda auth login` with mode 0600; a wider mode is reported, and in a terminal Sonda offers to fix it.
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
  Grants are a matrix of project environments × capabilities, with the services each row
  covers; a cell no service of the project configures cannot be selected. A new or rotated token is shown once; only its SHA-256 is stored.
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
  Viewer roles.
- Provider credentials never appear in responses, errors or audit records.
- Limits: time range, lines, response bytes, timeout, concurrency, rate, and scanned bytes for
  Logs Insights.
- Audit log in the database records every request, including denied ones and admin actions.
- The admin UI can create tokens for any configured service. Protect the admin token like a
  provider credential and expose `/admin` only on a trusted network.
- Telemetry is untrusted: marked in `meta.untrusted`. Built-in rules redact bearer and basic
  tokens, URL credentials, AWS keys, JWTs, private keys and `password=`-style fields in log
  lines, Sentry titles, messages and tags, and span names, attributes, events and status
  messages; `redact` in the config adds patterns. Redaction reduces risk; it is not a
  guarantee. Stack frames and metric labels are not redacted.
- Expensive expressions inside a query (e.g. `rate(x[90d])`) are not detected by Sonda. Upstream
  limits in Prometheus, Loki and Tempo remain necessary.
- Source headers such as `X-Scope-OrgID` are sent as configured. Sonda does not check their
  values: a `|` in a tenant header can make a cross-tenant query where Loki or Tempo allows
  that, but headers are admin configuration, not agent input.
- **Cloudflare token.** Use a token with only "Workers Observability Read" and "Account
  Analytics Read" on the one account. The read permission is enough for
  `/workers/observability/telemetry/query`, although the API reference names "Workers
  Observability Write".
- **Vercel token.** Create the token for the one team in `team_id`, with an expiry. Sonda sends
  only `POST /v1/observability/events`, a read; whether Vercel offers a read-only token scope is
  open (section 14). The token `vercel login` stores expires after hours and does not fit a
  server.
- **Kubernetes role.** Bind Sonda's service account to a Role in each bound namespace with
  only `get` and `list` on `pods`, `events` and `apps/replicasets`. Events are listed for the
  whole namespace and filtered by Sonda, so the role must not be broader than the namespaces in
  the config. Container and event messages are redacted and marked untrusted.
- **Alerts token.** The alerts API returns every alert of the Prometheus tenant or Grafana
  organization, so the credential reads alerts of all services; Sonda's selector filter is the
  only scope. For Grafana, use a service account with the Viewer role in the organization that
  holds the rules.
- **Sonda's identity.** The signing key in the database is a credential: whoever reads it can
  assume every role that trusts the issuer, from anywhere. Whoever controls what the issuer URL
  serves (DNS, TLS certificate, a proxy in front of Sonda) can publish their own key and do the
  same. Trust policies must check both `aud` and `sub`. Redirects never carry a source's
  credentials to another host.
- **EKS access.** Map the role to a Kubernetes group without an EKS access policy, and allow
  only `services/proxy` with exact `resourceNames`. The proxy forwards every path and method the
  Role allows, so the backend's own write endpoints are reachable with `create`; Sonda sends
  only read calls.
- **AWS role.** Grant Sonda only these read-only actions: `logs:StartQuery`,
  `logs:GetQueryResults`, `logs:StopQuery`, `logs:ListLogGroupsForQuery`,
  `logs:GetLogGroupFields`, `cloudwatch:GetMetricData`, `cloudwatch:ListMetrics`, plus
  `kms:Decrypt` on the keys of encrypted log groups. `sts:GetCallerIdentity` needs no
  permission. With `role_arn` and `credentials: default`, the base credentials need
  `sts:AssumeRole` on that role.
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
- Editing sources, projects and services at runtime.
- Identity stores other than SQLite and Postgres (the `identities.Store` interface allows adding them).
- Automated rotation of the signing key of Sonda's identity.

## 14. Open questions

1. If a deployment can reach only Grafana, does its datasource proxy pass all needed Loki
   endpoints (`query_range`, `query`, `series`, `detected_fields`)? This affects only that
   fallback, not the default direct connection.
2. The log sample is the newest lines. For long ranges, a sample spread over the range would
   describe older patterns better, at the cost of more upstream requests.
3. How does Cloudflare combine `needle` with `filters`? Sonda assumes AND. The scope is not
   affected either way, because the script filter is in `filters` and the post-check verifies
   every event.
4. Does the Cloudflare keys endpoint take the range as `from`/`to` or as `timeframe`? Sonda
   sends `from`/`to`; a wrong guess affects only `logs fields`, not the scope.
5. Can a Vercel access token be limited to reads? If not, the token can also change the team's
   projects and deployments, and only Sonda's code keeps it read-only.

Resolved: native queries use the same capability as the structured tools (section 1).
The Workers Observability query API accepts a token with "Workers Observability Read"
(section 12).
`overview` ranks issues by event count in the range and marks issues first seen in the range
with `new: true`.
