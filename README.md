# Sonda

Your agent's eyes into production.

Sonda is a self-hosted, read-only gateway that gives AI agents one credential and one
service-centric interface to production telemetry. It stores no telemetry: it queries the
sources on demand, restricts every query to the services an agent may see, and returns
compact responses with links back to the source.

| Source | Capabilities |
|---|---|
| **Sentry** | errors, releases |
| **Loki** | logs |
| **Prometheus** (and Mimir, Thanos, VictoriaMetrics, Grafana Cloud) | metrics |
| **Cloudflare** Workers Observability and GraphQL Analytics | logs, metrics, traces |
| **AWS CloudWatch** Logs Insights and metrics | logs, metrics |
| **Grafana Tempo** | traces |

```text
agent ──sonda CLI──► sonda-server ──► Sentry / Loki / Prometheus / Cloudflare / CloudWatch / Tempo
          one token     authz, query scoping, grouping, limits, audit
```

- **One token per agent.** Provider credentials stay on the server.
- **Service-centric.** Agents ask for `engine-api` in `production`; Sonda knows the Sentry
  project, the Loki selector, the Worker script, the log groups and the Tempo service name.
- **Enforced scoping.** Native queries are allowed in each backend's own dialect (LogQL,
  PromQL, TraceQL, Logs Insights, Cloudflare query JSON). Sonda adds the service scope to
  every query, so a query cannot reach another service. `describe` tells the agent which
  dialect a capability takes.
- **Compact answers.** Log search returns an exact count and a sample grouped into patterns;
  metrics return summaries; a trace is a span tree. Large results stay on the server behind
  result handles.
- **Audited and limited.** Every request is logged; time range, lines, response size,
  timeouts, rate and concurrency are limited per identity.

Sonda does not reason about incidents. The agent does; Sonda supplies the evidence.

## Quick start

```bash
go build -o . ./cmd/...            # builds sonda-server and sonda

cp sonda.example.yaml sonda.yaml   # configure sources and services
export SONDA_ADMIN_TOKEN=$(openssl rand -hex 32)
./sonda-server check -c sonda.yaml
./sonda-server serve -c sonda.yaml

# Open http://localhost:8080/admin, sign in with the admin token, create an identity
# and copy its token.
export SONDA_URL=http://localhost:8080 SONDA_TOKEN=sonda_...
./sonda services
./sonda overview engine-api -e production
```

Requires Go 1.26.5 or newer. A container image builds from the `Dockerfile`.

## For agents

`skills/sonda/SKILL.md` teaches an agent the investigation flow and the commands. Install
it as a skill for Claude Code, or paste it into the agent's instructions.

| Command | Purpose |
|---|---|
| `sonda services`, `sonda describe <svc>` | What the token can access; backend and dialect per capability |
| `sonda overview <svc>` | Releases, top errors, signal summaries |
| `sonda errors <svc>`, `sonda error <svc> <id>`, `sonda releases <svc>` | Sentry |
| `sonda logs search/query/fields <svc>`, `sonda result <id>` | Logs |
| `sonda metrics list/query <svc>`, `sonda signal <svc> <name>` | Metrics |
| `sonda traces search/query <svc>`, `sonda trace <svc> <id>` | Traces |

The CLI prints JSON when its output is piped and compact text in a terminal.

## Configuration

Sources, services and server limits are in `sonda.yaml` (see `sonda.example.yaml`). The server
reads it at startup. Agent identities are in the database and are managed in the admin UI. The
parts that matter for security:

- **Bindings** are the scoping boundary. Every query of the service is restricted to them:
  - Loki and Prometheus `selector`: must contain an `=` or `=~` matcher that rejects the empty
    value, and the labels must really identify the service in your data.
  - Cloudflare `script`: the Worker script name.
  - CloudWatch `log_groups`: 1 to 50 exact log group names, no patterns.
  - CloudWatch metrics `namespace` and `dimensions`: at least one dimension.
  - Tempo `service`: the `resource.service.name` of the service's spans.
- **Grants** give an identity capabilities (`errors`, `logs`, `metrics`, `traces`) for service
  environments. Anything else is not found. A `traces` grant also decides which spans of a
  trace an identity sees in full; spans of other services are reduced to service, timing and
  status.
- **Provider credentials** come from environment variables or, for AWS, the default credential
  chain. Use read-only tokens and roles; the Security section of `docs/design.md` lists the
  Cloudflare permission and the AWS IAM actions.
- **Admin token** (`admin.token`) can create tokens for every service. Keep it secret and expose
  `/admin` only on a trusted network.

Sources and bindings for Cloudflare, AWS and Tempo:

```yaml
sources:
  cloudflare:
    type: cloudflare
    account_id: "${CF_ACCOUNT_ID}"
    auth: { type: bearer, token: "${CF_API_TOKEN}" }  # url defaults to https://api.cloudflare.com/client/v4
  aws-prod:
    type: aws
    region: eu-west-1
    role_arn: "${SONDA_AWS_ROLE_ARN}"  # optional; the default credential chain otherwise
    max_scan_bytes: 10GB               # Logs Insights is billed by scanned bytes
  tempo-prod:
    type: tempo
    url: http://tempo.monitoring.svc:3200
    headers: { X-Scope-OrgID: prod }   # multi-tenant Tempo only
    grafana_datasource_uid: tempo-prod

services:
  web-worker:
    environments:
      production:
        logs:    { source: cloudflare, script: web-worker }
        metrics: { source: cloudflare, script: web-worker }
        traces:  { source: cloudflare, script: web-worker }
    signals:
      errors: { metric: errors, by: [status] }  # Cloudflare signals are mappings
  engine-db:
    environments:
      production:
        logs:    { source: aws-prod, log_groups: [/aws/rds/cluster/engine/postgresql] }
        metrics: { source: aws-prod, namespace: AWS/RDS, dimensions: { DBClusterIdentifier: engine } }
    signals:
      cpu: { metric: CPUUtilization, stat: Average }
  engine-api:
    environments:
      production:
        traces: { source: tempo-prod, service: engine-api }  # resource.service.name
```

A signal is PromQL for Prometheus and a mapping for Cloudflare or CloudWatch. All metrics
environments of a service with signals must use the same source type.

## Admin UI

Set `admin.token` to enable the UI at `/admin`. Without it, the UI is not served.

- **Identities**: create an identity, select its grants in a service × capability matrix,
  override limits, rotate or revoke its token. Changes apply to the next request; no restart.
  A token is shown once; Sonda stores only its SHA-256.
- **Audit log**: every agent request and every admin action, filterable by identity.

The UI is server-rendered with htmx and embedded in `sonda-server`.

## HTTP API

The CLI is a thin client over the API in `api/`. All endpoints need
`Authorization: Bearer <token>`.

| Endpoint | Capability |
|---|---|
| `GET /v1/services`, `GET /v1/services/{s}` | any grant |
| `GET /v1/services/{s}/overview` | any granted |
| `GET /v1/services/{s}/errors`, `/errors/{id}`, `/releases` | `errors` |
| `POST /v1/services/{s}/logs/search`, `/logs/query`; `GET /logs/fields` | `logs` |
| `GET /v1/services/{s}/metrics`, `/signals/{name}`; `POST /metrics/query` | `metrics` |
| `POST /v1/services/{s}/traces/search`, `/traces/query`; `GET /traces/{id}` | `traces` |
| `GET /v1/results/{id}` | the identity that created it |

Time ranges: `env`, `since` (`30m`, `6h`, `2d`) or `from`/`to` (RFC 3339) as query
parameters, or the same fields in POST bodies.

## Development

```bash
go test ./...
docker compose -f dev/docker-compose.yml up -d   # Loki on :13100, Prometheus on :19090, Tempo on :13200, Postgres on :15432
SONDA_TEST_LOKI_URL=http://localhost:13100 go test ./internal/logql   # LogQL scoping against a real Loki
dev/seed-traces.sh                               # traces of two services in the local Tempo
SONDA_TEST_TEMPO_URL=http://localhost:13200 go test ./internal/traceql   # TraceQL scoping against a real Tempo
SONDA_TEST_POSTGRES_URL=postgres://sonda:sonda@localhost:15432/sonda go test ./internal/store   # store against Postgres
```

The design and its trade-offs are in `docs/design.md`.

## License

MIT
