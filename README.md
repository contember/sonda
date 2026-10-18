# Sonda

Your agent's eyes into production.

Sonda is a self-hosted, read-only gateway that gives AI agents one credential and one
service-centric interface to production telemetry in **Sentry**, **Loki** and
**Prometheus**. It stores no telemetry: it queries the sources on demand, restricts every
query to the services an agent may see, and returns compact responses with links back to
the source.

```text
agent ──sonda CLI──► sonda-server ──► Sentry / Loki / Prometheus
          one token     authz, query scoping, grouping, limits, audit
```

- **One token per agent.** Provider credentials stay on the server.
- **Service-centric.** Agents ask for `engine-api` in `production`; Sonda knows the Sentry
  project, the Loki selector and the Prometheus selector.
- **Enforced scoping.** Native PromQL and LogQL are allowed. Sonda parses each query and adds
  the service matchers to every selector, so a query cannot reach another service.
- **Compact answers.** Log search returns an exact count and a sample grouped into patterns;
  metrics return summaries; large results stay on the server behind result handles.
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

Requires Go 1.26.5 or newer (the Loki parser sets this minimum). A container image builds
from the `Dockerfile`.

## For agents

`skills/sonda/SKILL.md` teaches an agent the investigation flow and the commands. Install
it as a skill for Claude Code, or paste it into the agent's instructions.

| Command | Purpose |
|---|---|
| `sonda services`, `sonda describe <svc>` | What the token can access |
| `sonda overview <svc>` | Releases, top errors, signal summaries |
| `sonda errors <svc>`, `sonda error <svc> <id>`, `sonda releases <svc>` | Sentry |
| `sonda logs search/query/fields <svc>`, `sonda result <id>` | Loki |
| `sonda metrics list/query <svc>`, `sonda signal <svc> <name>` | Prometheus |

The CLI prints JSON when its output is piped and compact text in a terminal.

## Configuration

Sources, services and server limits are in `sonda.yaml` (see `sonda.example.yaml`). The server
reads it at startup. Agent identities are in the database and are managed in the admin UI. The
parts that matter for security:

- **Selectors** (`logs.selector`, `metrics.selector`) are the scoping boundary. Every query of
  the service gets these matchers. They must contain an `=` or `=~` matcher that rejects the
  empty value, and the labels must really identify the service in your data.
- **Grants** give an identity capabilities (`errors`, `logs`, `metrics`) for service
  environments. Anything else is not found.
- **Provider credentials** come from environment variables. Use read-only tokens.
- **Admin token** (`admin.token`) can create tokens for every service. Keep it secret and expose
  `/admin` only on a trusted network.

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
| `GET /v1/results/{id}` | the identity that created it |

Time ranges: `env`, `since` (`30m`, `6h`, `2d`) or `from`/`to` (RFC 3339) as query
parameters, or the same fields in POST bodies.

## Development

```bash
go test ./...
docker compose -f dev/docker-compose.yml up -d   # Loki on :13100, Prometheus on :19090
```

The design and its trade-offs are in `docs/design.md`.

## License

MIT
