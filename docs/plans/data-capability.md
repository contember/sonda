# Proposal: `data` capability backed by the Contember Content API

Status: proposal with a working implementation in the same pull request. The design is
folded into `docs/design.md` (sections 1, 2, 3, 4, 6 "Contember GraphQL", 7, 9, 10, 12, 13);
this document explains why and what to review.

## Why

Agents investigating a bug need two kinds of evidence: what the system did (errors, logs,
metrics, traces, which Sonda serves) and what state the data is in ("does order 1234 have a
payment", "how many published articles have no author"). Without Sonda, agents get the
second from a database or API token pasted into a prompt: unscoped, unlimited, unaudited,
often able to write.

The `data` capability gives data the same deal as telemetry: one Sonda token, scoped to a
service environment, read-only, limited, audited, with the provider credential kept on the
server.

The first backend is the Contember Content API (GraphQL). Its per-role schema makes a
read-only credential verifiable, which a raw database connection does not offer.

## What it adds

- Source type `contember` and a `data` binding: `project`, `stage` (default `live`), optional
  `entities` allow list and `deny_fields` (`Entity.field` or `*.field`).
- Capability `data`, dialect `contember-graphql`. A separate grant in the admin matrix;
  existing identities do not get it.
- `GET /v1/services/{s}/data/schema` and `POST /v1/services/{s}/data/query`;
  CLI `sonda data schema|query`; a "Data queries" section in the agent skill.
- `internal/gqlguard`: parses, normalizes and checks GraphQL against the key's own schema.
- `sonda-server check --online` and a startup check for data sources.
- Limits `data_max_rows`, `data_max_depth`, `data_max_fields`, `data_max_query_bytes`.
- A Contember engine in `dev/docker-compose.yml`, seeded by `dev/seed-contember.sh` with a
  read-only and a write role, used by integration tests locally and in CI.

## Security model

Two independent layers; each must hold on its own.

1. **Contember role.** The operator creates a role with read permissions only (ACL predicates
   hide rows) and an API key for it. Contember generates no `Mutation` type for such a role.
   The project and stage come from the binding, in the URL; the query cannot change them.
   This is why agent-written GraphQL is acceptable here, while design section 1 rejects it
   for Cloudflare: there, the account and script would be inside the query.
2. **Sonda.** The schema is introspected and cached for 10 minutes per source, project and
   stage. It shows
   what the key may do in the bound project stage, so the key should have one membership
   only. Every load fails if the schema can write (any `Mutation` field, or the `validateCreate…` and
   `validateUpdate…` queries that Contember adds only for writing roles). `serve` refuses to
   start with such a key, and a binding whose ACL later gains write access stops serving
   within one cache period. An unreachable engine only logs a warning at startup, so one
   outage does not take telemetry down.

Every query goes through `gqlguard` (design section 6, "Contember GraphQL"): one `query`
operation, no directives, fragments and variables inlined, the normalized text validated
again and checked. Root fields are limited to `get`/`list`/`paginate`. The entity allow list
and denied fields apply at every level, including derived relation fields and the keys of
`filter`, `by` and `orderBy`, so a hidden field cannot be tested by filtering or ordering.
Every list needs a limit, and nested limits multiply into one row budget.

## Review of the first draft

The first version of this plan was reviewed against the code and the Contember engine
sources. The implementation addresses:

- Allow and deny lists applied only at the root; relations, `paginate<Rel>`, `<rel>By…` and
  `_meta` bypassed them. Now checked on the typed tree at every level.
- Hidden fields reachable through `by`, `orderBy`, nested and has-one filters, and
  `totalCount`. Now rejected in all inputs, through relations and operators.
- Per-list limits did not bound the total: aliases and nesting multiplied rows. Now one row
  budget (sum over lists of the product of limits on the path), an offset cap, and depth in
  entity hops.
- Variables and defaults could drop limits or hide filters from the check. Now inlined before
  any rule runs; a null limit counts as missing.
- Layering: the scoped query is a `policy.ContemberGraphQL` value, built only by `policy`; the
  connector never receives agent text. The scope is `authz.DataScope` with a
  `ContemberScope` variant.
- A second review of the implementation found no bypass of the guard. It led to: has-one
  relations no longer counting as rows, a field cap before the quadratic validation step,
  `--var name=text` always being a string (`name:=json` for other values), shared schema
  loads, and CI failing instead of skipping when the Contember seed fails.
- Later review rounds: the normalized query is size-limited too (inlined variables could
  multiply it), startup checks run per binding in parallel, and a denied relation also
  denies its other side, so `Article.author` cannot be read back through `Author.articles`.
- Round 6: the size cap on the normalized query is enforced while variables are inlined,
  so a large variable repeated in a list cannot make Sonda build and validate megabytes of
  text first; an upstream response over 32 MB is `limit_exceeded`, not invalid JSON.
- Round 7: the same cap covers literals repeated through fragments, and an oversized
  response to Sonda's own schema queries is an upstream error, since the agent cannot fix it.
- Round 8: an agent query's response is read only up to twice `max_response_bytes`, so
  aliasing a text column hundreds of times cannot make Sonda read and redact 30 MB; the
  README tells operators to revoke `data` grants before rolling back to an older version.
- Round 9: the oversize error names `max_response_bytes`, the limit the agent must fit, and
  the generic response-size message no longer assumes a time range.
- No per-identity overrides for the data limits (they would need a store migration), no
  result handles for GraphQL trees (`limit_exceeded` instead), `check` stays offline unless
  `--online` is given.

## Tests

- `internal/gqlguard`: accept and reject cases per rule against real introspection fixtures of
  a read-only and a write role, including fragment tricks, alias multiplication, fragment
  explosion, variables with defaults, denied fields in nested filters, introspection and
  mutations; a fuzz target for normalization stability (6.7 million runs clean locally).
- Config, authz, shape (order-preserving JSON redaction) and HTTP tests for both endpoints,
  the capability check, redaction, rejection before any upstream call, and a write key.
- Integration tests against Contember 2.0.8 (`SONDA_TEST_CONTEMBER_URL`): the role's row
  predicate holds, denied fields are hidden and rejected, a write key is refused, and
  `check --online` reports a mistyped `deny_fields` entry.
- Manual end-to-end run: `sonda-server` with a read-only key, an identity created in the
  admin UI, and `sonda data schema|query` from the CLI; a write key stops `serve`.

## Open questions

- Is a data capability in scope for Sonda? It changes the one-line pitch from "telemetry" to
  "telemetry and data".
- A missing limit is rejected, not injected. Rejection teaches the agent the rule and keeps
  the audited query equal to the executed one. Injection would be friendlier for quick
  queries.
- A denied field fails the query instead of being masked. Failing tells the agent why data is
  missing; masking would let generic queries run.
- Contember System API (event history) as a second data source: "who changed this record and
  when" is a common investigation question.
- Per-identity data limits would need the first schema migration in the identity store.
