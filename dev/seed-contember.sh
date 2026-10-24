#!/usr/bin/env bash
# Seeds the local Contember engine from dev/docker-compose.yml with the sonda_test
# project: schema + ACL (dev/contember/migrate.json), two API keys and sample data.
#
#   docker compose -f dev/docker-compose.yml up -d contember
#   eval "$(dev/seed-contember.sh)"
#
# Safe to re-run: existing project, migration, keys and data are left alone.
# Progress goes to stderr, the env exports to stdout. Needs curl and shasum or sha256sum.
set -euo pipefail

CONTEMBER_URL="${CONTEMBER_URL:-http://localhost:14000}"
ROOT_TOKEN="${CONTEMBER_ROOT_TOKEN:-0000000000000000000000000000000000000000}"
PROJECT="${CONTEMBER_PROJECT:-sonda_test}"
STAGE=live
# Fixed dev tokens, registered by hash so the exports below never change.
READER_TOKEN="${SONDA_TEST_CONTEMBER_READER_TOKEN:-2222222222222222222222222222222222222222}"
WRITER_TOKEN="${SONDA_TEST_CONTEMBER_WRITER_TOKEN:-3333333333333333333333333333333333333333}"

DIR="$(cd "$(dirname "$0")" && pwd)"

log() { echo "seed-contember: $*" >&2; }

sha256() {
	if command -v sha256sum >/dev/null; then
		printf '%s' "$1" | sha256sum | cut -d' ' -f1
	else
		printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
	fi
}

# gql PATH TOKEN BODY_ARGS... prints the response body.
gql() {
	local path="$1" token="$2"
	shift 2
	curl -sS -X POST "$CONTEMBER_URL$path" \
		-H 'Content-Type: application/json' \
		-H "Authorization: Bearer $token" \
		"$@"
}

has() { grep -q "$1" <<<"$2"; }

fail() {
	log "$1"
	log "response: $2"
	exit 1
}

log "waiting for $CONTEMBER_URL"
for _ in $(seq 1 60); do
	if curl -s -o /dev/null "$CONTEMBER_URL"; then break; fi
	sleep 1
done

# 1. Project
res=$(gql /tenant "$ROOT_TOKEN" --data "{\"query\":\"mutation { createProject(projectSlug: \\\"$PROJECT\\\", name: \\\"Sonda test\\\", options: { noDeployToken: true }) { ok error { code developerMessage } } }\"}")
if has '"ok":true' "$res"; then
	log "created project $PROJECT"
elif has 'ALREADY_EXISTS' "$res"; then
	log "project $PROJECT exists"
else
	fail "createProject failed" "$res"
fi

# 2. Schema and ACL. Already executed migrations are skipped by the engine.
res=$(gql "/system/$PROJECT" "$ROOT_TOKEN" --data @"$DIR/contember/migrate.json")
has '"ok":true' "$res" || fail "migrate failed" "$res"
log "schema migrated"

# 3. API keys. A key is created only when its token does not authenticate yet.
ensure_key() {
	local role="$1" token="$2" probe
	probe=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CONTEMBER_URL/content/$PROJECT/$STAGE" \
		-H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
		--data '{"query":"{ __typename }"}')
	if [ "$probe" = 200 ]; then
		log "api key for $role exists"
		return
	fi
	res=$(gql /tenant "$ROOT_TOKEN" --data "{\"query\":\"mutation { createApiKey(projectSlug: \\\"$PROJECT\\\", description: \\\"sonda dev $role\\\", tokenHash: \\\"$(sha256 "$token")\\\", memberships: [{ role: \\\"$role\\\", variables: [] }]) { ok error { code developerMessage } } }\"}")
	has '"ok":true' "$res" || fail "createApiKey for $role failed" "$res"
	log "created api key for $role"
}
ensure_key sonda_reader "$READER_TOKEN"
ensure_key writer "$WRITER_TOKEN"

# 4. Sample data, inserted once in a single transaction with the writer key.
CONTENT="/content/$PROJECT/$STAGE"
res=$(gql "$CONTENT" "$WRITER_TOKEN" --data '{"query":"{ paginateAuthor { pageInfo { totalCount } } }"}')
has '"totalCount"' "$res" || fail "counting authors failed" "$res"
if has '"totalCount":0' "$res"; then
	# JSON strings cannot hold raw newlines, so the readable query is flattened first.
	res=$(tr '\n' ' ' <<'JSON' | gql "$CONTENT" "$WRITER_TOKEN" --data @-
{"query":"mutation {
  transaction {
    ok
    errorMessage
    t1: createTag(data: { name: \"go\" }) { ok }
    t2: createTag(data: { name: \"observability\" }) { ok }
    t3: createTag(data: { name: \"databases\" }) { ok }
    t4: createTag(data: { name: \"ai\" }) { ok }
    a1: createAuthor(data: {
      name: \"Ada Lovelace\", email: \"ada@example.com\"
      articles: [
        { create: { title: \"Notes on the Analytical Engine\", published: true, status: published, secretNote: \"ada-1\", tags: [{ connect: { name: \"ai\" } }] } }
        { create: { title: \"Loops before loops\", published: true, status: published, secretNote: \"ada-2\", tags: [{ connect: { name: \"go\" } }, { connect: { name: \"ai\" } }] } }
        { create: { title: \"Draft: Bernoulli numbers\", published: false, status: draft, secretNote: \"ada-3 unpublished\" } }
      ]
    }) { ok }
    a2: createAuthor(data: {
      name: \"Grace Hopper\", email: \"grace@example.com\"
      articles: [
        { create: { title: \"Tracing a moth\", published: true, status: published, secretNote: \"grace-1\", tags: [{ connect: { name: \"observability\" } }] } }
        { create: { title: \"Nanoseconds explained\", published: true, status: published, secretNote: \"grace-2\", tags: [{ connect: { name: \"observability\" } }, { connect: { name: \"go\" } }] } }
        { create: { title: \"Draft: COBOL for agents\", published: false, status: draft, secretNote: \"grace-3 unpublished\", tags: [{ connect: { name: \"ai\" } }] } }
      ]
    }) { ok }
    a3: createAuthor(data: {
      name: \"Edgar Codd\", email: \"edgar@example.com\"
      articles: [
        { create: { title: \"A relational model of data\", published: true, status: published, secretNote: \"edgar-1\", tags: [{ connect: { name: \"databases\" } }] } }
        { create: { title: \"Draft: Twelve rules\", published: false, status: draft, secretNote: \"edgar-2 unpublished\", tags: [{ connect: { name: \"databases\" } }] } }
      ]
    }) { ok }
  }
}"}
JSON
)
	has '"transaction":{"ok":true' "$res" || fail "inserting sample data failed" "$res"
	log "inserted 3 authors, 8 articles (3 unpublished), 4 tags"
else
	log "sample data exists"
fi

cat <<EOF
export SONDA_TEST_CONTEMBER_URL=$CONTEMBER_URL
export SONDA_TEST_CONTEMBER_PROJECT=$PROJECT
export SONDA_TEST_CONTEMBER_READER_TOKEN=$READER_TOKEN
export SONDA_TEST_CONTEMBER_WRITER_TOKEN=$WRITER_TOKEN
EOF
