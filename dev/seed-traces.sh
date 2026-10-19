#!/usr/bin/env bash
# Pushes OTLP JSON traces of svc-a and svc-b to the Tempo in dev/docker-compose.yml.
# Each run adds new traces: one per service alone, and two that cross both services.
set -euo pipefail

url="${TEMPO_OTLP_URL:-http://localhost:14318}"

hex() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }

now=$(date +%s%N)
# at MS prints a nanosecond timestamp MS milliseconds after the start of the run.
at() { echo $((now + $1 * 1000000)); }

# span TRACE SPAN PARENT NAME KIND START_MS END_MS STATUS_CODE ATTRIBUTES
span() {
  cat <<JSON
{"traceId":"$1","spanId":"$2","parentSpanId":"$3","name":"$4","kind":$5,
 "startTimeUnixNano":"$(at "$6")","endTimeUnixNano":"$(at "$7")",
 "status":{"code":$8,"message":"$( [ "$8" = 2 ] && echo "seeded failure" )"},
 "attributes":[$9],
 "events":[{"timeUnixNano":"$(at "$6")","name":"seed","attributes":[{"key":"step","value":{"intValue":"1"}}]}]}
JSON
}

attr() { echo "{\"key\":\"$1\",\"value\":{\"stringValue\":\"$2\"}}"; }

# resource SERVICE SPANS...
resource() {
  local service=$1
  shift
  local spans
  spans=$(IFS=,; echo "$*")
  echo "{\"resource\":{\"attributes\":[$(attr service.name "$service")]},\"scopeSpans\":[{\"scope\":{\"name\":\"seed\"},\"spans\":[$spans]}]}"
}

push() {
  local body
  body="{\"resourceSpans\":[$(IFS=,; echo "$*")]}"
  curl -sSf -X POST -H 'Content-Type: application/json' --data "$body" "$url/v1/traces" >/dev/null
}

a_only=$(hex 16) a1=$(hex 8) a2=$(hex 8)
push "$(resource svc-a \
  "$(span "$a_only" "$a1" "" "GET /orders" 2 0 120 1 "$(attr http.method GET),$(attr http.route /orders)")" \
  "$(span "$a_only" "$a2" "$a1" "SELECT orders" 3 10 90 2 "$(attr db.system postgresql)")")"

b_only=$(hex 16) b1=$(hex 8) b2=$(hex 8)
push "$(resource svc-b \
  "$(span "$b_only" "$b1" "" "GET /secret" 2 0 200 1 "$(attr http.method GET),$(attr secret b-only)")" \
  "$(span "$b_only" "$b2" "$b1" "read secret" 1 20 150 2 "$(attr secret b-only)")")"

ab=$(hex 16) ab1=$(hex 8) ab2=$(hex 8) ab3=$(hex 8)
push "$(resource svc-a \
  "$(span "$ab" "$ab1" "" "POST /checkout" 2 0 300 1 "$(attr http.method POST)")" \
  "$(span "$ab" "$ab2" "$ab1" "call svc-b" 3 20 280 1 "$(attr peer.service svc-b)")")" \
  "$(resource svc-b \
  "$(span "$ab" "$ab3" "$ab2" "POST /charge" 2 30 270 2 "$(attr secret b-in-shared)")")"

ba=$(hex 16) ba1=$(hex 8) ba2=$(hex 8)
push "$(resource svc-b \
  "$(span "$ba" "$ba1" "" "GET /report" 2 0 500 1 "$(attr secret b-root)")")" \
  "$(resource svc-a \
  "$(span "$ba" "$ba2" "$ba1" "render report" 2 50 450 1 "$(attr http.method GET)")")"

echo "svc-a only:        $a_only"
echo "svc-b only:        $b_only"
echo "svc-a -> svc-b:    $ab"
echo "svc-b -> svc-a:    $ba"
