#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run-e2e-tests.sh [--wait-only] [-- <cargo-test-args...>]

Waits for the gateway readiness endpoint and the REST resources required by the
compose-backed end-to-end tests, then runs all E2E test targets in the
gvm-gateway-e2e package, including ignored tests.

Environment:
  GVM_GATEWAY_E2E_BASE_URL             Default: http://127.0.0.1:8080
  GVM_GATEWAY_E2E_USERNAME             Default: admin
  GVM_GATEWAY_E2E_PASSWORD             Default: admin
  GVM_GATEWAY_E2E_READY_TIMEOUT_SECS   Default: 1200
  GVM_GATEWAY_E2E_RESOURCE_TIMEOUT_SECS Default: 1200
  GVM_GATEWAY_E2E_POLL_INTERVAL_SECS   Default: 10

Options:
  --wait-only  Stop after the REST readiness/resource checks.
EOF
}

json_field() {
  local field="$1"
  python3 -c '
import json
import sys

field = sys.argv[1]
document = json.load(sys.stdin)
value = document[field]
print(value)
' "${field}"
}

feed_summary() {
  python3 -c '
import json
import sys

document = json.load(sys.stdin)
feeds = document.get("data", [])
if not feeds:
    print("no feeds returned")
    sys.exit(2)

syncing = [feed for feed in feeds if feed.get("currentlySyncing") is True]
summary = ", ".join(
    "{}:{}:syncing={}".format(
        feed.get("type", "?"),
        feed.get("version", "?"),
        feed.get("currentlySyncing", False),
    )
    for feed in feeds
)
print(summary)
sys.exit(1 if syncing else 0)
'
}

resource_summary() {
  local resource_type="$1"
  python3 -c '
import json
import sys

resource_type = sys.argv[1]
document = json.load(sys.stdin)
items = document.get("data", [])

def lower(value):
    return str(value or "").lower()

def names():
    return ", ".join(str(item.get("name", "")) for item in items if item.get("name")) or "none"

if resource_type == "scan-configs":
    selected = next((item for item in items if "host discovery" in lower(item.get("name"))), None)
    if selected is None:
        selected = next((item for item in items if "discovery" in lower(item.get("name"))), None)
    if selected is None:
        print(f"no discovery scan config yet; available scan configs: {names()}")
        sys.exit(1)
    print("selected scan config {} ({})".format(selected.get("name"), selected.get("id")))
    sys.exit(0)

if resource_type == "scanners":
    selected = next(
        (
            item
            for item in items
            if item.get("type") in ("OSP", "OpenVAS")
            or "openvas" in lower(item.get("name"))
        ),
        None,
    )
    if selected is None and items:
        selected = items[0]
    if selected is None:
        print("no scanners returned from REST API")
        sys.exit(1)
    print("selected scanner {} ({})".format(selected.get("name"), selected.get("id")))
    sys.exit(0)

if resource_type == "port-lists":
    selected = next((item for item in items if "all iana assigned tcp" in lower(item.get("name"))), None)
    if selected is None:
        selected = next((item for item in items if "all tcp" in lower(item.get("name"))), None)
    if selected is None and items:
        selected = items[0]
    if selected is None:
        print("no port lists returned from REST API")
        sys.exit(1)
    print("selected port list {} ({})".format(selected.get("name"), selected.get("id")))
    sys.exit(0)

if resource_type == "report-formats":
    if not items:
        print("no report formats returned from REST API")
        sys.exit(1)
    preferred = next((item for item in items if item.get("id") == "c402cc3e-b531-11e1-9163-406186ea4fc5"), None)
    if preferred is None:
        preferred = next((item for item in items if lower(item.get("extension")) == "pdf"), None)
    if preferred is None:
        preferred = items[0]
    print("selected report format {} ({})".format(preferred.get("name"), preferred.get("id")))
    sys.exit(0)

print(f"unknown resource type: {resource_type}", file=sys.stderr)
sys.exit(2)
' "${resource_type}"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

wait_for_gateway_ready() {
  local deadline="$1"
  local last_observation="gateway readiness has not been queried yet"

  while (( $(date +%s) < deadline )); do
    local response
    response="$(mktemp)"
    local status
    status="$(
      curl -sS -o "${response}" -w '%{http_code}' "${BASE_URL}/ready" \
        || true
    )"
    local body
    body="$(cat "${response}")"
    rm -f "${response}"

    if [[ "${status}" == "200" ]] && [[ "$(printf '%s' "${body}" | json_field status 2>/dev/null || true)" == "ready" ]]; then
      echo "gateway ready: ${body}"
      return 0
    fi

    last_observation="status=${status} body=${body}"
    sleep "${POLL_INTERVAL_SECS}"
  done

  echo "gateway did not become ready within ${READY_TIMEOUT_SECS}s: ${last_observation}" >&2
  exit 1
}

create_session() {
  local response
  response="$(mktemp)"
  local status
  status="$(
    curl -sS -o "${response}" -w '%{http_code}' \
      -u "${USERNAME}:${PASSWORD}" \
      -X POST "${BASE_URL}/api/v1/sessions"
  )"
  local body
  body="$(cat "${response}")"
  rm -f "${response}"

  if [[ "${status}" != "201" ]]; then
    echo "create session failed: status=${status} body=${body}" >&2
    exit 1
  fi

  printf '%s' "${body}" | json_field sessionToken
}

delete_session() {
  local token="$1"
  curl -sS -o /dev/null -X DELETE \
    -H "Authorization: Bearer ${token}" \
    "${BASE_URL}/api/v1/sessions/${token}" \
    || true
}

print_feed_status() {
  local token="$1"
  local response
  response="$(mktemp)"
  local status
  status="$(
    curl -sS -o "${response}" -w '%{http_code}' \
      -H "Authorization: Bearer ${token}" \
      "${BASE_URL}/api/v1/feeds" \
      || true
  )"
  local body
  body="$(cat "${response}")"
  rm -f "${response}"

  if [[ "${status}" == "200" ]]; then
    local summary
    summary="$(printf '%s' "${body}" | feed_summary || true)"
    echo "feed status: ${summary}"
  else
    echo "feed status unavailable: status=${status} body=${body}"
  fi
}

wait_for_rest_resource() {
  local token="$1"
  local resource_name="$2"
  local resource_type="$3"
  local path="$4"
  local deadline="$5"
  local last_observation="${resource_name} has not been queried yet"

  while (( $(date +%s) < deadline )); do
    local response
    response="$(mktemp)"
    local status
    status="$(
      curl -sS -o "${response}" -w '%{http_code}' \
        -H "Authorization: Bearer ${token}" \
        "${BASE_URL}${path}" \
        || true
    )"
    local body
    body="$(cat "${response}")"
    rm -f "${response}"

    if [[ "${status}" == "200" ]]; then
      local summary_status=0
      local summary
      summary="$(printf '%s' "${body}" | resource_summary "${resource_type}")" || summary_status=$?
      last_observation="${summary}"
      echo "${resource_name}: ${summary}"
      if [[ "${summary_status}" == "0" ]]; then
        return 0
      fi
    else
      last_observation="status=${status} body=${body}"
      echo "${resource_name} unavailable: ${last_observation}"
    fi

    sleep "${POLL_INTERVAL_SECS}"
  done

  echo "${resource_name} did not become ready within ${RESOURCE_TIMEOUT_SECS}s: ${last_observation}" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

WAIT_ONLY=0
if [[ "${1:-}" == "--wait-only" ]]; then
  WAIT_ONLY=1
  shift
fi

require_command curl
require_command python3
require_command cargo

BASE_URL="${GVM_GATEWAY_E2E_BASE_URL:-http://127.0.0.1:8080}"
USERNAME="${GVM_GATEWAY_E2E_USERNAME:-admin}"
PASSWORD="${GVM_GATEWAY_E2E_PASSWORD:-admin}"
READY_TIMEOUT_SECS="${GVM_GATEWAY_E2E_READY_TIMEOUT_SECS:-1200}"
RESOURCE_TIMEOUT_SECS="${GVM_GATEWAY_E2E_RESOURCE_TIMEOUT_SECS:-1200}"
POLL_INTERVAL_SECS="${GVM_GATEWAY_E2E_POLL_INTERVAL_SECS:-10}"

if [[ "${1:-}" == "--" ]]; then
  shift
fi

wait_for_gateway_ready "$(( $(date +%s) + READY_TIMEOUT_SECS ))"

SESSION_TOKEN="$(create_session)"
trap 'delete_session "${SESSION_TOKEN}"' EXIT

print_feed_status "${SESSION_TOKEN}"
RESOURCE_DEADLINE="$(( $(date +%s) + RESOURCE_TIMEOUT_SECS ))"
wait_for_rest_resource "${SESSION_TOKEN}" "scan configs" "scan-configs" "/api/v1/scan-configs" "${RESOURCE_DEADLINE}"
wait_for_rest_resource "${SESSION_TOKEN}" "scanners" "scanners" "/api/v1/scanners" "${RESOURCE_DEADLINE}"
wait_for_rest_resource "${SESSION_TOKEN}" "port lists" "port-lists" "/api/v1/port-lists" "${RESOURCE_DEADLINE}"
wait_for_rest_resource "${SESSION_TOKEN}" "report formats" "report-formats" "/api/v1/report-formats" "${RESOURCE_DEADLINE}"
delete_session "${SESSION_TOKEN}"
trap - EXIT

if [[ "${WAIT_ONLY}" == "1" ]]; then
  exit 0
fi

exec cargo test -p gvm-gateway-e2e --tests -- --include-ignored --nocapture "$@"
