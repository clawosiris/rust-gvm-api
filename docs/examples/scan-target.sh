#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: docs/examples/scan-target.sh <target-host>

Runs a one-shot scan through the REST gateway: creates a target, creates and
starts a task, waits for the scan to finish, writes all report results as JSON,
exports the report as PDF, downloads the PDF, and then closes the REST session.
The created target, task, and report remain in gvmd.

Environment:
  GVM_GATEWAY_BASE_URL              Default: http://127.0.0.1:8080
  GVM_GATEWAY_USERNAME              Default: admin
  GVM_GATEWAY_PASSWORD              Default: admin
  GVM_SCAN_TARGET_NAME              Default: scan-target-<timestamp>
  GVM_SCAN_TASK_NAME                Default: scan-task-<timestamp>
  GVM_SCAN_OUTPUT_DIR               Default: scan-output-<timestamp>
  GVM_SCAN_POLL_INTERVAL_SECS       Default: 15
  GVM_SCAN_TIMEOUT_SECS             Default: 7200
  GVM_REPORT_EXPORT_POLL_SECS       Default: 5
  GVM_REPORT_EXPORT_TIMEOUT_SECS    Default: 900
  GVM_SCAN_CONFIG_ID                Optional explicit scan config UUID
  GVM_SCANNER_ID                    Optional explicit scanner UUID
  GVM_PORT_LIST_ID                  Optional explicit port list UUID
  GVM_PDF_REPORT_FORMAT_ID          Default: c402cc3e-b531-11e1-9163-406186ea4fc5
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
    echo "${name} must be a positive integer, got '${value}'" >&2
    exit 1
  fi
}

api_get() {
  local path="$1"
  curl -fsS \
    -H "Authorization: Bearer ${SESSION_TOKEN}" \
    "${BASE_URL}${path}"
}

api_post_json() {
  local path="$1"
  local body="$2"
  curl -fsS \
    -H "Authorization: Bearer ${SESSION_TOKEN}" \
    -H 'Content-Type: application/json' \
    -X POST \
    -d "${body}" \
    "${BASE_URL}${path}"
}

api_post() {
  local path="$1"
  curl -fsS \
    -H "Authorization: Bearer ${SESSION_TOKEN}" \
    -X POST \
    "${BASE_URL}${path}"
}

api_download_file() {
  local path="$1"
  local output_file="$2"
  local accept="${3:-application/octet-stream}"
  curl -fsS \
    -H "Authorization: Bearer ${SESSION_TOKEN}" \
    -H "Accept: ${accept}" \
    -o "${output_file}" \
    "${BASE_URL}${path}"
}

select_scan_config_id() {
  jq -er '
    .data
    | (
        map(select((.name // "" | ascii_downcase) | contains("host discovery")))[0]
        // map(select((.name // "" | ascii_downcase) | contains("discovery")))[0]
      )
    | .id
  '
}

select_scanner_id() {
  jq -er '
    .data
    | (
        map(select((.type == "OSP") or (.type == "OpenVAS") or ((.name // "" | ascii_downcase) | contains("openvas"))))[0]
        // .[0]
      )
    | .id
  '
}

select_port_list_id() {
  jq -er '
    .data
    | (
        map(select((.name // "" | ascii_downcase) | contains("all iana assigned tcp")))[0]
        // map(select((.name // "" | ascii_downcase) | contains("all tcp")))[0]
        // .[0]
      )
    | .id
  '
}

select_resource_name() {
  local id="$1"
  jq -r --arg id "${id}" '.data[] | select(.id == $id) | .name // ""'
}

create_session() {
  curl -fsS \
    -u "${USERNAME}:${PASSWORD}" \
    -H 'Accept: application/json' \
    -X POST \
    "${BASE_URL}/api/v1/session"
}

delete_session() {
  if [[ -n "${SESSION_TOKEN:-}" ]]; then
    curl -fsS \
      -H "Authorization: Bearer ${SESSION_TOKEN}" \
      -X DELETE \
      "${BASE_URL}/api/v1/session" >/dev/null || true
  fi
}

cleanup() {
  rm -rf "${RESULTS_TMP_DIR:-}"
  delete_session
}

wait_for_task_done() {
  local task_id="$1"
  local deadline=$(( $(date +%s) + SCAN_TIMEOUT_SECS ))
  local task_json
  local status
  local progress

  while (( $(date +%s) < deadline )); do
    task_json="$(api_get "/api/v1/tasks/${task_id}")"
    status="$(printf '%s' "${task_json}" | jq -r '.status')"
    progress="$(printf '%s' "${task_json}" | jq -r '.progress // "unknown"')"
    echo "task ${task_id}: status=${status} progress=${progress}" >&2

    case "${status}" in
      Done)
        printf '%s' "${task_json}"
        return 0
        ;;
      Error|Stopped|Interrupted|Container|Delete\ Requested|Ultimate\ Delete\ Requested)
        echo "task reached non-success terminal status: ${status}" >&2
        printf '%s\n' "${task_json}" >&2
        return 1
        ;;
    esac

    sleep "${SCAN_POLL_INTERVAL_SECS}"
  done

  echo "task ${task_id} did not finish within ${SCAN_TIMEOUT_SECS}s" >&2
  return 1
}

fetch_all_report_results() {
  local report_id="$1"
  local output_file="$2"
  local per_page=1000
  local page=1
  local total_pages=1
  local page_file

  RESULTS_TMP_DIR="$(mktemp -d)"

  while (( page <= total_pages )); do
    page_file="$(printf '%s/results-page-%05d.json' "${RESULTS_TMP_DIR}" "${page}")"
    api_get "/api/v1/reports/${report_id}/results?page=${page}&perPage=${per_page}" > "${page_file}"

    if (( page == 1 )); then
      total_pages="$(jq -r '.pagination.totalPages // 1' "${page_file}")"
      if [[ ! "${total_pages}" =~ ^[0-9]+$ ]] || (( total_pages < 1 )); then
        total_pages=1
      fi
    fi

    page=$((page + 1))
  done

  jq -s '
    {
      data: (map(.data // []) | add // []),
      pagination: {
        page: 1,
        perPage: (.[0].pagination.perPage // 1000),
        total: (.[0].pagination.total // (map((.data // []) | length) | add // 0)),
        totalPages: (.[0].pagination.totalPages // length)
      }
    }
  ' "${RESULTS_TMP_DIR}"/results-page-*.json > "${output_file}"

  rm -rf "${RESULTS_TMP_DIR}"
  RESULTS_TMP_DIR=""
}

wait_for_export_job() {
  local job_id="$1"
  local deadline=$(( $(date +%s) + EXPORT_TIMEOUT_SECS ))
  local job_json
  local status
  local progress

  while (( $(date +%s) < deadline )); do
    job_json="$(api_get "/api/v1/jobs/${job_id}")"
    status="$(printf '%s' "${job_json}" | jq -r '.status')"
    progress="$(printf '%s' "${job_json}" | jq -r '.progress.percent // "unknown"')"
    echo "export job ${job_id}: status=${status} progress=${progress}" >&2

    case "${status}" in
      succeeded)
        printf '%s' "${job_json}"
        return 0
        ;;
      failed|cancelled|expired)
        echo "export job reached non-success terminal status: ${status}" >&2
        printf '%s\n' "${job_json}" >&2
        return 1
        ;;
    esac

    sleep "${EXPORT_POLL_INTERVAL_SECS}"
  done

  echo "export job ${job_id} did not finish within ${EXPORT_TIMEOUT_SECS}s" >&2
  return 1
}

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

require_command curl
require_command date
require_command jq
require_command mktemp

TARGET_HOST="$1"
BASE_URL="${GVM_GATEWAY_BASE_URL:-http://127.0.0.1:8080}"
USERNAME="${GVM_GATEWAY_USERNAME:-admin}"
PASSWORD="${GVM_GATEWAY_PASSWORD:-admin}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET_NAME="${GVM_SCAN_TARGET_NAME:-scan-target-${TIMESTAMP}}"
TASK_NAME="${GVM_SCAN_TASK_NAME:-scan-task-${TIMESTAMP}}"
OUTPUT_DIR="${GVM_SCAN_OUTPUT_DIR:-scan-output-${TIMESTAMP}}"
SCAN_POLL_INTERVAL_SECS="${GVM_SCAN_POLL_INTERVAL_SECS:-15}"
SCAN_TIMEOUT_SECS="${GVM_SCAN_TIMEOUT_SECS:-7200}"
EXPORT_POLL_INTERVAL_SECS="${GVM_REPORT_EXPORT_POLL_SECS:-5}"
EXPORT_TIMEOUT_SECS="${GVM_REPORT_EXPORT_TIMEOUT_SECS:-900}"
PDF_REPORT_FORMAT_ID="${GVM_PDF_REPORT_FORMAT_ID:-c402cc3e-b531-11e1-9163-406186ea4fc5}"
SESSION_TOKEN=""
RESULTS_TMP_DIR=""

require_positive_integer GVM_SCAN_POLL_INTERVAL_SECS "${SCAN_POLL_INTERVAL_SECS}"
require_positive_integer GVM_SCAN_TIMEOUT_SECS "${SCAN_TIMEOUT_SECS}"
require_positive_integer GVM_REPORT_EXPORT_POLL_SECS "${EXPORT_POLL_INTERVAL_SECS}"
require_positive_integer GVM_REPORT_EXPORT_TIMEOUT_SECS "${EXPORT_TIMEOUT_SECS}"

mkdir -p "${OUTPUT_DIR}"
trap cleanup EXIT

SESSION_JSON="$(create_session)"
SESSION_TOKEN="$(printf '%s' "${SESSION_JSON}" | jq -er '.sessionToken')"
GMP_VERSION="$(printf '%s' "${SESSION_JSON}" | jq -r '.gmpVersion')"

SCAN_CONFIGS_JSON="$(api_get '/api/v1/scan-configs?perPage=1000')"
SCANNERS_JSON="$(api_get '/api/v1/scanners?perPage=1000')"
PORT_LISTS_JSON="$(api_get '/api/v1/port-lists?perPage=1000')"

SCAN_CONFIG_ID="${GVM_SCAN_CONFIG_ID:-$(printf '%s' "${SCAN_CONFIGS_JSON}" | select_scan_config_id)}"
SCANNER_ID="${GVM_SCANNER_ID:-$(printf '%s' "${SCANNERS_JSON}" | select_scanner_id)}"
PORT_LIST_ID="${GVM_PORT_LIST_ID:-$(printf '%s' "${PORT_LISTS_JSON}" | select_port_list_id)}"

SCAN_CONFIG_NAME="$(printf '%s' "${SCAN_CONFIGS_JSON}" | select_resource_name "${SCAN_CONFIG_ID}")"
SCANNER_NAME="$(printf '%s' "${SCANNERS_JSON}" | select_resource_name "${SCANNER_ID}")"
PORT_LIST_NAME="$(printf '%s' "${PORT_LISTS_JSON}" | select_resource_name "${PORT_LIST_ID}")"

TARGET_BODY="$(
  jq -n \
    --arg name "${TARGET_NAME}" \
    --arg host "${TARGET_HOST}" \
    --arg portListId "${PORT_LIST_ID}" \
    '{
      name: $name,
      hosts: [$host],
      aliveTest: "Consider Alive",
      portListId: $portListId
    }'
)"
TARGET_JSON="$(api_post_json '/api/v1/targets' "${TARGET_BODY}")"
TARGET_ID="$(printf '%s' "${TARGET_JSON}" | jq -er '.id')"

TASK_BODY="$(
  jq -n \
    --arg name "${TASK_NAME}" \
    --arg targetId "${TARGET_ID}" \
    --arg scanConfigId "${SCAN_CONFIG_ID}" \
    --arg scannerId "${SCANNER_ID}" \
    '{
      name: $name,
      targetId: $targetId,
      scanConfigId: $scanConfigId,
      scannerId: $scannerId
    }'
)"
TASK_JSON="$(api_post_json '/api/v1/tasks' "${TASK_BODY}")"
TASK_ID="$(printf '%s' "${TASK_JSON}" | jq -er '.id')"

START_JSON="$(api_post "/api/v1/tasks/${TASK_ID}/start")"
REPORT_ID="$(printf '%s' "${START_JSON}" | jq -er '.reportId')"

cat <<EOF
started scan
  gateway:      ${BASE_URL}
  gmp version:  ${GMP_VERSION}
  target host:  ${TARGET_HOST}
  target:       ${TARGET_NAME} (${TARGET_ID})
  task:         ${TASK_NAME} (${TASK_ID})
  report:       ${REPORT_ID}
  scan config:  ${SCAN_CONFIG_NAME:-${SCAN_CONFIG_ID}} (${SCAN_CONFIG_ID})
  scanner:      ${SCANNER_NAME:-${SCANNER_ID}} (${SCANNER_ID})
  port list:    ${PORT_LIST_NAME:-${PORT_LIST_ID}} (${PORT_LIST_ID})
  output dir:   ${OUTPUT_DIR}
EOF

TASK_DONE_JSON="$(wait_for_task_done "${TASK_ID}")"

RESULTS_FILE="${OUTPUT_DIR}/results-${REPORT_ID}.json"
fetch_all_report_results "${REPORT_ID}" "${RESULTS_FILE}"

EXPORT_BODY="$(
  jq -n \
    --arg reportFormatId "${PDF_REPORT_FORMAT_ID}" \
    '{reportFormatId: $reportFormatId}'
)"
EXPORT_JSON="$(api_post_json "/api/v1/reports/${REPORT_ID}/exports" "${EXPORT_BODY}")"
EXPORT_JOB_ID="$(printf '%s' "${EXPORT_JSON}" | jq -er '.id')"
EXPORT_DONE_JSON="$(wait_for_export_job "${EXPORT_JOB_ID}")"

PDF_FILE="${OUTPUT_DIR}/report-${REPORT_ID}.pdf"
api_download_file "/api/v1/jobs/${EXPORT_JOB_ID}/result" "${PDF_FILE}" "application/pdf"

cat <<EOF
scan complete
  task status:  $(printf '%s' "${TASK_DONE_JSON}" | jq -r '.status')
  report:       ${REPORT_ID}
  results json: ${RESULTS_FILE}
  result count: $(jq -r '.pagination.total' "${RESULTS_FILE}")
  pdf export:   ${PDF_FILE}
  export job:   ${EXPORT_JOB_ID} ($(printf '%s' "${EXPORT_DONE_JSON}" | jq -r '.status'))
EOF
