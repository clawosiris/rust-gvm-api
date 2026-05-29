#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run-performance-tests.sh [-- <cargo-test-args...>]

Waits for the compose-backed gateway stack to expose the same seeded REST
resources required by the E2E lane, then runs the ignored performance tests
single-threaded and writes JSON reports to dist/performance by default.

Environment:
  GVM_GATEWAY_PERF_OUTPUT_DIR        Default: dist/performance
  GVM_GATEWAY_PERF_ITERATIONS        Default: 5
  GVM_GATEWAY_PERF_WARMUP_ITERATIONS Default: 1
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi

export GVM_GATEWAY_PERF_OUTPUT_DIR="${GVM_GATEWAY_PERF_OUTPUT_DIR:-dist/performance}"
mkdir -p "${GVM_GATEWAY_PERF_OUTPUT_DIR}"

./scripts/run-e2e-tests.sh --wait-only

if [[ $# -gt 0 ]]; then
  exec cargo test -p gvm-gateway-performance --test rest_smoke_performance -- --ignored --nocapture --test-threads=1 "$@"
fi

exec cargo test -p gvm-gateway-performance --test rest_smoke_performance -- --ignored --nocapture --test-threads=1
