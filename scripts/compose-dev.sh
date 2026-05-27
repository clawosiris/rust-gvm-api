#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
COMPOSE_FILE="${ROOT_DIR}/compose.yaml"

if [[ $# -eq 0 ]]; then
  echo "Usage: scripts/compose-dev.sh <compose-args...>" >&2
  exit 1
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  exec docker compose -f "${COMPOSE_FILE}" "$@"
fi

if command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
  exec podman compose -f "${COMPOSE_FILE}" "$@"
fi

if command -v podman-compose >/dev/null 2>&1; then
  exec podman-compose -f "${COMPOSE_FILE}" "$@"
fi

echo "No supported compose runtime found. Install Docker Compose or Podman Compose." >&2
exit 1
