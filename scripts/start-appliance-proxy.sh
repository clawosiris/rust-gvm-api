#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/start-appliance-proxy.sh <ip-address> <ssh-user>

Starts a local gvm-gateway instance against a remote Greenbone appliance gvmd
Unix socket reached through SSH. SSH key authentication must already be
configured for the requested user and appliance.

Environment:
  GVM_GATEWAY_BIND               Default: 127.0.0.1:18080
  GVM_APPLIANCE_GVMD_SOCKET      Default: /usr/share/gvm/gsad/web/gvmd.sock
  GVM_GATEWAY_LOCAL_GVMD_SOCKET  Default: /tmp/rust-gvm-api-gvmd-<user>-<ip>.sock

Accepted input characters:
  <ssh-user>                    [A-Za-z_][A-Za-z0-9_.-]*
  <ip-address>                  [A-Za-z0-9][A-Za-z0-9.-]*
  socket paths                  absolute paths containing only /A-Za-z0-9._-
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

invalid_value() {
  local name="$1"
  local expected="$2"
  local value="$3"
  echo "invalid ${name}: expected ${expected}, got ${value@Q}" >&2
  exit 1
}

validate_ssh_user() {
  local value="$1"
  if [[ ! "${value}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]]; then
    invalid_value "ssh user" "[A-Za-z_][A-Za-z0-9_.-]*" "${value}"
  fi
}

validate_appliance_host() {
  local value="$1"
  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
    invalid_value "appliance host" "[A-Za-z0-9][A-Za-z0-9.-]*" "${value}"
  fi
}

validate_socket_path() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    invalid_value "${name}" "an absolute path containing only /A-Za-z0-9._-" "${value}"
  fi
}

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 1
fi

APPLIANCE_IP="$1"
SSH_USER="$2"
ROOT_DIR="$(git rev-parse --show-toplevel)"
BIND_ADDR="${GVM_GATEWAY_BIND:-127.0.0.1:18080}"
REMOTE_SOCKET="${GVM_APPLIANCE_GVMD_SOCKET:-/usr/share/gvm/gsad/web/gvmd.sock}"
SAFE_IP="${APPLIANCE_IP//[^A-Za-z0-9_.-]/_}"
SAFE_USER="${SSH_USER//[^A-Za-z0-9_.-]/_}"
LOCAL_SOCKET="${GVM_GATEWAY_LOCAL_GVMD_SOCKET:-/tmp/rust-gvm-api-gvmd-${SAFE_USER}-${SAFE_IP}.sock}"

validate_appliance_host "${APPLIANCE_IP}"
validate_ssh_user "${SSH_USER}"
validate_socket_path "GVM_APPLIANCE_GVMD_SOCKET" "${REMOTE_SOCKET}"
validate_socket_path "GVM_GATEWAY_LOCAL_GVMD_SOCKET" "${LOCAL_SOCKET}"

BRIDGE_PID=""
GATEWAY_PID=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" >/dev/null 2>&1; then
    kill "${GATEWAY_PID}" >/dev/null 2>&1 || true
    wait "${GATEWAY_PID}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${BRIDGE_PID}" ]] && kill -0 "${BRIDGE_PID}" >/dev/null 2>&1; then
    kill "${BRIDGE_PID}" >/dev/null 2>&1 || true
    wait "${BRIDGE_PID}" >/dev/null 2>&1 || true
  fi

  rm -f "${LOCAL_SOCKET}"
  exit "${status}"
}

trap cleanup EXIT INT TERM

require_command cargo
require_command git
require_command socat
require_command ssh

cd "${ROOT_DIR}"

rm -f "${LOCAL_SOCKET}"

socat -d -d \
  "UNIX-LISTEN:${LOCAL_SOCKET},fork,unlink-early,mode=0600" \
  "EXEC:ssh -F /dev/null -o BatchMode=yes ${SSH_USER}@${APPLIANCE_IP} socat - UNIX-CONNECT\\:${REMOTE_SOCKET}" &
BRIDGE_PID=$!

for _ in {1..50}; do
  if [[ -S "${LOCAL_SOCKET}" ]]; then
    break
  fi

  if ! kill -0 "${BRIDGE_PID}" >/dev/null 2>&1; then
    echo "failed to start gvmd SSH socket bridge" >&2
    wait "${BRIDGE_PID}"
  fi

  sleep 0.1
done

if [[ ! -S "${LOCAL_SOCKET}" ]]; then
  echo "timed out waiting for local gvmd socket bridge at ${LOCAL_SOCKET}" >&2
  exit 1
fi

cat <<EOF
Starting gvm-gateway
  appliance:     ${SSH_USER}@${APPLIANCE_IP}
  remote socket: ${REMOTE_SOCKET}
  local socket:  ${LOCAL_SOCKET}
  base URL:      http://${BIND_ADDR}

Version endpoint:
  curl -fsS http://${BIND_ADDR}/api/v1/version
EOF

GVM_GATEWAY_GVMD_ENDPOINT="unix://${LOCAL_SOCKET}" \
GVM_GATEWAY_TRANSPORT_SECURITY_MODE=disabled \
  cargo run -p gvm-gateway -- --bind "${BIND_ADDR}" &
GATEWAY_PID=$!

wait "${GATEWAY_PID}"
