#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/oci-build.sh [--tag <image>] [--file <containerfile>]
EOF
}

TAG="local/gvm-gateway:dev"
CONTAINERFILE="Containerfile"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="$2"
      shift 2
      ;;
    --file)
      CONTAINERFILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

ROOT_DIR="$(git rev-parse --show-toplevel)"
VERSION="$("${ROOT_DIR}/scripts/workspace-version.sh")"
REVISION="$(git -C "${ROOT_DIR}" rev-parse HEAD)"

if command -v docker >/dev/null 2>&1; then
  if docker buildx version >/dev/null 2>&1; then
    exec docker buildx build \
      --load \
      --build-arg "GVM_GATEWAY_VERSION=${VERSION}" \
      --build-arg "GVM_GATEWAY_VCS_REF=${REVISION}" \
      -t "${TAG}" \
      -f "${ROOT_DIR}/${CONTAINERFILE}" \
      "${ROOT_DIR}"
  fi

  exec docker build \
    --build-arg "GVM_GATEWAY_VERSION=${VERSION}" \
    --build-arg "GVM_GATEWAY_VCS_REF=${REVISION}" \
    -t "${TAG}" \
    -f "${ROOT_DIR}/${CONTAINERFILE}" \
    "${ROOT_DIR}"
fi

if command -v podman >/dev/null 2>&1; then
  exec podman build \
    --format oci \
    --build-arg "GVM_GATEWAY_VERSION=${VERSION}" \
    --build-arg "GVM_GATEWAY_VCS_REF=${REVISION}" \
    -t "${TAG}" \
    -f "${ROOT_DIR}/${CONTAINERFILE}" \
    "${ROOT_DIR}"
fi

echo "No supported container runtime found. Install Docker or Podman." >&2
exit 1
