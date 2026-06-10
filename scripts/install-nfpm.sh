#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-2.43.2}"
ROOT_DIR="$(git rev-parse --show-toplevel)"
BIN_DIR="${ROOT_DIR}/.bin"

case "$(uname -m)" in
  x86_64|amd64)
    NFPM_ARCH="x86_64"
    ;;
  aarch64|arm64)
    NFPM_ARCH="arm64"
    ;;
  *)
    echo "unsupported host architecture for nfpm install: $(uname -m)" >&2
    exit 1
    ;;
esac

ARCHIVE="nfpm_${VERSION}_Linux_${NFPM_ARCH}.tar.gz"
URL="https://github.com/goreleaser/nfpm/releases/download/v${VERSION}/${ARCHIVE}"

mkdir -p "${BIN_DIR}"

if [[ -x "${BIN_DIR}/nfpm" ]]; then
  INSTALLED_VERSION="$(${BIN_DIR}/nfpm --version | awk '{print $3}')"
  if [[ "${INSTALLED_VERSION}" == "${VERSION}" ]]; then
    exit 0
  fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

curl -fsSL "${URL}" -o "${TMP_DIR}/${ARCHIVE}"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"
install -m 0755 "${TMP_DIR}/nfpm" "${BIN_DIR}/nfpm"
