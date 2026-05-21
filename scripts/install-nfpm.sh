#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-2.43.2}"
ROOT_DIR="$(git rev-parse --show-toplevel)"
BIN_DIR="${ROOT_DIR}/.bin"
ARCHIVE="nfpm_${VERSION}_Linux_x86_64.tar.gz"
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
