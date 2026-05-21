#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: package-smoke.sh --packager <deb|archlinux> [--package-dir <dir>]
EOF
}

PACKAGER=""
PACKAGE_DIR="dist/packages"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --packager)
      PACKAGER="$2"
      shift 2
      ;;
    --package-dir)
      PACKAGE_DIR="$2"
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

if [[ -z "${PACKAGER}" ]]; then
  usage >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found; skipping package smoke test" >&2
  exit 0
fi

ROOT_DIR="$(git rev-parse --show-toplevel)"
PACKAGE_DIR="$(cd "${ROOT_DIR}/${PACKAGE_DIR}" && pwd)"

case "${PACKAGER}" in
  deb)
    docker run --rm -v "${PACKAGE_DIR}:/packages:ro" debian:trixie-slim sh -lc '
      set -e
      dpkg -i /packages/*.deb
      test -f /etc/gvm-gateway/gvm-gateway.toml
      /usr/bin/gvm-gateway --help >/tmp/gvm-gateway-help.txt
    '
    ;;
  archlinux)
    docker run --rm -v "${PACKAGE_DIR}:/packages:ro" archlinux:latest sh -lc '
      set -e
      sed -i "s/^SigLevel.*/SigLevel = Never/" /etc/pacman.conf
      pacman -Sy --noconfirm
      pacman -U --noconfirm /packages/*.pkg.tar.zst
      test -f /etc/gvm-gateway/gvm-gateway.toml
      /usr/bin/gvm-gateway --help >/tmp/gvm-gateway-help.txt
    '
    ;;
  *)
    echo "unsupported packager: ${PACKAGER}" >&2
    exit 1
    ;;
esac
