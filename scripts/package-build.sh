#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: package-build.sh --packager <deb|archlinux> --version <version> [--release <n>] [--output-dir <dir>]
EOF
}

PACKAGER=""
VERSION=""
RELEASE="1"
OUTPUT_DIR="dist/packages"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --packager)
      PACKAGER="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --release)
      RELEASE="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
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

if [[ -z "${PACKAGER}" || -z "${VERSION}" ]]; then
  usage >&2
  exit 1
fi

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "${ROOT_DIR}"

if [[ ! -x "${ROOT_DIR}/.bin/nfpm" ]]; then
  echo "nfpm is not installed; run scripts/install-nfpm.sh first" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/target/release/gvm-gateway" ]]; then
  echo "release binary missing: target/release/gvm-gateway" >&2
  exit 1
fi

case "${PACKAGER}" in
  deb)
    ARCHITECTURE="amd64"
    ;;
  archlinux)
    ARCHITECTURE="x86_64"
    ;;
  *)
    echo "unsupported packager: ${PACKAGER}" >&2
    exit 1
    ;;
esac

eval "$(${ROOT_DIR}/scripts/package-version.sh "${VERSION}" "${PACKAGER}" "${RELEASE}")"

rm -rf dist/package-root dist/package-work
rm -rf "${OUTPUT_DIR}"
mkdir -p dist/package-root/usr/bin \
  dist/package-root/etc/gvm-gateway \
  dist/package-root/usr/share/doc/gvm-gateway \
  dist/package-root/usr/share/licenses/gvm-gateway \
  dist/package-work \
  "${OUTPUT_DIR}"

install -m 0755 target/release/gvm-gateway dist/package-root/usr/bin/gvm-gateway
install -m 0644 packaging/gvm-gateway.toml dist/package-root/etc/gvm-gateway/gvm-gateway.toml

cat > dist/package-root/usr/share/doc/gvm-gateway/BUILDINFO <<EOF
package_name=gvm-gateway
package_format=${PACKAGER}
package_version=${PACKAGE_VERSION}
package_release=${PACKAGE_RELEASE}
source_version=${VERSION}
source_commit=$(git rev-parse HEAD)
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

ARCHITECTURE="${ARCHITECTURE}" PACKAGE_VERSION="${PACKAGE_VERSION}" PACKAGE_RELEASE="${PACKAGE_RELEASE}" perl -0pe 's/__ARCH__/$ENV{ARCHITECTURE}/g; s/__VERSION__/$ENV{PACKAGE_VERSION}/g; s/__RELEASE__/$ENV{PACKAGE_RELEASE}/g' \
  packaging/nfpm.yaml.tpl > dist/package-work/nfpm.yaml

"${ROOT_DIR}/.bin/nfpm" package \
  --config dist/package-work/nfpm.yaml \
  --packager "${PACKAGER}" \
  --target "${OUTPUT_DIR}"

for artifact in "${OUTPUT_DIR}"/*; do
  [[ -f "${artifact}" ]] || continue
  [[ "${artifact}" == *.sha256 ]] && continue
  sha256sum "${artifact}" > "${artifact}.sha256"
done
