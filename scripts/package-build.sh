#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: package-build.sh --packager <deb|archlinux> --version <version> [--release <n>] [--architecture <arch>] [--output-dir <dir>]
EOF
}

PACKAGER=""
VERSION=""
RELEASE="1"
ARCHITECTURE=""
OUTPUT_DIR="dist/packages"
NFPM_VERSION="${NFPM_VERSION:-2.43.2}"
NFPM_IMAGE_REPOSITORY="${NFPM_IMAGE_REPOSITORY:-ghcr.io/goreleaser/nfpm}"
NFPM_IMAGE_DIGEST="${NFPM_IMAGE_DIGEST:-sha256:40fb2e649c8f7ab7b7465a825150ae64a6d9c56b45e44a4912541a36fd06014c}"
NFPM_IMAGE="${NFPM_IMAGE:-${NFPM_IMAGE_REPOSITORY}@${NFPM_IMAGE_DIGEST}}"

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
    --architecture)
      ARCHITECTURE="$2"
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

case "${OUTPUT_DIR}" in
  /*)
    OUTPUT_DIR_ABS="$(realpath -m "${OUTPUT_DIR}")"
    ;;
  *)
    OUTPUT_DIR_ABS="$(realpath -m "${ROOT_DIR}/${OUTPUT_DIR}")"
    ;;
esac

case "${OUTPUT_DIR_ABS}" in
  "${ROOT_DIR}/dist/"*)
    ;;
  *)
    echo "package output directory must be under dist/: ${OUTPUT_DIR}" >&2
    exit 1
    ;;
esac

if [[ -z "${OUTPUT_DIR}" || "${OUTPUT_DIR_ABS}" == "/" || "${OUTPUT_DIR_ABS}" == "${ROOT_DIR}" || "${OUTPUT_DIR_ABS}" == "${ROOT_DIR}/dist" ]]; then
  echo "unsafe package output directory: ${OUTPUT_DIR:-<empty>}" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run the verified nfpm image" >&2
  exit 1
fi

NFPM_IMAGE="${NFPM_IMAGE}" "${ROOT_DIR}/scripts/verify-nfpm-image.sh" "${NFPM_VERSION}"

if [[ ! -x "${ROOT_DIR}/target/release/gvm-gateway" ]]; then
  echo "release binary missing: target/release/gvm-gateway" >&2
  exit 1
fi

if [[ -z "${ARCHITECTURE}" ]]; then
  HOST_ARCH="$(uname -m)"
  case "${HOST_ARCH}" in
    x86_64|amd64)
      case "${PACKAGER}" in
        deb) ARCHITECTURE="amd64" ;;
        archlinux) ARCHITECTURE="x86_64" ;;
      esac
      ;;
    aarch64|arm64)
      case "${PACKAGER}" in
        deb) ARCHITECTURE="arm64" ;;
      esac
      ;;
    *)
      echo "unsupported host architecture: ${HOST_ARCH}; pass --architecture explicitly" >&2
      exit 1
      ;;
  esac
fi

case "${PACKAGER}:${ARCHITECTURE}" in
  deb:amd64|deb:arm64|archlinux:x86_64)
    ;;
  *)
    echo "unsupported package architecture for ${PACKAGER}: ${ARCHITECTURE}" >&2
    exit 1
    ;;
esac

eval "$(${ROOT_DIR}/scripts/package-version.sh "${VERSION}" "${PACKAGER}" "${RELEASE}")"

rm -rf dist/package-root dist/package-work
rm -rf "${OUTPUT_DIR_ABS}"
mkdir -p dist/package-root/usr/bin \
  dist/package-root/etc/gvm-gateway \
  dist/package-root/usr/share/doc/gvm-gateway \
  dist/package-root/usr/share/licenses/gvm-gateway \
  dist/package-work \
  "${OUTPUT_DIR_ABS}"

install -m 0755 target/release/gvm-gateway dist/package-root/usr/bin/gvm-gateway
install -m 0644 packaging/gvm-gateway.toml dist/package-root/etc/gvm-gateway/gvm-gateway.toml
install -m 0644 README.md dist/package-root/usr/share/doc/gvm-gateway/README.md
install -m 0644 LICENSE dist/package-root/usr/share/licenses/gvm-gateway/LICENSE

cat > dist/package-root/usr/share/doc/gvm-gateway/BUILDINFO <<EOF
package_name=gvm-gateway
package_format=${PACKAGER}
package_architecture=${ARCHITECTURE}
package_version=${PACKAGE_VERSION}
package_release=${PACKAGE_RELEASE}
source_version=${VERSION}
source_commit=$(git rev-parse HEAD)
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

ARCHITECTURE="${ARCHITECTURE}" PACKAGE_VERSION="${PACKAGE_VERSION}" PACKAGE_RELEASE="${PACKAGE_RELEASE}" perl -0pe 's/__ARCH__/$ENV{ARCHITECTURE}/g; s/__VERSION__/$ENV{PACKAGE_VERSION}/g; s/__RELEASE__/$ENV{PACKAGE_RELEASE}/g' \
  packaging/nfpm.yaml.tpl > dist/package-work/nfpm.yaml

NFPM_DOCKER_ARGS=(
  --rm
  --user "$(id -u):$(id -g)"
  --volume "${ROOT_DIR}/dist:${ROOT_DIR}/dist"
  --workdir "${ROOT_DIR}"
)

docker run "${NFPM_DOCKER_ARGS[@]}" \
  "${NFPM_IMAGE}" package \
  --config dist/package-work/nfpm.yaml \
  --packager "${PACKAGER}" \
  --target "${OUTPUT_DIR_ABS}"

for artifact in "${OUTPUT_DIR_ABS}"/*; do
  [[ -f "${artifact}" ]] || continue
  [[ "${artifact}" == *.sha256 ]] && continue
  sha256sum "${artifact}" > "${artifact}.sha256"
done
