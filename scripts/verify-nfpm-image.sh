#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-2.43.2}"
expected_digest() {
  case "$1" in
    2.43.2)
      echo "sha256:40fb2e649c8f7ab7b7465a825150ae64a6d9c56b45e44a4912541a36fd06014c"
      ;;
    *)
      echo "no pinned nfpm image digest for version $1" >&2
      exit 1
      ;;
  esac
}

IMAGE="${NFPM_IMAGE:-ghcr.io/goreleaser/nfpm@$(expected_digest "${VERSION}")}"
ISSUER="https://token.actions.githubusercontent.com"
IDENTITY="https://github.com/goreleaser/nfpm/.github/workflows/release.yml@refs/tags/v${VERSION}"

if [[ "${IMAGE}" != *@sha256:* ]]; then
  echo "nfpm image must be pinned by digest: ${IMAGE}" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to verify ${IMAGE}" >&2
  exit 1
fi

cosign verify \
  --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  "${IMAGE}" >/dev/null
