#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
PACKAGER="${2:?packager is required}"
RELEASE="${3:-1}"

if [[ "${VERSION}" == *-* ]]; then
  BASE="${VERSION%%-*}"
  PRERELEASE="${VERSION#${BASE}-}"
  LABEL="${PRERELEASE%%.*}"
  if [[ "${PRERELEASE}" == *.* ]]; then
    REST="${PRERELEASE#${LABEL}}"
  else
    REST=""
  fi

  case "${LABEL}" in
    alpha) SUFFIX="alpha" ;;
    beta) SUFFIX="beta" ;;
    release-candidate) SUFFIX="rc" ;;
    *) SUFFIX="$(printf '%s' "${LABEL}" | tr -cs '[:alnum:]' '.')" ;;
  esac

  case "${PACKAGER}" in
    deb) PACKAGE_VERSION="${BASE}~${SUFFIX}${REST}" ;;
    archlinux) PACKAGE_VERSION="${BASE}${SUFFIX}${REST}" ;;
    *)
      echo "unsupported packager: ${PACKAGER}" >&2
      exit 1
      ;;
  esac
else
  PACKAGE_VERSION="${VERSION}"
fi

printf 'PACKAGE_VERSION=%s\nPACKAGE_RELEASE=%s\n' "${PACKAGE_VERSION}" "${RELEASE}"
