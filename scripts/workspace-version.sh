#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"

awk '
  $0 == "[workspace.package]" { in_block = 1; next }
  /^\[/ && $0 != "[workspace.package]" { in_block = 0 }
  in_block && $1 == "version" {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' "${ROOT_DIR}/Cargo.toml"
