#!/usr/bin/env bash
set -euo pipefail

output_file="${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"
summary_file="${GITHUB_STEP_SUMMARY:-/dev/null}"
event_name="${GITHUB_EVENT_NAME:-}"
target_branch="${TARGET_BRANCH:-${GITHUB_REF_NAME:-}}"

docs_only=false
changed_count=0
code_count=0
range_label=""

is_docs_only_path() {
  case "$1" in
    docs/*|LICENSE|.github/ISSUE_TEMPLATE/*)
      return 0
      ;;
    */*)
      return 1
      ;;
    *.md)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_commit() {
  local sha="$1"
  if [[ -z "$sha" || "$sha" =~ ^0+$ ]]; then
    return 1
  fi
  git cat-file -e "${sha}^{commit}" 2>/dev/null
}

collect_changed_files() {
  local base=""
  local head=""

  case "$event_name" in
    pull_request|pull_request_target)
      base="${BASE_SHA:-}"
      head="${HEAD_SHA:-}"
      ;;
    push)
      base="${BEFORE_SHA:-}"
      head="${AFTER_SHA:-${GITHUB_SHA:-}}"
      if [[ -z "$base" || "$base" =~ ^0+$ ]]; then
        require_commit "$head" || {
          echo "Unable to inspect pushed commit ${head}" >&2
          return 1
        }
        git diff-tree --no-commit-id --name-only -r "$head"
        return
      fi
      ;;
    *)
      return 2
      ;;
  esac

  require_commit "$base" || {
    echo "Unable to inspect base commit ${base}" >&2
    return 1
  }
  require_commit "$head" || {
    echo "Unable to inspect head commit ${head}" >&2
    return 1
  }
  git diff --name-only "$base" "$head"
}

case "$event_name" in
  pull_request|pull_request_target)
    range_label="${BASE_SHA:-}...${HEAD_SHA:-}"
    ;;
  push)
    if [[ -z "${BEFORE_SHA:-}" || "${BEFORE_SHA:-}" =~ ^0+$ ]]; then
      range_label="${AFTER_SHA:-${GITHUB_SHA:-}}"
    else
      range_label="${BEFORE_SHA:-}...${AFTER_SHA:-${GITHUB_SHA:-}}"
    fi
    ;;
  *)
    range_label="${event_name:-unknown-event}"
    ;;
esac

collect_status=0
changed_file_list="$(collect_changed_files)" || collect_status=$?

if [[ "$collect_status" -eq 2 ]]; then
  # Manual and scheduled runs are intentionally treated as code-affecting.
  changed_files=()
  code_count=1
elif [[ "$collect_status" -ne 0 ]]; then
  exit "$collect_status"
elif [[ -n "$changed_file_list" ]]; then
  mapfile -t changed_files <<< "$changed_file_list"
else
  changed_files=()
fi

changed_count="${#changed_files[@]}"

if [[ "$code_count" -eq 0 ]]; then
  for path in "${changed_files[@]}"; do
    if ! is_docs_only_path "$path"; then
      code_count=$((code_count + 1))
    fi
  done
fi

if [[ "$changed_count" -gt 0 && "$code_count" -eq 0 ]]; then
  docs_only=true
fi

{
  echo "target_branch=${target_branch}"
  echo "docs_only=${docs_only}"
  echo "ci_required=$([[ "$docs_only" == "true" ]] && echo false || echo true)"
  echo "e2e_required=$([[ "$docs_only" == "true" ]] && echo false || echo true)"
  echo "changed_count=${changed_count}"
  echo "code_count=${code_count}"
  echo "range=${range_label}"
} >> "$output_file"

{
  echo "### Change classification"
  echo
  echo "- Target branch: \`${target_branch:-unknown}\`"
  echo "- Compared range: \`${range_label:-unknown}\`"
  echo "- Changed files: ${changed_count}"
  echo "- Code-affecting files: ${code_count}"
  echo "- Docs-only: ${docs_only}"
} >> "$summary_file"
