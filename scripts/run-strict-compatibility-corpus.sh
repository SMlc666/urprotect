#!/usr/bin/env bash
set -u -o pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --runtime glibc [--skip-existing]\n' "$0" >&2
}

tier=''
runtime=''
skip_existing=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --runtime) [[ $# -ge 2 ]] || { usage; exit 2; }; runtime="$2"; shift 2 ;;
    --skip-existing) skip_existing=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid strict corpus tier: $tier" >&2; exit 2 ;; esac
case "$runtime" in glibc) ;; *) echo "strict compatibility corpus currently requires glibc" >&2; exit 2 ;; esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${PROTECTED_IMAGE_ARTIFACT_ROOT:-${repo_root}/.artifacts/protected-image/${tier}/${runtime}}"
mkdir -p "$artifact_root"

mapfile -t rows < <(python3 - "$repo_root/fixtures/evaluator/compatibility-corpus.json" <<'PY'
import json
import pathlib
import sys
corpus = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for row in corpus['rows']:
    if row.get('required') and row.get('applicable'):
        print(f"{row['unitId']}\t{row['sourceProvenance']}")
PY
)

status=0
completed=0
failed=0
for row in "${rows[@]}"; do
  IFS=$'\t' read -r unit source <<<"$row"
  root="$artifact_root/$unit"
  if (( skip_existing )) && [[ -f "$root/behavioral-oracle.json" && -f "$root/SHA256SUMS" ]]; then
    if python3 "$repo_root/scripts/check-rehydration-evidence.py" "$root" --tier "$tier" --runtime "$runtime" --unit "$unit" >/dev/null 2>&1; then
      completed=$((completed + 1))
      continue
    fi
  fi
  echo "[strict-corpus] $unit"
  if PATH="${DOTNET_ROOT:-/root/.dotnet}:$PATH" \
      "$repo_root/scripts/run-rehydration-e2e.sh" \
      --tier "$tier" --runtime "$runtime" --unit "$unit" --source "$repo_root/$source"; then
    completed=$((completed + 1))
  else
    failed=$((failed + 1))
    status=1
  fi
done

python3 - "$artifact_root/strict-corpus-summary.json" "$tier" "$runtime" "$completed" "$failed" "${#rows[@]}" <<'PY'
import json
import pathlib
import sys
path, tier, runtime, completed, failed, total = sys.argv[1:]
document = {
    'schemaVersion': 1,
    'kind': 'strict-compatibility-corpus-run',
    'tier': tier,
    'runtime': runtime,
    'totalRows': int(total),
    'completedRows': int(completed),
    'failedRows': int(failed),
    'status': 'passed' if int(failed) == 0 else 'failed',
}
pathlib.Path(path).write_text(json.dumps(document, sort_keys=True, indent=2) + '\n', encoding='utf-8')
PY

if (( failed != 0 )); then
  echo "strict compatibility corpus failed: ${failed}/${#rows[@]} rows" >&2
  exit "$status"
fi
echo "PASS strict compatibility corpus: ${completed}/${#rows[@]} rows"
