#!/usr/bin/env bash
set -u -o pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --runtime glibc [--skip-existing] [--shard-index N --shard-count N] [--workers 1..8]\n' "$0" >&2
}

tier=''
runtime=''
skip_existing=0
workers=1
shard_index=''
shard_count=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --runtime) [[ $# -ge 2 ]] || { usage; exit 2; }; runtime="$2"; shift 2 ;;
    --skip-existing) skip_existing=1; shift ;;
    --workers) [[ $# -ge 2 ]] || { usage; exit 2; }; workers="$2"; shift 2 ;;
    --shard-index) [[ $# -ge 2 ]] || { usage; exit 2; }; shard_index="$2"; shift 2 ;;
    --shard-count) [[ $# -ge 2 ]] || { usage; exit 2; }; shard_count="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid strict corpus tier: $tier" >&2; exit 2 ;; esac
case "$runtime" in glibc) ;; *) echo "strict compatibility corpus currently requires glibc" >&2; exit 2 ;; esac

if [[ -n "$shard_index" || -n "$shard_count" ]]; then
  [[ "$shard_index" =~ ^[0-9]+$ && "$shard_count" =~ ^[1-9][0-9]*$ ]] || { echo "both shard parameters must be nonnegative integers (count positive)" >&2; exit 2; }
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${PROTECTED_IMAGE_ARTIFACT_ROOT:-${repo_root}/.artifacts/protected-image/${tier}/${runtime}}"
mkdir -p "$artifact_root"

if [[ ! "$workers" =~ ^[1-8]$ ]]; then
  echo "workers must be between 1 and 8" >&2
  exit 2
fi
if (( workers > 1 )); then
  command=(python3 "$repo_root/scripts/run_strict_compatibility_corpus.py" --tier "$tier" --runtime "$runtime" --workers "$workers")
  if [[ -n "$shard_index" ]]; then
    command+=(--shard-index "$shard_index" --shard-count "$shard_count")
  fi
  if (( skip_existing )); then command+=(--skip-existing); fi
  exec "${command[@]}"
fi

if [[ -n "$shard_index" ]]; then
  mapfile -t rows < <(python3 "$repo_root/scripts/strict_corpus_shards.py" select --shard-index "$shard_index" --shard-count "$shard_count") || exit 2
  # mapfile/process substitution does not propagate producer failures.
  python3 "$repo_root/scripts/strict_corpus_shards.py" select --shard-index "$shard_index" --shard-count "$shard_count" >/dev/null || exit 2
else
  mapfile -t rows < <(python3 "$repo_root/scripts/strict_corpus_shards.py" select --shard-index 0 --shard-count 1) || exit 2
fi

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

summary_path="$artifact_root/strict-corpus-summary.json"
if [[ -n "$shard_index" ]]; then
  summary_path="$artifact_root/strict-corpus-summary-shard-${shard_index}-of-${shard_count}.json"
fi
python3 - "$summary_path" "$tier" "$runtime" "$completed" "$failed" "${#rows[@]}" "$shard_index" "$shard_count" "$repo_root/fixtures/evaluator/compatibility-corpus.json" <<'PY'
import json
import pathlib
import sys
path, tier, runtime, completed, failed, total, shard_index, shard_count, manifest = sys.argv[1:]
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
if shard_index:
    document["shardIndex"] = int(shard_index)
    document["shardCount"] = int(shard_count)
    document["unitIds"] = [
        row["unitId"] for row in json.loads(
            pathlib.Path(manifest)
            .read_text(encoding="utf-8")
        )["rows"]
        if row.get("required") and row.get("applicable")
    ][int(shard_index)::int(shard_count)]
pathlib.Path(path).write_text(json.dumps(document, sort_keys=True, indent=2) + '\n', encoding='utf-8')
PY

if (( failed != 0 )); then
  echo "strict compatibility corpus failed: ${failed}/${#rows[@]} rows" >&2
  exit "$status"
fi
echo "PASS strict compatibility corpus: ${completed}/${#rows[@]} rows"
