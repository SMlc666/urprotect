#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --runtime glibc|musl|bionic\n' "$0" >&2
}

tier=''
runtime=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      tier="$2"
      shift 2
      ;;
    --runtime)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      runtime="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

case "$tier" in
  pr|nightly|release) ;;
  *) echo "invalid protection tier: $tier" >&2; exit 2 ;;
esac
case "$runtime" in
  glibc|musl) ;;
  bionic) ;;
  *) echo "invalid protection runtime: $runtime" >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${PROTECTION_ARTIFACT_ROOT:-${repo_root}/.artifacts/protection/${tier}/${runtime}}"
work_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/urprotect-protection-${tier}-${runtime}-$$"
mkdir -p "$artifact_root" "$work_root"
cleanup() {
  rm -rf -- "$work_root"
}
trap cleanup EXIT

if [[ "$runtime" == 'bionic' ]]; then
  BIONIC_ARTIFACT_ROOT="$artifact_root" \
    BIONIC_PROTECTION_E2E=true \
    "${repo_root}/scripts/run-bionic-fixture.sh"
  python3 "${repo_root}/scripts/check-protection-evidence.py" \
    "${artifact_root}/c-termux-bionic-pie" --runtime bionic
  exit 0
fi

for required_command in cmp dotnet file python3 readelf sha256sum timeout; do
  command -v "$required_command" >/dev/null 2>&1 || {
    echo "$required_command is required for protection E2E" >&2
    exit 127
  }
done
if [[ "$(uname -m)" != 'aarch64' ]]; then
  echo "protection E2E requires a native AArch64 runner; got $(uname -m)" >&2
  exit 2
fi

case "$runtime" in
  glibc)
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
      cc=(aarch64-linux-gnu-gcc)
    else
      cc=(gcc)
    fi
    ;;
  musl)
    command -v musl-gcc >/dev/null 2>&1 || {
      echo 'musl-gcc is required for musl protection E2E' >&2
      exit 127
    }
    cc=(musl-gcc)
    ;;
esac

build_root="$work_root/build"
mkdir -p "$build_root"
"${cc[@]}" -std=c11 -O0 -g0 -fPIE -pie -Wl,--build-id=none \
  "$repo_root/fixtures/samples/protection/main.c" \
  "$repo_root/fixtures/samples/protection/target.S" \
  -o "$build_root/original"

# A spare PT_NULL entry gives the initial writer a transactional program-header
# placement without moving or rewriting any existing load map. Removing only
# GNU_RELRO is intentional for this controlled fixture; the runtime oracle still
# validates original/protected behavior in the declared userspace.
python3 - "$build_root/original" "$build_root/input" <<'PY'
from pathlib import Path
import struct
import sys

source = bytearray(Path(sys.argv[1]).read_bytes())
phoff = struct.unpack_from('<Q', source, 32)[0]
entry_size = struct.unpack_from('<H', source, 54)[0]
count = struct.unpack_from('<H', source, 56)[0]
for index in range(count):
    offset = phoff + index * entry_size
    if struct.unpack_from('<I', source, offset)[0] == 0x6474E552:
        struct.pack_into('<I', source, offset, 0)
        Path(sys.argv[2]).write_bytes(source)
        break
else:
    raise SystemExit('the protection fixture has no GNU_RELRO slot to convert to PT_NULL')
PY
chmod --reference="$build_root/original" "$build_root/input"

file "$build_root/input" > "$artifact_root/input-file.txt"
readelf -hW -lW -sW "$build_root/input" > "$artifact_root/input-readelf.txt"
grep -Fq 'AArch64' "$artifact_root/input-readelf.txt"
grep -Fq 'urp_transform_target' "$artifact_root/input-readelf.txt"

run_timeout="${PROTECTION_TIMEOUT_SECONDS:-20}"
dotnet_cli=(dotnet run --project "$repo_root/src/UrProtect.Cli" --configuration Release --no-restore --)
set +e
timeout "$run_timeout" "$build_root/input" > "$work_root/baseline.stdout" 2> "$work_root/baseline.stderr"
baseline_status=$?
set -e
printf '%s\n' "$baseline_status" > "$artifact_root/baseline.status"
cp "$work_root/baseline.stdout" "$artifact_root/baseline.stdout"
cp "$work_root/baseline.stderr" "$artifact_root/baseline.stderr"
[[ "$baseline_status" -eq 0 ]] || {
  echo "baseline protection fixture failed with status $baseline_status" >&2
  exit 1
}

recipes=(register-permutation control-flow-flattening combined)
for recipe in "${recipes[@]}"; do
  case "$recipe" in
    register-permutation) passes=(--pass register-permutation) ;;
    control-flow-flattening) passes=(--pass control-flow-flattening) ;;
    combined) passes=(--pass register-permutation --pass control-flow-flattening) ;;
  esac

  output="$work_root/$recipe"
  report="$work_root/$recipe.json"
  if ! "${dotnet_cli[@]}" protect "$build_root/input" \
      --output "$output" \
      --function urp_transform_target \
      "${passes[@]}" \
      --json "$report" \
      > "$work_root/$recipe.stdout" \
      2> "$work_root/$recipe.stderr"; then
    cat "$work_root/$recipe.stdout" >&2
    cat "$work_root/$recipe.stderr" >&2
    exit 1
  fi

  python3 - "$report" "$recipe" <<'PY'
import json
import sys

report = json.loads(open(sys.argv[1]).read())
recipe = sys.argv[2]
if report.get('success') is not True:
    raise SystemExit(f'{recipe}: protection report did not succeed')
selected = [item for item in report.get('functions', [])
            if item.get('name') == 'urp_transform_target']
if len(selected) != 1 or selected[0].get('transformed') is not True:
    raise SystemExit(f'{recipe}: selected function was not transformed')
expected = {
    'register-permutation': ['register-permutation'],
    'control-flow-flattening': ['control-flow-flattening'],
    'combined': ['control-flow-flattening', 'register-permutation'],
}[recipe]
if selected[0].get('appliedPasses') != expected:
    raise SystemExit(f'{recipe}: pass order mismatch: {selected[0].get("appliedPasses")}')
PY

  chmod --reference="$build_root/input" "$output"
  set +e
  timeout "$run_timeout" "$output" > "$work_root/$recipe.protected.stdout" \
    2> "$work_root/$recipe.protected.stderr"
  protected_status=$?
  set -e
  printf '%s\n' "$protected_status" > "$artifact_root/$recipe.status"
  cmp -- "$work_root/baseline.stdout" "$work_root/$recipe.protected.stdout"
  cmp -- "$work_root/baseline.stderr" "$work_root/$recipe.protected.stderr"
  [[ "$protected_status" -eq "$baseline_status" ]] || {
    echo "$recipe: protected status $protected_status differs from baseline $baseline_status" >&2
    exit 1
  }
  cp "$report" "$artifact_root/$recipe.json"
  readelf -hW -lW "$output" > "$artifact_root/$recipe-readelf.txt"
  sha256sum "$build_root/input" "$output" > "$artifact_root/$recipe.sha256"
done

# Exercise a non-trivial NZCV-based branch separately so the standalone
# flattening claim includes CFG dispatch rather than only a one-block function.
branch_output="$work_root/branch-control-flow-flattening"
branch_report="$work_root/branch-control-flow-flattening.json"
if ! "${dotnet_cli[@]}" protect "$build_root/input" \
    --output "$branch_output" \
    --function urp_flatten_target \
    --pass control-flow-flattening \
    --json "$branch_report" \
    > "$work_root/branch-control-flow-flattening.stdout" \
    2> "$work_root/branch-control-flow-flattening.stderr"; then
  cat "$work_root/branch-control-flow-flattening.stdout" >&2
  cat "$work_root/branch-control-flow-flattening.stderr" >&2
  exit 1
fi
python3 - "$branch_report" <<'PY'
import json
import sys

report = json.loads(open(sys.argv[1]).read())
selected = [item for item in report.get('functions', [])
            if item.get('name') == 'urp_flatten_target']
if report.get('success') is not True or len(selected) != 1:
    raise SystemExit('branch flattening report did not succeed')
if selected[0].get('transformed') is not True:
    raise SystemExit('branch flattening target was not transformed')
if selected[0].get('appliedPasses') != ['control-flow-flattening']:
    raise SystemExit('branch flattening pass order is incorrect')
PY
chmod --reference="$build_root/input" "$branch_output"
set +e
timeout "$run_timeout" "$branch_output" > "$work_root/branch-control-flow-flattening.protected.stdout" \
  2> "$work_root/branch-control-flow-flattening.protected.stderr"
branch_status=$?
set -e
printf '%s\n' "$branch_status" > "$artifact_root/branch-control-flow-flattening.status"
cmp -- "$work_root/baseline.stdout" "$work_root/branch-control-flow-flattening.protected.stdout"
cmp -- "$work_root/baseline.stderr" "$work_root/branch-control-flow-flattening.protected.stderr"
[[ "$branch_status" -eq "$baseline_status" ]] || {
  echo "branch flattening protected status $branch_status differs from baseline $baseline_status" >&2
  exit 1
}
cp "$branch_report" "$artifact_root/branch-control-flow-flattening.json"
readelf -hW -lW "$branch_output" > "$artifact_root/branch-control-flow-flattening-readelf.txt"
sha256sum "$build_root/input" "$branch_output" > "$artifact_root/branch-control-flow-flattening.sha256"

python3 - "$artifact_root/result.json" "$tier" "$runtime" "$baseline_status" <<'PY'
import json
import pathlib
import sys

path, tier, runtime, baseline = sys.argv[1:]
document = {
    'schemaVersion': 1,
    'tier': tier,
    'runtime': runtime,
    'baselineStatus': int(baseline),
    'recipes': [
        'register-permutation',
        'control-flow-flattening',
        'combined',
        'branch-control-flow-flattening',
    ],
    'behaviorEquivalent': True,
    'rawInputsRemoved': True,
}
pathlib.Path(path).write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
PY
printf 'runtime=%s\ntier=%s\nexecution=native-aarch64-%s\n' "$runtime" "$tier" "$runtime" > "$artifact_root/environment.txt"
rm -rf -- "$build_root"
printf 'PASS protection-e2e: runtime=%s tier=%s\n' "$runtime" "$tier"
