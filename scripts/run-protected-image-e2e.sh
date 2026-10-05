#!/usr/bin/env bash
set -u -o pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --runtime glibc|musl|bionic [--unit UNIT]\n' "$0" >&2
}

tier=''
runtime=''
unit='compat.protection-symbolized-fixture.glibc.outer-execveat'
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
    --unit)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      unit="$2"
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
  *) echo "invalid protected-image tier: $tier" >&2; exit 2 ;;
esac
case "$runtime" in
  glibc|musl|bionic) ;;
  *) echo "invalid protected-image runtime: $runtime" >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_parent="${PROTECTED_IMAGE_ARTIFACT_ROOT:-${repo_root}/.artifacts/protected-image/${tier}/${runtime}}"
artifact_root="${artifact_parent}/${unit}"
work_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/urprotect-protected-image-${tier}-${runtime}-$$"
# Each invocation owns one evidence unit. Remove stale output before starting so a
# retry cannot mistake a previous successful artifact for a failed publication.
rm -rf -- "$artifact_root"
mkdir -p "$artifact_root" "$work_root"

artifact_path="$artifact_root/protected-image.bin"
role_path="$artifact_root/protected-image.json"
manifest_path="$artifact_root/SHA256SUMS"
stage_path="$artifact_root/stage.json"
stdout_path="$artifact_root/stdout.txt"
stderr_path="$artifact_root/stderr.txt"

cleanup() {
  rm -rf -- "$work_root"
}
trap cleanup EXIT

sha256_text() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

command_digest="$(sha256_text "protect-image|${tier}|${runtime}|${unit}")"
environment_digest="$(env | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
producer_build=''
if [[ -f "$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll" ]]; then
  producer_build="$(sha256sum "$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll" | cut -d' ' -f1)"
fi
[[ -n "$producer_build" ]] || producer_build="$(sha256_text 'urprotect-cli:unavailable')"

write_failure_stage() {
  local reason="$1"
  local source_digest='null'
  if [[ -f "$work_root/input" ]]; then
    source_digest="\"$(sha256sum "$work_root/input" | cut -d' ' -f1)\""
  fi
  python3 - "$stage_path" "$manifest_path" "$unit" "$runtime" "$producer_build" "$command_digest" "$environment_digest" "$source_digest" "$reason" <<'PY'
import json
import pathlib
import sys

path, manifest, unit, profile, producer, command, environment, source, reason = sys.argv[1:]
document = {
    "schemaVersion": 1,
    "stage": "protected-image-producer",
    "status": "failed",
    "unitId": unit,
    "profile": "outer-execveat" if profile in {"glibc", "musl", "bionic"} else profile,
    "sourceSha256": json.loads(source),
    "requestSha256": None,
    "producerId": "gcc-c-protection-fixture",
    "producerBuildSha256": producer,
    "rehydratorConsumerId": "urprotect.rehydrator.v1",
    "artifactSha256": None,
    "artifactSize": None,
    "commandDigest": command,
    "environmentDigest": environment,
    "artifactPath": "protected-image.bin",
    "rolePath": "protected-image.json",
    "rawEvidenceManifestPath": "SHA256SUMS",
    "transformationStatus": "runner-failed",
    "transformedFunctionCount": 0,
    "selectors": ["name=urp_transform_target"],
    "passes": ["control-flow-flattening"],
    "diagnostics": [{
        "severity": "Error",
        "code": "RunnerFailure",
        "message": reason[:4096],
        "offset": None,
    }],
    "publicationComplete": False,
}
pathlib.Path(path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

required_commands=(python3 sha256sum sort find)
for required_command in "${required_commands[@]}"; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$required_command" >"$stderr_path"
    : >"$stdout_path"
    write_failure_stage "missing required command: $required_command"
    (cd "$artifact_root" && find . -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$manifest_path"
    python3 "$repo_root/scripts/check-protected-image-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" --expect-failure
    exit 127
  fi
done

cc=()
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  cc=(aarch64-linux-gnu-gcc)
elif command -v gcc >/dev/null 2>&1; then
  cc=(gcc)
else
  printf 'no AArch64 C compiler is available\n' >"$stderr_path"
  : >"$stdout_path"
  write_failure_stage 'no AArch64 C compiler is available'
  (cd "$artifact_root" && find . -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$manifest_path"
  python3 "$repo_root/scripts/check-protected-image-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" --expect-failure
  exit 127
fi

mkdir -p "$work_root/build"
if ! "${cc[@]}" -std=c11 -O0 -g0 -fPIE -pie -Wl,--build-id=none \
    "$repo_root/fixtures/samples/protection/main.c" \
    "$repo_root/fixtures/samples/protection/target.S" \
    -o "$work_root/build/original" >"$work_root/compile.stdout" 2>"$work_root/compile.stderr"; then
  cp "$work_root/compile.stdout" "$stdout_path"
  cp "$work_root/compile.stderr" "$stderr_path"
  write_failure_stage 'frozen protection fixture compilation failed'
  (cd "$artifact_root" && find . -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$manifest_path"
  python3 "$repo_root/scripts/check-protected-image-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" --expect-failure
  exit 1
fi

python3 - "$work_root/build/original" "$work_root/input" >"$work_root/fixture.stdout" 2>"$work_root/fixture.stderr" <<'PY'
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
    raise SystemExit('the frozen fixture has no GNU_RELRO entry to convert to PT_NULL')
PY
if [[ ! -s "$work_root/input" ]]; then
  cp "$work_root/fixture.stdout" "$stdout_path"
  cp "$work_root/fixture.stderr" "$stderr_path"
  write_failure_stage 'frozen protection fixture did not produce an input image'
  (cd "$artifact_root" && find . -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$manifest_path"
  python3 "$repo_root/scripts/check-protected-image-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" --expect-failure
  exit 1
fi

source_sha256="$(sha256sum "$work_root/input" | cut -d' ' -f1)"
producer_command=(
  dotnet run --project "$repo_root/src/UrProtect.Cli" --configuration Release --no-restore --
  protect-image "$work_root/input"
  --artifact "$artifact_path"
  --role "$role_path"
  --manifest "$manifest_path"
  --stage "$stage_path"
  --unit "$unit"
  --profile outer-execveat
  --producer-id gcc-c-protection-fixture
  --rehydrator urprotect.rehydrator.v1
  --source-sha256 "$source_sha256"
  --function urp_transform_target
  --pass control-flow-flattening
  --json -
)

set +e
"${producer_command[@]}" >"$stdout_path" 2>"$stderr_path"
producer_status=$?
set -e

if [[ ! -s "$stage_path" ]]; then
  write_failure_stage "protect-image command exited ${producer_status} without a stage record"
fi

# The CLI's publisher atomically writes artifact, role, stage, and the initial
# producer manifest. Add the retained command streams and close the evidence tree
# after the process has stopped writing them.
(
  cd "$artifact_root"
  find . -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum
) >"$manifest_path.tmp" && mv -f "$manifest_path.tmp" "$manifest_path"

if [[ "$producer_status" -eq 0 ]]; then
  python3 "$repo_root/scripts/check-protected-image-evidence.py" \
    "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit"
  checker_status=$?
else
  python3 "$repo_root/scripts/check-protected-image-evidence.py" \
    "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" --expect-failure
  checker_status=$?
fi

rm -rf -- "$work_root"
trap - EXIT
if [[ "$producer_status" -ne 0 ]]; then
  exit "$producer_status"
fi
exit "$checker_status"
