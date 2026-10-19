#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --artifact-root FRESH-PATH [--unit UNIT]\n' "$0" >&2
}
tier=''
artifact_root=''
unit='compat.protection-host-context-fixture.glibc.static-function-pointer-local-callback'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --artifact-root) [[ $# -ge 2 ]] || { usage; exit 2; }; artifact_root="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { usage; exit 2; }; unit="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) usage; exit 2 ;; esac
[[ -n "$artifact_root" ]] || { usage; exit 2; }
[[ "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo "invalid evidence unit: $unit" >&2; exit 2; }
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: static function-pointer E2E requires native AArch64" >&2; exit 2 ;; esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$artifact_root" in /*) ;; *) artifact_root="$repo_root/$artifact_root" ;; esac
artifact_root="$(realpath -m -- "$artifact_root")"
[[ ! -e "$artifact_root" && ! -L "$artifact_root" ]] || { echo "artifact root must be fresh and absent: $artifact_root" >&2; exit 2; }
mkdir -p -- "$(dirname "$artifact_root")"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/urprotect-static-function-pointer.XXXXXX")"
trap 'rm -rf -- "$work_root"' EXIT

native_root="$repo_root/native/urprotect-runtime"
make -C "$native_root" static-function-pointer-fixture >"$work_root/fixture-build.stdout" 2>"$work_root/fixture-build.stderr"
source_elf="$native_root/build/host-context-static-function-pointer-fixture.so"
object_file="$native_root/build/host-context-static-function-pointer-fixture.o"
[[ -s "$source_elf" && -s "$object_file" ]] || { echo "static callback fixture build did not produce ELF/object" >&2; exit 1; }
function_index="$(readelf --dyn-syms -W "$source_elf" | awk '$4 == "FUNC" && $7 != "UND" && $8 == "urp_entry" && $1 ~ /^[0-9]+:/ { sub(":", "", $1); print $1; }')"
[[ "$function_index" =~ ^[0-9]+$ ]] || { echo "fixture lacks one dynamic urp_entry selector" >&2; exit 1; }
[[ "$(printf '%s\n' "$function_index" | wc -l)" -eq 1 ]] || { echo "fixture has duplicate dynamic urp_entry selectors" >&2; exit 1; }

PROTECTED_IMAGE_ARTIFACT_ROOT="$artifact_root" \
  "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" --runtime glibc --unit "$unit" --source "$source_elf" \
  --function-id "dynsym:$function_index" --entry-status 97 \
  --producer-id gcc-c-static-function-pointer-fixture

cp -- "$native_root/host_context_static_function_pointer_fixture.c" "$artifact_root/fixture-source.c"
cp -- "$object_file" "$artifact_root/fixture-object.o"
cp -- "$source_elf" "$artifact_root/fixture-shared-object.so"
cp -- "$work_root/fixture-build.stdout" "$artifact_root/fixture-build.stdout"
cp -- "$work_root/fixture-build.stderr" "$artifact_root/fixture-build.stderr"
cat >"$artifact_root/fixture-build.json" <<'JSON'
{
  "schemaVersion": 1,
  "compileCommand": "aarch64-linux-gnu-gcc -std=c11 -O1 -fPIC -fno-inline -fno-optimize-sibling-calls -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Werror -c host_context_static_function_pointer_fixture.c -o host-context-static-function-pointer-fixture.o",
  "linkCommand": "aarch64-linux-gnu-ld -shared --build-id=none --no-undefined --emit-relocs -z now host-context-static-function-pointer-fixture.o -o host-context-static-function-pointer-fixture.so"
}
JSON
readelf -h -S -s -r -W "$source_elf" >"$artifact_root/fixture-readelf.txt"

"$repo_root/native/urprotect-runtime/build/host-context-image-handoff" \
  "$artifact_root/source-image.bin" urp_observer "$artifact_root/observer-source-handoff.json" \
  >"$artifact_root/observer-source.stdout" 2>"$artifact_root/observer-source.stderr" || observer_source_status=$?
observer_source_status="${observer_source_status:-0}"
"$repo_root/native/urprotect-runtime/build/host-context-image-handoff" \
  "$artifact_root/native-image.bin" urp_observer "$artifact_root/observer-target-handoff.json" \
  >"$artifact_root/observer-target.stdout" 2>"$artifact_root/observer-target.stderr" || observer_target_status=$?
observer_target_status="${observer_target_status:-0}"
printf '%s\n' "$observer_source_status" >"$artifact_root/observer-source-process-status.txt"
printf '%s\n' "$observer_target_status" >"$artifact_root/observer-target-process-status.txt"
python3 - "$artifact_root" "$unit" "$observer_source_status" "$observer_target_status" <<'PY'
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
unit = sys.argv[2]
source_status, target_status = map(int, sys.argv[3:5])
def load(name):
    return json.loads((root / name).read_text(encoding="utf-8"))
def sha(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()
source = load("observer-source-handoff.json")
target = load("observer-target-handoff.json")
source["processStatus"] = source_status
(root / "observer-source-handoff.json").write_text(json.dumps(source, sort_keys=True, indent=2) + "\n", encoding="utf-8")
target["processStatus"] = target_status
(root / "observer-target-handoff.json").write_text(json.dumps(target, sort_keys=True, indent=2) + "\n", encoding="utf-8")
status = (
    source_status == target_status == 97
    and source.get("status") == target.get("status") == "passed"
    and source.get("entryStatus") == target.get("entryStatus") == 97
    and source.get("releaseStatus") == target.get("releaseStatus") == "passed"
    and source.get("loaderId") == target.get("loaderId")
    and (root / "observer-source.stdout").read_bytes() == (root / "observer-target.stdout").read_bytes()
    and (root / "observer-source.stderr").read_bytes() == (root / "observer-target.stderr").read_bytes()
)
report = {
    "schemaVersion": 1,
    "status": "passed" if status else "failed",
    "unitId": unit,
    "sourceImageSha256": sha("source-image.bin"),
    "nativeImageSha256": sha("native-image.bin"),
    "sourceHandoffSha256": sha("observer-source-handoff.json"),
    "nativeHandoffSha256": sha("observer-target-handoff.json"),
    "sourceProcessStatus": source_status,
    "nativeProcessStatus": target_status,
    "sourceEntryStatus": source.get("entryStatus"),
    "nativeEntryStatus": target.get("entryStatus"),
    "sourceReleaseStatus": source.get("releaseStatus"),
    "nativeReleaseStatus": target.get("releaseStatus"),
    "sourceStdoutSha256": sha("observer-source.stdout"),
    "nativeStdoutSha256": sha("observer-target.stdout"),
    "sourceStderrSha256": sha("observer-source.stderr"),
    "nativeStderrSha256": sha("observer-target.stderr"),
    "loaderId": target.get("loaderId"),
}
(root / "observer-handoff-evidence.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
if not status:
    raise SystemExit("observer source/transformed callback behavior or release status differs")
PY
python3 "$repo_root/scripts/tls_runtime_identity.py" >"$artifact_root/runtime-identity.json"
python3 "$repo_root/scripts/check-static-function-pointer-evidence.py" "$artifact_root" --tier "$tier" --unit "$unit" --write-report
(
  cd "$artifact_root"
  find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum
) >"$artifact_root/SHA256SUMS"
python3 "$repo_root/scripts/check-rehydration-evidence.py" "$artifact_root" --tier "$tier" --runtime glibc --unit "$unit"
python3 "$repo_root/scripts/check-static-function-pointer-evidence.py" "$artifact_root" --tier "$tier" --unit "$unit" --verify-manifest
printf 'Static function-pointer HostContext E2E: PASS (%s; entry and observer status 97)\n' "$unit"
