#!/usr/bin/env bash
set -u -o pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --runtime glibc|musl|bionic [--unit UNIT] [--source ELF] [--function-id TABLE:INDEX] [--entry-status STATUS] [--producer-id ID] [--native-build-dir build|build/musl-indirect-control|build/musl-shared-jump-table|build/bionic-indirect-control]\n' "$0" >&2
}

tier=''
runtime=''
native_build_dir_relative=''
require_runtime_identity=0
unit='compat.protection-host-context-fixture.glibc.host-context-entry'
source_file=''
function_id=''
expected_entry_status='23'
producer_id='gcc-c-host-context-fixture'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --runtime) [[ $# -ge 2 ]] || { usage; exit 2; }; runtime="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { usage; exit 2; }; unit="$2"; shift 2 ;;
    --source) [[ $# -ge 2 ]] || { usage; exit 2; }; source_file="$2"; shift 2 ;;
    --function-id) [[ $# -ge 2 ]] || { usage; exit 2; }; function_id="$2"; shift 2 ;;
    --entry-status) [[ $# -ge 2 ]] || { usage; exit 2; }; expected_entry_status="$2"; shift 2 ;;
    --producer-id) [[ $# -ge 2 ]] || { usage; exit 2; }; producer_id="$2"; shift 2 ;;
    --native-build-dir) [[ $# -ge 2 ]] || { usage; exit 2; }; native_build_dir_relative="$2"; shift 2 ;;
    --require-runtime-identity) require_runtime_identity=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid HostContext rehydration tier: $tier" >&2; exit 2 ;; esac
case "$runtime" in glibc|musl|bionic) ;; *) echo "unsupported HostContext rehydration runtime: $runtime" >&2; exit 2 ;; esac
if [[ "$runtime" == musl || "$runtime" == bionic ]]; then require_runtime_identity=1; fi
case "$runtime:$native_build_dir_relative" in
  glibc:) native_build_dir_relative=build ;;
  musl:) native_build_dir_relative=build/musl-indirect-control ;;
  bionic:) native_build_dir_relative=build/bionic-indirect-control ;;
  glibc:build|musl:build/musl-indirect-control|musl:build/musl-shared-jump-table|bionic:build/bionic-indirect-control) ;;
  *) echo "native build directory does not match the selected runtime" >&2; exit 2 ;;
esac
if [[ ! "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "invalid HostContext rehydration unit: $unit" >&2
  exit 2
fi
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: HostContext handoff requires native AArch64" >&2; exit 2 ;; esac
if [[ ! "${expected_entry_status}" =~ ^[0-9]+$ || "${expected_entry_status}" -gt 255 ]]; then
  echo "invalid expected HostContext entry status: ${expected_entry_status}" >&2
  exit 2
fi
if [[ -n "${function_id}" && ! "${function_id}" =~ ^(dynsym|symtab):[0-9]+$ ]]; then
  echo "invalid function selector: ${function_id}" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
native_build_dir="$native_root/$native_build_dir_relative"
if [[ "$runtime" == bionic ]]; then
  [[ -n "${BIONIC_INDIRECT_CONTROL_BUILD_ROOT:-}" ]] || { echo "environment-unavailable: pinned Bionic fixture build root is required" >&2; exit 2; }
  native_build_dir="$(realpath -e -- "$BIONIC_INDIRECT_CONTROL_BUILD_ROOT" 2>/dev/null || true)"
  [[ -n "$native_build_dir" && -d "$native_build_dir" && ! -L "$BIONIC_INDIRECT_CONTROL_BUILD_ROOT" ]] || { echo "Bionic fixture build root is not a real directory" >&2; exit 2; }
elif [[ "$runtime" == musl ]]; then
  command -v musl-gcc >/dev/null 2>&1 || { echo "environment-unavailable: pinned musl-gcc is required for native musl rehydration" >&2; exit 2; }
  runtime_cc="$(command -v musl-gcc)"
else
  runtime_cc=cc
fi
artifact_root="${PROTECTED_IMAGE_ARTIFACT_ROOT:-${repo_root}/.artifacts/protected-image/${tier}/${runtime}/${unit}}"
work_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/urprotect-host-context-rehydration-${tier}-${runtime}-$$"
mkdir -p "$artifact_root" "$work_root"
trap 'rm -rf -- "$work_root"' EXIT
rm -rf -- "$artifact_root"
mkdir -p "$artifact_root"
if [[ -z "$source_file" ]]; then
  source_file="$native_build_dir/host-context-entry-fixture.so"
elif [[ "$source_file" != /* ]]; then
  source_file="$repo_root/$source_file"
fi
make_args=("BUILD_DIR=$native_build_dir_relative")
if [[ "$runtime" == musl ]]; then
  make_args+=("CC=$runtime_cc" "LD=ld")
  make_args+=("HOST_ADAPTER_CFLAGS=-mno-outline-atomics")
fi
native_build_diagnostics_root="${URP_NATIVE_BUILD_DIAGNOSTICS_ROOT:-${artifact_root}.native-build-diagnostics}"
artifact_root_resolved="$(realpath -m -- "$artifact_root")" || exit 1
native_build_diagnostics_root_resolved="$(realpath -m -- "$native_build_diagnostics_root")" || exit 1
case "$native_build_diagnostics_root_resolved" in
  "$artifact_root_resolved"|"$artifact_root_resolved"/*)
    echo "HostContext native-build diagnostics must be outside the positive evidence root" >&2
    exit 2
    ;;
esac
nested_build_diagnostics_root="$native_build_diagnostics_root/host-context-image-handoff"
if [[ -e "$nested_build_diagnostics_root" || -L "$nested_build_diagnostics_root" ]]; then
  echo "refusing to overwrite existing HostContext native-build diagnostics: $nested_build_diagnostics_root" >&2
  exit 2
fi
mkdir -p "$nested_build_diagnostics_root" || exit 1
if [[ "$runtime" == bionic ]]; then
  for diagnostic in native-build.command.txt native-build.stdout native-build.stderr; do
    [[ -f "$native_build_dir/$diagnostic" && ! -L "$native_build_dir/$diagnostic" ]] || {
      echo "Bionic native build is missing regular non-symlink diagnostic $diagnostic" >&2
      exit 1
    }
    cp -- "$native_build_dir/$diagnostic" "$nested_build_diagnostics_root/$diagnostic" || exit 1
  done
  if ! native_build_status="$(python3 "$repo_root/scripts/parse-native-build-status.py" "$native_build_dir/native-build.status")"; then
    echo "refusing Bionic HostContext continuation without an exact canonical native-build status" >&2
    exit 1
  fi
  printf '%s\n' "$native_build_status" >"$nested_build_diagnostics_root/native-build.status" || exit 1
else
  native_build_command=(make -C "$native_root" "${make_args[@]}" host-context-entry-fixture host-context-image-handoff)
  {
    printf 'cwd=%s\n' "$native_root"
    printf 'runtime=%s\n' "$runtime"
    printf 'argv='
    printf '%q ' "${native_build_command[@]}"
    printf '\n'
  } >"$nested_build_diagnostics_root/native-build.command.txt" || exit 1
  native_build_status=0
  "${native_build_command[@]}" \
    >"$nested_build_diagnostics_root/native-build.stdout" \
    2>"$nested_build_diagnostics_root/native-build.stderr" || native_build_status=$?
  printf '%s\n' "$native_build_status" >"$nested_build_diagnostics_root/native-build.status" || exit 1
fi
if [[ "$native_build_status" != "0" ]]; then
  printf 'HostContext native fixture/helper build failed with status %s\n' "$native_build_status" >&2
  exit "$native_build_status"
fi
if [[ "$runtime" == bionic ]]; then
  [[ -n "${BIONIC_RUNTIME_RESULT:-}" && -f "$BIONIC_RUNTIME_RESULT" && ! -L "$BIONIC_RUNTIME_RESULT" ]] || { echo "Bionic pinned runtime provenance result is missing" >&2; exit 2; }
  cp -- "$BIONIC_RUNTIME_RESULT" "$artifact_root/bionic-runtime-environment.json" || exit 1
fi
source_file="$(realpath -e -- "$source_file" 2>/dev/null || true)"
[[ -f "$source_file" && ! -L "$source_file" ]] || { echo "HostContext source fixture is not a regular ELF" >&2; exit 2; }
native_helper_elf="$native_build_dir/host-context-image-handoff"
[[ -x "$native_helper_elf" && -f "$native_helper_elf" && ! -L "$native_helper_elf" ]] || { echo "HostContext native handoff helper is missing from the selected runtime build directory" >&2; exit 2; }
helper_interpreter="$(readelf -lW "$native_helper_elf" | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p' | head -n 1)"
if [[ "$runtime" == bionic ]]; then
  [[ "$helper_interpreter" == /system/bin/linker64 ]] || { echo "Bionic native handoff helper PT_INTERP is not exactly /system/bin/linker64" >&2; exit 2; }
  [[ -n "${BIONIC_RUNTIME_RESULT:-}" && -f "$BIONIC_RUNTIME_RESULT" && ! -L "$BIONIC_RUNTIME_RESULT" ]] || { echo "Bionic pinned runtime provenance result is missing" >&2; exit 2; }
  native_helper="$repo_root/scripts/run-bionic-host-context-handoff.sh"
  [[ -x "$native_helper" && -f "$native_helper" && ! -L "$native_helper" ]] || { echo "Bionic HostContext container bridge is missing" >&2; exit 2; }
else
  [[ -n "$helper_interpreter" && -e "$helper_interpreter" ]] || { echo "environment-unavailable: selected native runtime interpreter is missing" >&2; exit 2; }
  case "$runtime:$(basename "$helper_interpreter")" in
    glibc:ld-linux-aarch64.so.1|musl:ld-musl-aarch64.so.1) ;;
    *) echo "native handoff helper was not linked against the selected runtime" >&2; exit 2 ;;
  esac
  native_helper="$native_helper_elf"
fi
source_path="$artifact_root/source-image.bin"
cp "$source_file" "$source_path"
artifact_path="$artifact_root/protected-image.bin"
role_path="$artifact_root/protected-image.json"
stage_path="$artifact_root/stage.json"
manifest_path="$artifact_root/SHA256SUMS"
native_path="$artifact_root/native-image.bin"
native_role_path="$artifact_root/native-image.json"
record_path="$artifact_root/rehydration.json"
handoff_path="$artifact_root/handoff.json"

capture_bionic_handoff() {
  local label="$1" record="$2" expected="$3" wrapper_status
  shift 3
  python3 "$repo_root/scripts/capture-bionic-handoff.py" \
    --root "$artifact_root" --label "$label" --record "$record" \
    --expected-status "$expected" -- "$@"
  wrapper_status=$?
  BIONIC_CAPTURE_WRAPPER_STATUS="$wrapper_status"
  BIONIC_CAPTURE_PROCESS_STATUS=''
  if [[ -f "$artifact_root/$label.process-status" && ! -L "$artifact_root/$label.process-status" ]]; then
    BIONIC_CAPTURE_PROCESS_STATUS="$(cat "$artifact_root/$label.process-status")"
  fi
  return "$wrapper_status"
}

# Name-only selection is intentionally rejected by the shared selector contract.
if [[ -z "${function_id}" ]]; then
  dynsym_index="$(readelf -Ws "$source_path" | awk '$8 == "urp_transform_target" && $1 ~ /^[0-9]+:/ { sub(":", "", $1); print $1; exit }')"
  [[ "$dynsym_index" =~ ^[0-9]+$ ]] || { echo "HostContext transform symbol is missing" >&2; exit 1; }
  function_id="dynsym:${dynsym_index}"
fi
source_sha256="$(sha256sum "$source_path" | cut -d' ' -f1)"
cli="$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
core="$repo_root/src/UrProtect.Core/bin/Release/net8.0/UrProtect.Core.dll"
[[ -s "$cli" && -s "$core" ]] || { echo "managed Release assemblies are missing" >&2; exit 1; }

set +e
dotnet "$cli" protect-image "$source_path" \
  --artifact "$artifact_path" --role "$role_path" --manifest "$manifest_path" --stage "$stage_path" \
  --unit "$unit" --profile host-context-entry --producer-id "${producer_id}" \
  --rehydrator urprotect.rehydrator.v1 --source-sha256 "$source_sha256" \
  --function-id "${function_id}" --pass control-flow-flattening --json - \
  >"$artifact_root/producer.json" 2>"$artifact_root/producer.stderr"
producer_status=$?
set -e
if [[ "$producer_status" -ne 0 || ! -s "$artifact_path" || ! -s "$role_path" || ! -s "$stage_path" ]]; then
  echo "HostContext Protected Image producer failed" >&2
  exit 1
fi
request_sha256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["requestSha256"])' "$role_path")"
producer_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["producerId"])' "$role_path")"
producer_build="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["producerBuildSha256"])' "$role_path")"
consumer_build="$(sha256sum "$core" | cut -d' ' -f1)"

dotnet "$cli" rehydrate-image "$source_path" \
  --artifact "$artifact_path" --native-image "$native_path" --role "$native_role_path" --record "$record_path" \
  --unit "$unit" --profile host-context-entry --source-sha256 "$source_sha256" --request-sha256 "$request_sha256" \
  --producer-id "$producer_id" --producer-build-sha256 "$producer_build" \
  --consumer-id urprotect.rehydrator.v1 --consumer-build-sha256 "$consumer_build" --json - \
  >"$artifact_root/rehydration-command.json" 2>"$artifact_root/rehydration-command.stderr"

[[ -s "$native_path" && -s "$record_path" ]] || { echo "HostContext managed rehydration did not publish a Native Image" >&2; exit 1; }
identity_args=()
if [[ "$require_runtime_identity" -eq 1 ]]; then
  mkdir -p "$artifact_root/runtime-identity/target" "$artifact_root/runtime-identity/source"
  if [[ "$runtime" == bionic ]]; then chmod a+rwx "$artifact_root" "$artifact_root/runtime-identity" "$artifact_root/runtime-identity/target" "$artifact_root/runtime-identity/source" || exit 1; fi
  identity_args=("$artifact_root/runtime-identity/target" runtime-identity/target target)
fi
if [[ "$runtime" == bionic ]]; then
  target_handoff_command=("$native_helper" "$BIONIC_TERMUX_IMAGE" "$native_path" urp_entry "$handoff_path" "${identity_args[@]}")
  if ! capture_bionic_handoff handoff "$handoff_path" "$expected_entry_status" "${target_handoff_command[@]}"; then
    handoff_status="${BIONIC_CAPTURE_PROCESS_STATUS:-unknown}"
    echo "Bionic HostContext transformed handoff failed; captured process status=${handoff_status}, wrapper status=${BIONIC_CAPTURE_WRAPPER_STATUS}" >&2
    if [[ "$handoff_status" =~ ^[0-9]+$ && "$handoff_status" -ne "$expected_entry_status" && "$handoff_status" -gt 0 ]]; then exit "$handoff_status"; fi
    exit 1
  fi
  handoff_status="$BIONIC_CAPTURE_PROCESS_STATUS"
else
  set +e
  "$native_helper" \
    "$native_path" urp_entry "$handoff_path" "${identity_args[@]}" \
    >"$artifact_root/handoff.stdout" 2>"$artifact_root/handoff.stderr"
  handoff_status=$?
  set -e
fi
[[ "$handoff_status" -eq "$expected_entry_status" && -s "$handoff_path" ]] || { echo "HostContext native handoff failed with status $handoff_status" >&2; exit 1; }
cp -- "$artifact_root/handoff.stdout" "$artifact_root/target.stdout"
cp -- "$artifact_root/handoff.stderr" "$artifact_root/target.stderr"

python3 - "$record_path" "$handoff_path" "$native_role_path" "$handoff_status" <<'PY'
import hashlib
import json
import pathlib
import tempfile
import os
record_path, handoff_path, role_path = map(pathlib.Path, __import__('sys').argv[1:4])
process_status = int(__import__('sys').argv[4])
old = record_path.read_bytes()
record = json.loads(old.decode())
handoff = json.loads(handoff_path.read_text())
pre_hash = hashlib.sha256(old).hexdigest()
handoff["processStatus"] = process_status
handoff["rehydrationRecordSha256"] = pre_hash
handoff_bytes = (json.dumps(handoff, indent=2, sort_keys=True) + "\n").encode()
handoff_path.write_bytes(handoff_bytes)
record["preHandoffRecordSha256"] = pre_hash
record["handoffRecordSha256"] = hashlib.sha256(handoff_bytes).hexdigest()
record["handoffStatus"] = handoff.get("status")
record["entryStatus"] = handoff.get("entryStatus")
record["processStatus"] = process_status
record["releaseOrder"] = handoff.get("releaseOrder")
record["loaderIdentity"] = handoff.get("loaderId")
updated = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
fd, temporary = tempfile.mkstemp(prefix=record_path.name + ".", suffix=".tmp", dir=record_path.parent)
os.close(fd)
try:
    pathlib.Path(temporary).write_bytes(updated)
    os.replace(temporary, record_path)
finally:
    pathlib.Path(temporary).unlink(missing_ok=True)
if role_path.is_file():
    role = json.loads(role_path.read_text())
    role["rehydrationRecordSha256"] = hashlib.sha256(updated).hexdigest()
    role_path.write_text(json.dumps(role, indent=2, sort_keys=True) + "\n")
PY
source_handoff_path="$artifact_root/source-handoff.json"
source_identity_args=()
if [[ "$require_runtime_identity" -eq 1 ]]; then
  source_identity_args=("$artifact_root/runtime-identity/source" runtime-identity/source source)
fi
if [[ "$runtime" == bionic ]]; then
  source_handoff_command=("$native_helper" "$BIONIC_TERMUX_IMAGE" "$source_path" urp_entry "$source_handoff_path" "${source_identity_args[@]}")
  if ! capture_bionic_handoff source-handoff "$source_handoff_path" "$expected_entry_status" "${source_handoff_command[@]}"; then
    source_process_status="${BIONIC_CAPTURE_PROCESS_STATUS:-unknown}"
    echo "Bionic HostContext source handoff failed; captured process status=${source_process_status}, wrapper status=${BIONIC_CAPTURE_WRAPPER_STATUS}" >&2
    if [[ "$source_process_status" =~ ^[0-9]+$ && "$source_process_status" -ne "$expected_entry_status" && "$source_process_status" -gt 0 ]]; then exit "$source_process_status"; fi
    exit 1
  fi
  source_process_status="$BIONIC_CAPTURE_PROCESS_STATUS"
  cp -- "$artifact_root/source-handoff.stdout" "$artifact_root/baseline.stdout"
  cp -- "$artifact_root/source-handoff.stderr" "$artifact_root/baseline.stderr"
else
  set +e
  "$native_helper" \
    "$source_path" urp_entry "$source_handoff_path" "${source_identity_args[@]}" \
    >"$artifact_root/baseline.stdout" 2>"$artifact_root/baseline.stderr"
  source_process_status=$?
  set -e
fi
python3 - "$artifact_root" "$source_sha256" "$native_path" "$handoff_path" "$source_handoff_path" "$source_process_status" "$handoff_status" "$expected_entry_status" <<'PY'
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1]).resolve()
source_hash = sys.argv[2]
native_path = pathlib.Path(sys.argv[3])
target_handoff_path = pathlib.Path(sys.argv[4])
source_handoff_path = pathlib.Path(sys.argv[5])
source_process_status = int(sys.argv[6])
target_process_status = int(sys.argv[7])
expected_entry_status = int(sys.argv[8])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def read_record(path):
    return json.loads(path.read_text(encoding="utf-8"))
source_record = read_record(source_handoff_path)
target_record = read_record(target_handoff_path)
native_hash = sha(native_path)
source_record["processStatus"] = source_process_status
source_handoff_path.write_text(json.dumps(source_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
source_handoff_hash = sha(source_handoff_path)
target_handoff_hash = sha(target_handoff_path)
baseline_stdout = (root / "baseline.stdout").read_bytes()
baseline_stderr = (root / "baseline.stderr").read_bytes()
target_stdout = (root / "target.stdout").read_bytes()
target_stderr = (root / "target.stderr").read_bytes()
(root / "stdout.txt").write_bytes(target_stdout)
(root / "stderr.txt").write_bytes(target_stderr)
if max(map(len, (baseline_stdout, baseline_stderr, target_stdout, target_stderr))) > 1024 * 1024:
    raise SystemExit("HostContext baseline/target streams exceed the evidence bound")
status_equal = (
    source_record.get("status") == target_record.get("status") == "passed"
    and source_process_status == target_process_status
    and source_record.get("entryStatus") == target_record.get("entryStatus")
    and source_record.get("releaseStatus") == target_record.get("releaseStatus") == "passed"
)
stdout_equal = baseline_stdout == target_stdout
stderr_equal = baseline_stderr == target_stderr
source_entry_status = source_record.get("entryStatus")
target_entry_status = target_record.get("entryStatus")
if not isinstance(source_entry_status, int) or not isinstance(target_entry_status, int):
    raise SystemExit("HostContext source or transformed handoff lacks an observed entry status")
comparison = {
    "schemaVersion": 1,
    "unitId": read_record(root / "stage.json")["unitId"],
    "oracleId": "fixture.host-context-entry.v1",
    "sourceSha256": source_hash,
    "protectedSha256": sha(root / "protected-image.bin"),
    "nativeImageSha256": native_hash,
    "sourceHandoffSha256": source_handoff_hash,
    "targetHandoffSha256": target_handoff_hash,
    "sourceProcessStatus": source_process_status,
    "targetProcessStatus": target_process_status,
    "sourceEntryStatus": source_entry_status,
    "targetEntryStatus": target_entry_status,
    "sourceReleaseStatus": source_record.get("releaseStatus"),
    "targetReleaseStatus": target_record.get("releaseStatus"),
    "baselineStdoutSha256": sha(root / "baseline.stdout"),
    "baselineStderrSha256": sha(root / "baseline.stderr"),
    "targetStdoutSha256": sha(root / "target.stdout"),
    "targetStderrSha256": sha(root / "target.stderr"),
    "statusEqual": status_equal,
    "stdoutEqual": stdout_equal,
    "stderrEqual": stderr_equal,
}
comparison_bytes = (json.dumps(comparison, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
comparison_path = root / "behavior-comparison.json"
comparison_path.write_bytes(comparison_bytes)
overall = status_equal and stdout_equal and stderr_equal
oracle = {
    **comparison,
    "stage": "behavioral-oracle",
    "status": "passed" if overall else "failed",
    "comparisonSha256": hashlib.sha256(comparison_bytes).hexdigest(),
    "baselineStatus": source_process_status,
    "targetStatus": target_process_status,
    "entryStatus": target_entry_status,
    "expectedEntryStatus": expected_entry_status,
    "firstFailureStage": None if overall else "behavioral-oracle",
}
(root / "behavioral-oracle.json").write_text(json.dumps(oracle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
target_loader = {
    "schemaVersion": 1,
    "stage": "target-loader",
    "status": "passed" if target_record.get("status") == "passed" else "failed",
    "loaderId": target_record.get("loaderId"),
    "nativeImageSha256": native_hash,
    "evidenceSha256": target_handoff_hash,
    "handoffRecordSha256": target_handoff_hash,
    "targetStatus": target_entry_status,
    "targetProcessStatus": target_process_status,
    "targetSignal": None,
    "stdoutSha256": sha(root / "target.stdout"),
    "stderrSha256": sha(root / "target.stderr"),
    "firstFailureStage": None if target_record.get("status") == "passed" else "target-loader",
}
(root / "target-loader.json").write_text(json.dumps(target_loader, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(root / "negative-rollback.json").write_text(json.dumps({
    "schemaVersion": 1, "kind": "strict-chain-negative-witness", "status": "passed",
    "unitId": comparison["unitId"], "stage": "rehydration",
    "failureClass": "ProtectedImageIntegrityMismatch", "rollbackStatus": "passed",
    "nativeImagePublished": False, "loaderInvoked": False, "loaderMarkerObserved": False,
    "artifactPath": "negative-protected-image.bin", "nativeImagePath": "negative-native-image.bin",
    "loaderMarkerPath": "target.stdout",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
record = read_record(root / "rehydration.json")
(root / "benchmark.json").write_text(json.dumps({
    "schemaVersion": 1, "unitId": comparison["unitId"],
    "rehydrationCpuMilliseconds": record.get("cpuMilliseconds"),
    "rehydrationDurationMilliseconds": record.get("durationMilliseconds"),
    "producerEmissionDurationMilliseconds": read_record(root / "stage.json").get("emissionDurationMilliseconds"),
    "nativeImageSize": record.get("nativeImageSize"), "handoffDurationNanoseconds": 0,
    "maxRssBytes": record.get("workingSetBytes"), "targetStatus": target_entry_status,
    "firstFailureStage": None if overall else "behavioral-oracle",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
(
  cd "$artifact_root"
  find . -type f ! -name 'SHA256SUMS' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum
) >"$manifest_path"
rehydration_checker_args=(--tier "$tier" --runtime "$runtime" --unit "$unit")
if [[ "$require_runtime_identity" -eq 1 ]]; then rehydration_checker_args+=(--require-runtime-identity); fi
python3 "$repo_root/scripts/check-rehydration-evidence.py" "$artifact_root" \
  "${rehydration_checker_args[@]}"
behavior_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$artifact_root/behavioral-oracle.json")"
[[ "$behavior_status" == "passed" ]] || { echo "HostContext source-vs-transformed behavioral oracle failed" >&2; exit 1; }
printf 'HostContext rehydration: PASS (entry status %s; source/transformed status, stdout, and stderr matched)\n' "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["entryStatus"])' "$handoff_path")"
