#!/usr/bin/env bash
set -u -o pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --runtime glibc [--unit UNIT] [--source C_SOURCE]\n' "$0" >&2
}

tier=''
runtime=''
unit='compat.protection-symbolized-fixture.glibc.outer-execveat'
source_file=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      tier="$2"; shift 2 ;;
    --runtime)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      runtime="$2"; shift 2 ;;
    --unit)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      unit="$2"; shift 2 ;;
    --source)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      source_file="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid rehydration tier: $tier" >&2; exit 2 ;; esac
case "$runtime" in glibc) ;; *) echo "the frozen rehydration vertical slice requires glibc" >&2; exit 2 ;; esac
if [[ ! "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "invalid rehydration unit: $unit" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "$source_file" ]]; then
  source_file="$repo_root/fixtures/samples/protection/main.c"
elif [[ "$source_file" != /* ]]; then
  source_file="$repo_root/$source_file"
fi
source_file="$(realpath -e -- "$source_file" 2>/dev/null || true)"
case "$source_file" in
  "$repo_root/fixtures/samples/"*.c) ;;
  *) echo "source must be a regular fixture C file under fixtures/samples" >&2; exit 2 ;;
esac
[[ -f "$source_file" && ! -L "$source_file" ]] || { echo "source fixture is not a regular file" >&2; exit 2; }
artifact_root="${PROTECTED_IMAGE_ARTIFACT_ROOT:-${repo_root}/.artifacts/protected-image/${tier}/${runtime}/${unit}}"
work_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/urprotect-rehydration-${tier}-${runtime}-$$"
mkdir -p "$artifact_root" "$work_root"
trap 'rm -rf -- "$work_root"' EXIT

source_path="$artifact_root/source-image.bin"
protected_path="$artifact_root/protected-image.bin"
role_path="$artifact_root/protected-image.json"
producer_stage="$artifact_root/stage.json"
native_path="$artifact_root/native-image.bin"
native_role_path="$artifact_root/native-image.json"
rehydration_path="$artifact_root/rehydration.json"
handoff_path="$artifact_root/handoff.json"
target_loader_path="$artifact_root/target-loader.json"
behavior_path="$artifact_root/behavioral-oracle.json"
producer_parent="$(dirname "$artifact_root")"
# The rehydration runner owns a clean unit tree and regenerates the producer
# evidence so it can be executed independently of the preceding CI step.
rm -rf -- "$artifact_root"
mkdir -p "$artifact_root"
set +e
PROTECTED_IMAGE_ARTIFACT_ROOT="$producer_parent" \
  "$repo_root/scripts/run-protected-image-e2e.sh" \
  --tier "$tier" --runtime "$runtime" --unit "$unit" --source "$source_file" \
  >"$work_root/producer-run.stdout" 2>"$work_root/producer-run.stderr"
producer_runner_status=$?
set -e
rm -f -- "$native_path" "$native_role_path" "$rehydration_path" "$handoff_path" \
  "$target_loader_path" "$behavior_path" "$artifact_root/behavior-comparison.json" \
  "$artifact_root/baseline.stdout" "$artifact_root/baseline.stderr" "$artifact_root/baseline.status" \
  "$artifact_root/target.stdout" "$artifact_root/target.stderr" "$artifact_root/handoff.stdout" \
  "$artifact_root/handoff.stderr" "$artifact_root/rehydration-command.stdout" \
  "$artifact_root/rehydration-command.stderr" "$artifact_root/rehydration-run.stdout" \
  "$artifact_root/rehydration-run.stderr" "$artifact_root/benchmark.json" \
  "$artifact_root/producer-check.stderr"

sha256_file() { sha256sum "$1" | cut -d' ' -f1; }
write_initial_environment() {
  python3 - "$artifact_root/environment.json" "$tier" "$runtime" "$unit" <<'PY'
import json
import os
import pathlib
import platform
import sys
path, tier, runtime, unit = sys.argv[1:]
document = {
    "schemaVersion": 1,
    "kind": "rehydration-environment",
    "tier": tier,
    "runtime": runtime,
    "unitId": unit,
    "architecture": platform.machine(),
    "kernel": platform.release(),
    "pageSize": os.sysconf("SC_PAGESIZE"),
    "strictLoader": "kernel.execveat-at-empty-path",
}
pathlib.Path(path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}
write_failure_records() {
  local stage="$1"
  local reason="$2"
  python3 - "$artifact_root" "$stage" "$reason" "$unit" <<'PY'
import hashlib
import json
import pathlib
import sys
root, stage, reason, unit = sys.argv[1:]
root = pathlib.Path(root)
producer = {}
try:
    producer = json.loads((root / "stage.json").read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    pass
source = producer.get("sourceSha256")
request = producer.get("requestSha256")
producer_id = producer.get("producerId", "gcc-c-protection-fixture")
producer_build = producer.get("producerBuildSha256") or hashlib.sha256(b"missing-producer-build").hexdigest()
consumer = producer.get("rehydratorConsumerId", "urprotect.rehydrator.v1")
protected_path = root / "protected-image.bin"
protected_hash = hashlib.sha256(protected_path.read_bytes()).hexdigest() if protected_path.is_file() else None
protected_size = protected_path.stat().st_size if protected_path.is_file() else None
record = {
    "schemaVersion": 1,
    "stage": "rehydration",
    "status": "failed",
    "unitId": unit,
    "profile": "outer-execveat",
    "abiId": "urprotect.protected-image.v1",
    "abiVersion": 1,
    "architecture": "AArch64",
    "sourceSha256": source,
    "requestSha256": request,
    "protectedImageSha256": protected_hash,
    "protectedImageSize": protected_size,
    "nativeImageSha256": None,
    "nativeImageSize": None,
    "producerId": producer_id,
    "producerBuildSha256": producer_build,
    "consumerId": consumer,
    "consumerBuildSha256": hashlib.sha256(b"rehydrator-not-started").hexdigest(),
    "layoutStrategy": "generic-elf-layout-v1",
    "handoffRecordPath": "handoff.json",
    "rawEvidenceManifestPath": "SHA256SUMS",
    "materializationStatus": "failed",
    "durationMilliseconds": 0,
    "cpuMilliseconds": None,
    "workingSetBytes": None,
    "firstFailureStage": stage,
    "diagnostics": [{
        "severity": "Error",
        "code": "UpstreamStageFailed" if stage != "rehydration" else "RehydrationRunnerFailure",
        "message": reason[:4096],
        "offset": None,
    }],
}
if not (root / "rehydration.json").is_file():
    (root / "rehydration.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if not (root / "handoff.json").is_file():
    (root / "handoff.json").write_text(json.dumps({
    "schemaVersion": 1, "stage": "native-handoff", "status": "failed",
    "helperStatus": "not-run", "helperExitCode": None,
    "nativeImageSha256": None,
    "rehydrationRecordSha256": hashlib.sha256((root / "rehydration.json").read_bytes()).hexdigest(),
    "loaderId": "kernel.execveat-at-empty-path",
    "memfdCreated": False, "fchmodStatus": "not-run", "fsyncStatus": "not-run",
    "sealsSupported": False, "sealsApplied": False, "execveatInvoked": False,
    "execveatStatus": "not-run", "targetStatus": None, "targetSignal": None,
    "stdoutBytes": 0, "stderrBytes": 0, "stdoutTruncated": False,
    "stderrTruncated": False, "targetDurationNanoseconds": 0, "maxRssBytes": None,
    "firstFailureStage": stage, "diagnostic": reason[:256],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if not (root / "target-loader.json").is_file():
    (root / "target-loader.json").write_text(json.dumps({
    "schemaVersion": 1, "stage": "target-loader", "status": "failed",
    "loaderId": "kernel.execveat-at-empty-path", "nativeImageSha256": None,
    "evidenceSha256": None, "targetStatus": None, "targetSignal": None,
    "firstFailureStage": stage,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if not (root / "behavioral-oracle.json").is_file():
    (root / "behavioral-oracle.json").write_text(json.dumps({
    "schemaVersion": 1, "stage": "behavioral-oracle", "status": "failed",
    "oracleId": "fixture.process-oracle.v1", "sourceSha256": source,
    "nativeImageSha256": None, "comparisonSha256": None,
    "firstFailureStage": stage,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
for stream_name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr"):
    if not (root / stream_name).exists():
        (root / stream_name).write_bytes(b"")
if not (root / "benchmark.json").is_file():
    (root / "benchmark.json").write_text(json.dumps({
    "schemaVersion": 1, "unitId": unit, "rehydrationCpuMilliseconds": None,
    "rehydrationDurationMilliseconds": None, "producerEmissionDurationMilliseconds": None,
    "nativeImageSize": None, "handoffDurationNanoseconds": None,
    "maxRssBytes": None, "targetStatus": None, "firstFailureStage": stage,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}
close_manifest() {
  (
    cd "$artifact_root"
    find . -type f ! -name 'SHA256SUMS' ! -name 'SHA256SUMS.tmp' -printf '%P\n' \
      | LC_ALL=C sort \
      | while IFS= read -r path; do sha256sum "$path"; done
  ) >"$artifact_root/SHA256SUMS.tmp" && mv -f "$artifact_root/SHA256SUMS.tmp" "$artifact_root/SHA256SUMS"
}

failure_stage=''
failure_reason=''
producer_check_status=0
if [[ ! -s "$producer_stage" || ! -s "$role_path" || ! -s "$protected_path" || ! -s "$source_path" ]]; then
  failure_stage='protected-image-producer'
  failure_reason='passed producer evidence and retained source image are required before rehydration'
else
  python3 "$repo_root/scripts/check-protected-image-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" >/dev/null 2>"$work_root/producer-check.stderr"
  producer_check_status=$?
  if [[ "$producer_check_status" -ne 0 ]]; then
    failure_stage='protected-image-producer'
    failure_reason="producer evidence checker returned ${producer_check_status}"
  else
    producer_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$producer_stage")"
    if [[ "$producer_status" != 'passed' ]]; then
      failure_stage='protected-image-producer'
      failure_reason='producer stage did not pass'
    fi
  fi
fi
write_initial_environment

cli="$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
core="$repo_root/src/UrProtect.Core/bin/Release/net8.0/UrProtect.Core.dll"
if [[ -z "$failure_stage" && ( ! -s "$cli" || ! -s "$core" ) ]]; then
  failure_stage='rehydration'
  failure_reason='the built managed rehydrator assemblies are missing'
fi

if [[ -z "$failure_stage" ]]; then
  mapfile -t role_values < <(python3 - "$role_path" <<'PY'
import json
import sys
role = json.load(open(sys.argv[1], encoding="utf-8"))
for field in ("unitId", "profile", "sourceSha256", "requestSha256", "producerId", "producerBuildSha256", "rehydratorConsumerId"):
    value = role.get(field)
    if not isinstance(value, str) or not value:
        raise SystemExit("role has a missing " + field)
    print(value)
PY
)
  if [[ "${#role_values[@]}" -ne 7 ]]; then
    failure_stage='protected-image-producer'
    failure_reason='producer role record is missing a required binding'
  else
    role_unit="${role_values[0]}"
    profile="${role_values[1]}"
    source_hash="${role_values[2]}"
    request_hash="${role_values[3]}"
    producer_id="${role_values[4]}"
    producer_build="${role_values[5]}"
    consumer_id="${role_values[6]}"
    consumer_build="$(sha256_file "$core")"
    artifact_hash="$(sha256_file "$protected_path")"
    if [[ "$role_unit" != "$unit" || "$profile" != 'outer-execveat' ]]; then
      failure_stage='protected-image-producer'
      failure_reason='producer unit or profile does not match the frozen vertical slice'
    elif [[ "$(sha256_file "$source_path")" != "$source_hash" ]]; then
      failure_stage='protected-image-producer'
      failure_reason='retained Source Image hash differs from the producer binding'
    elif [[ "$artifact_hash" != "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifactSha256"])' "$role_path")" ]]; then
      failure_stage='protected-image-producer'
      failure_reason='Protected Image artifact hash differs from its producer role'
    else
      rehydrate_command=(
        dotnet "$cli" rehydrate-image "$source_path"
        --artifact "$protected_path"
        --native-image "$native_path"
        --role "$native_role_path"
        --record "$rehydration_path"
        --unit "$unit"
        --profile "$profile"
        --source-sha256 "$source_hash"
        --request-sha256 "$request_hash"
        --producer-id "$producer_id"
        --producer-build-sha256 "$producer_build"
        --consumer-id "$consumer_id"
        --consumer-build-sha256 "$consumer_build"
        --json -
      )
      set +e
      "${rehydrate_command[@]}" >"$artifact_root/rehydration-command.stdout" 2>"$artifact_root/rehydration-command.stderr"
      rehydration_status=$?
      set -e
      if [[ "$rehydration_status" -ne 0 || ! -s "$rehydration_path" ]]; then
        failure_stage='rehydration'
        failure_reason="managed rehydration failed with status ${rehydration_status}"
      fi
    fi
  fi
fi

if [[ -n "$failure_stage" ]]; then
  rm -f -- "$native_path" "$native_role_path"
  write_failure_records "$failure_stage" "$failure_reason"
  printf '%s\n' "$failure_reason" >"$artifact_root/rehydration-run.stderr"
  : >"$artifact_root/rehydration-run.stdout"
  close_manifest
  if ! python3 "$repo_root/scripts/check-rehydration-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" --expect-failure >/dev/null; then
    echo "rehydration failure evidence checker rejected the retained tree" >&2
  fi
  echo "rehydration first failure: ${failure_stage}: ${failure_reason}" >&2
  exit 1
fi
negative_artifact="$work_root/negative-protected-image.bin"
negative_native="$artifact_root/negative-native-image.bin"
negative_role="$artifact_root/negative-native-image.json"
negative_record="$artifact_root/negative-rehydration.json"
negative_command_stdout="$artifact_root/negative-command.stdout"
negative_command_stderr="$artifact_root/negative-command.stderr"
cp "$protected_path" "$negative_artifact"
python3 - "$negative_artifact" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[-1] ^= 1
path.write_bytes(data)
PY
set +e
dotnet "$cli" rehydrate-image "$source_path" \
  --artifact "$negative_artifact" \
  --native-image "$negative_native" \
  --role "$negative_role" \
  --record "$negative_record" \
  --unit "$unit" --profile "$profile" \
  --source-sha256 "$source_hash" --request-sha256 "$request_hash" \
  --producer-id "$producer_id" --producer-build-sha256 "$producer_build" \
  --consumer-id "$consumer_id" --consumer-build-sha256 "$consumer_build" \
  --json - >"$negative_command_stdout" 2>"$negative_command_stderr"
negative_status=$?
set -e
negative_native_published=false
negative_loader_invoked=false
if [[ -s "$negative_native" || -s "$negative_role" || "$negative_status" -eq 0 ]]; then
  rm -f -- "$negative_native" "$negative_role"
  negative_rollback_status='failed'
  negative_failure_class='tampered-protected-image-was-accepted'
else
  negative_rollback_status='passed'
  negative_failure_class='ProtectedImageIntegrityMismatch'
fi
python3 - "$artifact_root/negative-rollback.json" "$unit" "$negative_rollback_status" "$negative_failure_class" <<'PY'
import json
import pathlib
import sys
path, unit, rollback, failure_class = sys.argv[1:]
document = {
    "schemaVersion": 1,
    "kind": "strict-chain-negative-witness",
    "status": "passed" if rollback == "passed" else "failed",
    "unitId": unit,
    "stage": "rehydration",
    "failureClass": failure_class,
    "rollbackStatus": rollback,
    "nativeImagePublished": False,
    "loaderInvoked": False,
    "loaderMarkerObserved": False,
    "artifactPath": "negative-protected-image.bin",
    "nativeImagePath": "negative-native-image.bin",
    "loaderMarkerPath": "target.stdout"
}
pathlib.Path(path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cp "$source_path" "$work_root/baseline"
chmod 0755 "$work_root/baseline"
set +e
"$work_root/baseline" >"$artifact_root/baseline.stdout" 2>"$artifact_root/baseline.stderr"
baseline_status=$?
set -e
printf '%s\n' "$baseline_status" >"$artifact_root/baseline.status"

native_helper="$repo_root/native/urprotect-runtime/build/native-image-handoff"
helper_build_status=0
make -C "$repo_root/native/urprotect-runtime" native-image-handoff >"$artifact_root/handoff-build.stdout" 2>"$artifact_root/handoff-build.stderr" || helper_build_status=$?
if [[ "$helper_build_status" -ne 0 || ! -x "$native_helper" ]]; then
  failure_stage='native-handoff'
  failure_reason="native handoff helper build failed with status ${helper_build_status}"
  write_failure_records "$failure_stage" "$failure_reason"
else
  architecture="$(uname -m)"
  if [[ "$architecture" != 'aarch64' && "$architecture" != 'arm64' ]]; then
    failure_stage='native-handoff'
    failure_reason="strict AArch64 native execution requires a native AArch64 host; observed ${architecture}"
    write_failure_records "$failure_stage" "$failure_reason"
  else
    set +e
    timeout --signal=TERM --kill-after=2s 30s "$native_helper" \
      "$native_path" "$(sha256_file "$native_path")" "$(sha256_file "$rehydration_path")" "$handoff_path" \
      "$artifact_root/target.stdout" "$artifact_root/target.stderr" 1048576 \
      -- "$work_root/baseline" >"$artifact_root/handoff.stdout" 2>"$artifact_root/handoff.stderr"
    helper_status=$?
    set -e
    if [[ "$helper_status" -ne 0 || ! -s "$handoff_path" ]]; then
      failure_stage='native-handoff'
      failure_reason="native handoff helper returned status ${helper_status}"
      if [[ ! -s "$handoff_path" ]]; then
        write_failure_records "$failure_stage" "$failure_reason"
      fi
    fi
  fi
fi

# Bind the completed handoff back into the rehydration record. The native role
# is then refreshed against the final record bytes so every stage remains hash-bound.
if [[ -s "$rehydration_path" && -s "$handoff_path" ]]; then
  python3 - "$rehydration_path" "$handoff_path" "$native_role_path" <<'PY'
import hashlib
import json
import pathlib
import os
import tempfile
import sys

rehydration_path, handoff_path, role_path = map(pathlib.Path, sys.argv[1:])
original_rehydration_bytes = rehydration_path.read_bytes()
rehydration = json.loads(original_rehydration_bytes.decode("utf-8"))
handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
handoff_bytes = handoff_path.read_bytes()
rehydration["preHandoffRecordSha256"] = hashlib.sha256(original_rehydration_bytes).hexdigest()
rehydration["handoffRecordSha256"] = hashlib.sha256(handoff_bytes).hexdigest()
rehydration["handoffStatus"] = handoff.get("status")
rehydration_bytes = (json.dumps(rehydration, indent=2, sort_keys=True) + "\n").encode()
fd, temporary = tempfile.mkstemp(prefix=rehydration_path.name + ".", suffix=".tmp", dir=rehydration_path.parent)
os.close(fd)
try:
    pathlib.Path(temporary).write_bytes(rehydration_bytes)
    os.replace(temporary, rehydration_path)
finally:
    pathlib.Path(temporary).unlink(missing_ok=True)

if role_path.is_file():
    role = json.loads(role_path.read_text(encoding="utf-8"))
    role["rehydrationRecordSha256"] = hashlib.sha256(rehydration_bytes).hexdigest()
    role_bytes = (json.dumps(role, indent=2, sort_keys=True) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=role_path.name + ".", suffix=".tmp", dir=role_path.parent)
    os.close(fd)
    try:
        pathlib.Path(temporary).write_bytes(role_bytes)
        os.replace(temporary, role_path)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)
PY
fi
if [[ -n "$failure_stage" && ! -s "$target_loader_path" ]]; then
  python3 - "$artifact_root" "$failure_stage" <<'PY'
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
first_failure = sys.argv[2]
rehydration = json.loads((root / "rehydration.json").read_text(encoding="utf-8"))
native = root / "native-image.bin"
handoff_path = root / "handoff.json"
image_hash = hashlib.sha256(native.read_bytes()).hexdigest() if native.is_file() else None
handoff_hash = hashlib.sha256(handoff_path.read_bytes()).hexdigest() if handoff_path.is_file() else None
(root / "target-loader.json").write_text(json.dumps({
    "schemaVersion": 1, "stage": "target-loader", "status": "not-run",
    "loaderId": "kernel.execveat-at-empty-path", "nativeImageSha256": image_hash,
    "evidenceSha256": handoff_hash, "handoffRecordSha256": handoff_hash,
    "targetStatus": None, "targetSignal": None, "firstFailureStage": first_failure,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(root / "behavioral-oracle.json").write_text(json.dumps({
    "schemaVersion": 1, "stage": "behavioral-oracle", "status": "not-run",
    "oracleId": "fixture.process-oracle.v1", "sourceSha256": rehydration.get("sourceSha256"),
    "nativeImageSha256": image_hash, "comparisonSha256": None,
    "firstFailureStage": first_failure,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

if [[ -z "$failure_stage" ]]; then
  target_loader_status=0
  python3 - "$artifact_root" "$native_path" <<'PY'
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
native = pathlib.Path(sys.argv[2])
handoff_path = root / "handoff.json"
handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
image_hash = hashlib.sha256(native.read_bytes()).hexdigest()
handoff_hash = hashlib.sha256(handoff_path.read_bytes()).hexdigest()
stdout = (root / "target.stdout").read_bytes()
stderr = (root / "target.stderr").read_bytes()
passed = handoff.get("status") == "passed" and handoff.get("execveatStatus") == "passed" and handoff.get("execveatInvoked") is True
stage = {
    "schemaVersion": 1,
    "stage": "target-loader",
    "status": "passed" if passed else "failed",
    "loaderId": "kernel.execveat-at-empty-path",
    "nativeImageSha256": image_hash,
    "evidenceSha256": handoff_hash,
    "handoffRecordSha256": handoff_hash,
    "targetStatus": handoff.get("targetStatus"),
    "targetSignal": handoff.get("targetSignal"),
    "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
    "stderrSha256": hashlib.sha256(stderr).hexdigest(),
    "stdoutBytes": len(stdout),
    "stderrBytes": len(stderr),
    "firstFailureStage": None if passed else "target-loader",
}
(root / "target-loader.json").write_text(json.dumps(stage, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  if [[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$target_loader_path")" != 'passed' ]]; then
    failure_stage='target-loader'
    failure_reason='execveat target-loader stage did not pass'
  fi
fi

if [[ -z "$failure_stage" ]]; then
  target_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["targetStatus"])' "$handoff_path")"
  source_hash="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sourceSha256"])' "$rehydration_path")"
  native_hash="$(sha256_file "$native_path")"
  python3 - "$artifact_root" "$unit" "$baseline_status" "$target_status" "$source_hash" "$native_hash" <<'PY'
import hashlib
import json
import pathlib
import sys
root, unit, baseline_status, target_status, source_hash, native_hash = sys.argv[1:]
root = pathlib.Path(root)
baseline_status = int(baseline_status)
target_status = int(target_status)
baseline_stdout = (root / "baseline.stdout").read_bytes()
target_stdout = (root / "target.stdout").read_bytes()
baseline_stderr = (root / "baseline.stderr").read_bytes()
target_stderr = (root / "target.stderr").read_bytes()
comparison = {
    "schemaVersion": 1,
    "unitId": unit,
    "oracleId": "fixture.process-oracle.v1",
    "sourceSha256": source_hash,
    "nativeImageSha256": native_hash,
    "baselineStatus": baseline_status,
    "targetStatus": target_status,
    "baselineStdoutSha256": hashlib.sha256(baseline_stdout).hexdigest(),
    "targetStdoutSha256": hashlib.sha256(target_stdout).hexdigest(),
    "baselineStderrSha256": hashlib.sha256(baseline_stderr).hexdigest(),
    "targetStderrSha256": hashlib.sha256(target_stderr).hexdigest(),
    "stdoutEqual": baseline_stdout == target_stdout,
    "stderrEqual": baseline_stderr == target_stderr,
    "statusEqual": baseline_status == target_status,
}
canonical = (json.dumps(comparison, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
comparison_hash = hashlib.sha256(canonical).hexdigest()
(root / "behavior-comparison.json").write_bytes(canonical)
passed = comparison["statusEqual"] and comparison["stdoutEqual"] and comparison["stderrEqual"] and baseline_status == 0
record = {
    "schemaVersion": 1,
    "stage": "behavioral-oracle",
    "status": "passed" if passed else "failed",
    "oracleId": "fixture.process-oracle.v1",
    "sourceSha256": source_hash,
    "nativeImageSha256": native_hash,
    "comparisonSha256": comparison_hash,
    "baselineStatus": baseline_status,
    "targetStatus": target_status,
    "stdoutEqual": comparison["stdoutEqual"],
    "stderrEqual": comparison["stderrEqual"],
    "firstFailureStage": None if passed else "behavioral-oracle",
}
(root / "behavioral-oracle.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(root / "behavior-check.status").write_text("0\n" if passed else "1\n", encoding="utf-8")
PY
  if [[ "$(cat "$artifact_root/behavior-check.status")" != '0' ]]; then
    failure_stage='behavioral-oracle'
    failure_reason='frozen baseline and rehydrated Native Image behavior differ'
  fi
fi

python3 - "$artifact_root" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
record = json.loads((root / "rehydration.json").read_text(encoding="utf-8"))
handoff = json.loads((root / "handoff.json").read_text(encoding="utf-8"))
producer = json.loads((root / "stage.json").read_text(encoding="utf-8"))
benchmark = {
    "schemaVersion": 1,
    "unitId": record.get("unitId"),
    "rehydrationCpuMilliseconds": record.get("cpuMilliseconds"),
    "rehydrationDurationMilliseconds": record.get("durationMilliseconds"),
    "producerEmissionDurationMilliseconds": producer.get("emissionDurationMilliseconds"),
    "nativeImageSize": record.get("nativeImageSize"),
    "handoffDurationNanoseconds": handoff.get("targetDurationNanoseconds"),
    "maxRssBytes": handoff.get("maxRssBytes") or record.get("workingSetBytes"),
    "targetStatus": handoff.get("targetStatus"),
    "firstFailureStage": None,
}
(root / "benchmark.json").write_text(json.dumps(benchmark, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if [[ -n "$failure_stage" ]]; then
  printf '%s\n' "$failure_reason" >"$artifact_root/rehydration-run.stderr"
  : >"$artifact_root/rehydration-run.stdout"
  python3 - "$artifact_root/benchmark.json" "$failure_stage" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
document["firstFailureStage"] = sys.argv[2]
path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
else
  : >"$artifact_root/rehydration-run.stdout"
  : >"$artifact_root/rehydration-run.stderr"
fi

close_manifest
set +e
if [[ -n "$failure_stage" ]]; then
  python3 "$repo_root/scripts/check-rehydration-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit" --expect-failure
  checker_status=$?
else
  python3 "$repo_root/scripts/check-rehydration-evidence.py" "$artifact_root" --tier "$tier" --runtime "$runtime" --unit "$unit"
  checker_status=$?
fi
set -e
rm -rf -- "$work_root"
trap - EXIT
if [[ -n "$failure_stage" ]]; then
  echo "rehydration first failure: ${failure_stage}: ${failure_reason}" >&2
  exit 1
fi
exit "$checker_status"
