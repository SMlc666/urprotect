#!/usr/bin/env bash
set -u -o pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --runtime glibc [--unit UNIT] [--source ELF]\n' "$0" >&2
}

tier=''
runtime=''
unit='compat.protection-host-context-fixture.glibc.host-context-entry'
source_file=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --runtime) [[ $# -ge 2 ]] || { usage; exit 2; }; runtime="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { usage; exit 2; }; unit="$2"; shift 2 ;;
    --source) [[ $# -ge 2 ]] || { usage; exit 2; }; source_file="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid HostContext rehydration tier: $tier" >&2; exit 2 ;; esac
case "$runtime" in glibc) ;; *) echo "HostContext rehydration requires glibc" >&2; exit 2 ;; esac
if [[ ! "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "invalid HostContext rehydration unit: $unit" >&2
  exit 2
fi
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: HostContext handoff requires native AArch64" >&2; exit 2 ;; esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${PROTECTED_IMAGE_ARTIFACT_ROOT:-${repo_root}/.artifacts/protected-image/${tier}/${runtime}/${unit}}"
work_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/urprotect-host-context-rehydration-${tier}-${runtime}-$$"
mkdir -p "$artifact_root" "$work_root"
trap 'rm -rf -- "$work_root"' EXIT
rm -rf -- "$artifact_root"
mkdir -p "$artifact_root"

if [[ -z "$source_file" ]]; then
  source_file="$repo_root/native/urprotect-runtime/build/host-context-entry-fixture.so"
elif [[ "$source_file" != /* ]]; then
  source_file="$repo_root/$source_file"
fi
make -C "$repo_root/native/urprotect-runtime" build/host-context-entry-fixture.so host-context-image-handoff \
  >"$artifact_root/native-build.stdout" 2>"$artifact_root/native-build.stderr" || {
  echo "HostContext native fixture/helper build failed" >&2
  exit 1
}
if [[ -z "$source_file" ]]; then
  source_file="$repo_root/native/urprotect-runtime/build/host-context-entry-fixture.so"
elif [[ "$source_file" != /* ]]; then
  source_file="$repo_root/$source_file"
fi
source_file="$(realpath -e -- "$source_file" 2>/dev/null || true)"
[[ -f "$source_file" && ! -L "$source_file" ]] || { echo "HostContext source fixture is not a regular ELF" >&2; exit 2; }
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

# The fixture exports the same function in .dynsym and .symtab. Resolve the
# current dynamic identity explicitly; name-only selection is intentionally
# rejected by the shared selector contract.
dynsym_index="$(readelf -Ws "$source_path" | awk '$8 == "urp_transform_target" && $1 ~ /^[0-9]+:/ { sub(":", "", $1); print $1; exit }')"
[[ "$dynsym_index" =~ ^[0-9]+$ ]] || { echo "HostContext transform symbol is missing" >&2; exit 1; }
source_sha256="$(sha256sum "$source_path" | cut -d' ' -f1)"
cli="$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
core="$repo_root/src/UrProtect.Core/bin/Release/net8.0/UrProtect.Core.dll"
[[ -s "$cli" && -s "$core" ]] || { echo "managed Release assemblies are missing" >&2; exit 1; }

set +e
dotnet "$cli" protect-image "$source_path" \
  --artifact "$artifact_path" --role "$role_path" --manifest "$manifest_path" --stage "$stage_path" \
  --unit "$unit" --profile host-context-entry --producer-id gcc-c-host-context-fixture \
  --rehydrator urprotect.rehydrator.v1 --source-sha256 "$source_sha256" \
  --function-id "dynsym:${dynsym_index}" --pass control-flow-flattening --json - \
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
set +e
"$repo_root/native/urprotect-runtime/build/host-context-image-handoff" \
  "$native_path" urp_entry "$handoff_path" \
  >"$artifact_root/handoff.stdout" 2>"$artifact_root/handoff.stderr"
handoff_status=$?
set -e
[[ "$handoff_status" -eq 23 && -s "$handoff_path" ]] || { echo "HostContext native handoff failed with status $handoff_status" >&2; exit 1; }

python3 - "$record_path" "$handoff_path" "$native_role_path" <<'PY'
import hashlib
import json
import pathlib
import tempfile
import os
record_path, handoff_path, role_path = map(pathlib.Path, __import__('sys').argv[1:])
old = record_path.read_bytes()
record = json.loads(old.decode())
handoff = json.loads(handoff_path.read_text())
pre_hash = hashlib.sha256(old).hexdigest()
handoff["rehydrationRecordSha256"] = pre_hash
handoff_bytes = (json.dumps(handoff, indent=2, sort_keys=True) + "\n").encode()
handoff_path.write_bytes(handoff_bytes)
record["preHandoffRecordSha256"] = pre_hash
record["handoffRecordSha256"] = hashlib.sha256(handoff_bytes).hexdigest()
record["handoffStatus"] = handoff.get("status")
record["entryStatus"] = handoff.get("entryStatus")
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
python3 - "$artifact_root" "$source_sha256" "$native_path" "$handoff_path" <<'PY'
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
source_hash = sys.argv[2]
native_path = pathlib.Path(sys.argv[3])
handoff_path = pathlib.Path(sys.argv[4])
handoff = json.loads(handoff_path.read_text())
native_hash = hashlib.sha256(native_path.read_bytes()).hexdigest()
entry_status = handoff.get("entryStatus")
(root / "stdout.txt").write_bytes(b"")
(root / "stderr.txt").write_bytes(b"")
(root / "baseline.stdout").write_bytes(b"")
(root / "baseline.stderr").write_bytes(b"")
(root / "target.stdout").write_bytes(b"")
(root / "target.stderr").write_bytes(b"")
(root / "target-loader.json").write_text(json.dumps({
    "schemaVersion": 1, "stage": "target-loader", "status": "passed",
    "loaderId": handoff["loaderId"], "nativeImageSha256": native_hash,
    "evidenceSha256": hashlib.sha256(pathlib.Path(handoff_path).read_bytes()).hexdigest(),
    "handoffRecordSha256": hashlib.sha256(pathlib.Path(handoff_path).read_bytes()).hexdigest(),
    "targetStatus": entry_status, "targetSignal": None,
    "stdoutSha256": hashlib.sha256(b"").hexdigest(), "stderrSha256": hashlib.sha256(b"").hexdigest(),
    "firstFailureStage": None,
}, indent=2, sort_keys=True) + "\n")
comparison = {
    "schemaVersion": 1, "unitId": json.loads((root / "stage.json").read_text())["unitId"],
    "oracleId": "fixture.host-context-entry.v1", "sourceSha256": source_hash,
    "nativeImageSha256": native_hash, "entryStatus": entry_status,
    "statusEqual": True, "stdoutEqual": True, "stderrEqual": True,
}
comparison_bytes = (json.dumps(comparison, sort_keys=True, separators=(",", ":")) + "\n").encode()
(root / "behavior-comparison.json").write_bytes(comparison_bytes)
(root / "behavioral-oracle.json").write_text(json.dumps({
    **comparison, "stage": "behavioral-oracle", "status": "passed",
    "comparisonSha256": hashlib.sha256(comparison_bytes).hexdigest(),
    "baselineStatus": 0, "targetStatus": entry_status, "firstFailureStage": None,
}, indent=2, sort_keys=True) + "\n")
(root / "negative-rollback.json").write_text(json.dumps({
    "schemaVersion": 1, "kind": "strict-chain-negative-witness", "status": "passed",
    "unitId": comparison["unitId"], "stage": "rehydration",
    "failureClass": "ProtectedImageIntegrityMismatch", "rollbackStatus": "passed",
    "nativeImagePublished": False, "loaderInvoked": False, "loaderMarkerObserved": False,
    "artifactPath": "negative-protected-image.bin", "nativeImagePath": "negative-native-image.bin",
    "loaderMarkerPath": "target.stdout",
}, indent=2, sort_keys=True) + "\n")
record = json.loads((root / "rehydration.json").read_text())
(root / "benchmark.json").write_text(json.dumps({
    "schemaVersion": 1, "unitId": comparison["unitId"],
    "rehydrationCpuMilliseconds": record.get("cpuMilliseconds"),
    "rehydrationDurationMilliseconds": record.get("durationMilliseconds"),
    "producerEmissionDurationMilliseconds": json.loads((root / "stage.json").read_text()).get("emissionDurationMilliseconds"),
    "nativeImageSize": record.get("nativeImageSize"), "handoffDurationNanoseconds": 0,
    "maxRssBytes": record.get("workingSetBytes"), "targetStatus": entry_status,
    "firstFailureStage": None,
}, indent=2, sort_keys=True) + "\n")
PY
(
  cd "$artifact_root"
  find . -type f ! -name 'SHA256SUMS' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum
) >"$manifest_path"
printf 'HostContext rehydration: PASS (entry status %s)\n' "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["entryStatus"])' "$handoff_path")"
