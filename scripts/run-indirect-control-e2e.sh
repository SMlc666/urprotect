#!/usr/bin/env bash
set -u -o pipefail

tier=
runtime=glibc
unit=
artifact_root_arg=
reuse_positive_root_arg=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { echo "missing --tier value" >&2; exit 2; }; tier="$2"; shift 2 ;;
    --runtime) [[ $# -ge 2 ]] || { echo "missing --runtime value" >&2; exit 2; }; runtime="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { echo "missing --unit value" >&2; exit 2; }; unit="$2"; shift 2 ;;
    --artifact-root) artifact_root_arg="$2"; shift 2 ;;
    --reuse-positive-root) reuse_positive_root_arg="$2"; shift 2 ;;
    *) echo "usage: $0 --tier pr|nightly|release [--runtime glibc|musl] [--unit UNIT] [--artifact-root PATH] [--reuse-positive-root PATH]" >&2; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid jump-table tier" >&2; exit 2 ;; esac
case "$runtime" in glibc|musl) ;; *) echo "invalid jump-table runtime" >&2; exit 2 ;; esac
if [[ -z "$unit" ]]; then unit="runtime.indirect-control.jump-table.${runtime}.host-context-entry"; fi
if [[ ! "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then echo "invalid jump-table evidence unit" >&2; exit 2; fi
if [[ "$runtime" == musl && -n "$reuse_positive_root_arg" ]]; then echo "musl positive execution cannot reuse an existing evidence root" >&2; exit 2; fi
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: jump-table native evidence requires AArch64" >&2; exit 2 ;; esac
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
native_build_dir_relative=build
make_args=()
if [[ "$runtime" == musl ]]; then
  command -v musl-gcc >/dev/null 2>&1 || { echo "environment-unavailable: pinned musl-gcc is required for native musl jump-table evidence" >&2; exit 2; }
  runtime_cc="$(command -v musl-gcc)"
  native_build_dir_relative=build/musl-indirect-control
  make_args+=("CC=$runtime_cc" "LD=ld")
fi
make_args+=("BUILD_DIR=$native_build_dir_relative")
native_build_dir="$native_root/$native_build_dir_relative"
artifact_base="$(realpath -m -- "$repo_root/.artifacts/indirect-control")"
if [[ -n "$artifact_root_arg" ]]; then
  root="$(realpath -m -- "$artifact_root_arg")"
  [[ "$root" == "$artifact_base/"* ]] || { echo "indirect evidence root must be under .artifacts/indirect-control" >&2; exit 2; }
else
  root="$artifact_base/$tier"
fi
[[ ! -e "$root" && ! -L "$root" ]] || { echo "refusing to overwrite existing indirect evidence root: $root" >&2; exit 2; }
native_build_diagnostics_root="${root}.native-build-diagnostics"
[[ ! -e "$native_build_diagnostics_root" && ! -L "$native_build_diagnostics_root" ]] || {
  echo "refusing to overwrite existing native build diagnostics root: $native_build_diagnostics_root" >&2
  exit 2
}
positive="$root/$unit"
mkdir -p "$positive" "$native_build_diagnostics_root" || exit 1
native_build_command=(make -C "$native_root" "${make_args[@]}" jump-table-fixture jump-table-index-clobber-fixture external-jump-table-fixture)
{
  printf 'cwd=%s\n' "$native_root"
  printf 'runtime=%s\n' "$runtime"
  printf 'argv='
  printf '%q ' "${native_build_command[@]}"
  printf '\n'
} >"$native_build_diagnostics_root/native-build.command.txt" || exit 1
native_build_status=0
"${native_build_command[@]}" \
  >"$root/native-build.stdout" 2>"$root/native-build.stderr" || native_build_status=$?
printf '%s\n' "$native_build_status" >"$native_build_diagnostics_root/native-build.status" || exit 1
if [[ "$native_build_status" -ne 0 ]]; then
  printf 'native fixture build failed at native-build with status %s\n' "$native_build_status" >&2
  exit "$native_build_status"
fi
source_file="$native_build_dir/host-context-jump-table-fixture.so"
function_id="$(readelf -Ws "$source_file" | awk '$8 == "urp_entry" && $1 ~ /^[0-9]+:/ && $4 == "FUNC" { sub(":", "", $1); print "dynsym:" $1; exit }')"
[[ -n "$function_id" ]] || exit 1

if [[ -n "$reuse_positive_root_arg" ]]; then
  reuse_root="$(realpath -e -- "$reuse_positive_root_arg")" || exit 1
  [[ "$reuse_root" == "$artifact_base/"* ]] || { echo "reused positive evidence root must be under .artifacts/indirect-control" >&2; exit 2; }
  reused_positive="$reuse_root/$unit"
  [[ -f "$reused_positive/SHA256SUMS" ]] || { echo "reused positive evidence lacks its closed inner manifest" >&2; exit 1; }
  cp -a -- "$reused_positive/." "$positive/" || exit 1
  python3 - "$root" "$positive" "$reuse_root" "$unit" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
positive = pathlib.Path(sys.argv[2])
origin = pathlib.Path(sys.argv[3])
unit = sys.argv[4]
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def inventory(directory):
    return {
        path.relative_to(directory).as_posix(): sha(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }
origin_positive = origin / unit
origin_inventory = inventory(origin_positive)
copy_inventory = inventory(positive)
if origin_inventory != copy_inventory:
    raise SystemExit("reused positive evidence copy differs from the independently accepted root")
record = {
    "schemaVersion": 1,
    "unitId": unit,
    "reuseMode": "existing-schema-2-positive-evidence-copy",
    "positiveExecutionRerun": False,
    "sourceEvidenceRoot": str(origin),
    "sourceEvidenceManifestSha256": sha(origin / "SHA256SUMS"),
    "positiveFiles": copy_inventory,
}
(root / "positive-reuse.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
else
rehydration_status=0
URP_NATIVE_BUILD_DIAGNOSTICS_ROOT="$native_build_diagnostics_root" \
  PROTECTED_IMAGE_ARTIFACT_ROOT="$positive" "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" --runtime "$runtime" --native-build-dir "$native_build_dir_relative" --require-runtime-identity --unit "$unit" --source "$source_file" \
  --function-id "$function_id" --entry-status 91 --producer-id gcc-aarch64-jump-table-fixture \
  >"$root/rehydration.stdout" 2>"$root/rehydration.stderr" || rehydration_status=$?
if [[ "$rehydration_status" -ne 0 ]]; then
  printf 'HostContext rehydration runner failed with status %s\n' "$rehydration_status" >&2
  exit "$rehydration_status"
fi

readelf -hW -lW -SW -rW -Ws "$positive/source-image.bin" >"$positive/source-readelf.txt" || exit 1
readelf -hW -lW -SW -rW "$positive/native-image.bin" >"$positive/native-readelf.txt" || exit 1

python3 - "$positive" "$unit" "$function_id" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
def read_json(name):
    return json.loads((root / name).read_text(encoding="utf-8"))
def sha(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()

source_handoff = read_json("source-handoff.json")
target_handoff = read_json("handoff.json")
rehydration = read_json("rehydration.json")
layout = rehydration.get("layoutEvidence", {})
source_status = source_handoff.get("processStatus")
target_status = target_handoff.get("processStatus")
source_entry_status = source_handoff.get("entryStatus")
target_entry_status = target_handoff.get("entryStatus")
streams = {
    name: (root / name).read_bytes()
    for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr")
}
if max(map(len, streams.values())) > 1024 * 1024:
    raise SystemExit("jump-table baseline/transformed streams exceed the evidence bound")
if source_entry_status != 91 or target_entry_status != 91:
    raise SystemExit("jump-table source/transformed entry did not validate the complete case-result trace")
if source_status != 91 or target_status != 91:
    raise SystemExit("jump-table source/transformed process status differs from the declared case oracle")
if not all(streams["baseline." + suffix] == streams["target." + suffix] for suffix in ("stdout", "stderr")):
    raise SystemExit("jump-table source/transformed stdout or stderr differs")

case_indices = [0, 1, 2, 3]
case_results = [17, 103, -7, 91]
case_symbol_names = [f"urp_jump_table_case{index}" for index in case_indices]
symbol_pattern = __import__("re").compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+NOTYPE\s+GLOBAL\s+DEFAULT\s+\S+\s+(urp_jump_table_case[0-3])$"
)
source_symbols = {}
for line in (root / "source-readelf.txt").read_text(encoding="utf-8").splitlines():
    match = symbol_pattern.match(line)
    if match:
        address = int(match.group(1), 16)
        name = match.group(2)
        if name in source_symbols and source_symbols[name] != address:
            raise SystemExit(f"jump-table case symbol {name} has inconsistent addresses")
        source_symbols[name] = address
if set(source_symbols) != set(case_symbol_names):
    raise SystemExit("jump-table target symbols are incomplete in the retained source ELF report")
trace_value = 0
for result in case_results:
    trace_value = ((trace_value << 8) | (result & 0xff)) & 0xffffffff
edits = layout.get("jumpTableEdits", [])
rewritten_target_offsets = [
    int.from_bytes(__import__("base64").b64decode(edit["bytes"], validate=True), "little", signed=True)
    for edit in edits
]
record = {
    "schemaVersion": 2,
    "unitId": sys.argv[2],
    "selectedFunction": sys.argv[3],
    "sourceSha256": sha("source-image.bin"),
    "protectedSha256": sha("protected-image.bin"),
    "nativeSha256": sha("native-image.bin"),
    "sourceHandoffSha256": sha("source-handoff.json"),
    "targetHandoffSha256": sha("handoff.json"),
    "baselineStatus": source_status,
    "transformedStatus": target_status,
    "baselineEntryStatus": source_entry_status,
    "transformedEntryStatus": target_entry_status,
    "baselineStdoutSha256": sha("baseline.stdout"),
    "baselineStderrSha256": sha("baseline.stderr"),
    "transformedStdoutSha256": sha("target.stdout"),
    "transformedStderrSha256": sha("target.stderr"),
    "statusEqual": source_status == target_status
        and source_entry_status == target_entry_status
        and source_handoff.get("status") == target_handoff.get("status") == "passed"
        and source_handoff.get("releaseStatus") == target_handoff.get("releaseStatus") == "passed",
    "stdoutEqual": streams["baseline.stdout"] == streams["target.stdout"],
    "stderrEqual": streams["baseline.stderr"] == streams["target.stderr"],
    "jumpTableEditCount": len(edits),
    "addressMapBindings": len(layout.get("addressMap", [])),
    "targetResolutionMode": "bounded-relative-table",
    "targetSelectionFacts": {
        "caseIndices": case_indices,
        "caseResults": case_results,
        "caseTargetSymbols": case_symbol_names,
        "sourceTargetAddresses": [source_symbols[name] for name in case_symbol_names],
        "rewrittenTargetOffsets": rewritten_target_offsets,
        "expectedTraceValue": f"0x{trace_value:08x}",
        "traceAcceptanceEntryStatus": 91,
        "observation": "urp_entry returns 91 only after the in-function 0,1,2,3 table walk matches all four exact result bytes",
    },
    "firstFailureStage": None,
}
(root / "jump-table-behavior.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(cd "$positive" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$positive/SHA256SUMS" || exit 1
python3 "$repo_root/scripts/check-rehydration-evidence.py" "$positive" \
  --tier "$tier" --runtime "$runtime" --require-runtime-identity --unit "$unit" || exit 1
fi

run_negative() {
  local negative_name="$1"
  local negative_source="$2"
  local expected_message="$3"
  local mutation_mode="${4:-}"
  local negative="$root/$negative_name"
  local negative_unit="$unit.$negative_name"
  mkdir -p "$negative" || return 1
  if [[ -n "$mutation_mode" ]]; then
    cp -- "$negative_source" "$negative/input-image.bin" || return 1
    python3 "$repo_root/scripts/mutate-indirect-jump-table.py" \
      --input "$negative/input-image.bin" --output "$negative/source-image.bin" \
      --report "$negative/mutation.json" --mode "$mutation_mode" || return 1
  else
    cp -- "$negative_source" "$negative/source-image.bin" || return 1
  fi
  local negative_function_id
  negative_function_id="$(readelf -Ws "$negative/source-image.bin" | awk '$8 == "urp_entry" && $1 ~ /^[0-9]+:/ && $4 == "FUNC" { sub(":", "", $1); print "dynsym:" $1; exit }')"
  [[ -n "$negative_function_id" ]] || return 1
  local source_sha
  source_sha="$(sha256sum "$negative/source-image.bin" | cut -d' ' -f1)"
  if [[ "$negative_name" == "negative-external-table" ]]; then
    readelf -hW -lW -rW -Ws "$negative/source-image.bin" >"$negative/external-table-readelf.txt" || return 1
    python3 "$repo_root/scripts/check-indirect-control-evidence.py" \
      --inspect-external-table "$negative/source-image.bin" --selected-function "$negative_function_id" \
      >"$negative/external-table-facts.json" || return 1
  fi
  local producer_assembly="$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
  local producer_command=(
    dotnet "$producer_assembly" protect-image "$negative/source-image.bin"
    --artifact "$negative/protected-image.bin" --role "$negative/protected-image.json"
    --manifest "$negative/producer-manifest.txt" --stage "$negative/stage.json"
    --unit "$negative_unit" --profile host-context-entry --producer-id "gcc-aarch64-jump-table-$negative_name"
    --rehydrator urprotect.rehydrator.v1 --source-sha256 "$source_sha"
    --function-id "$negative_function_id" --pass control-flow-flattening --json -
  )
  python3 - "$negative/producer-command.json" "$source_sha" "$negative_function_id" "$negative_unit" "${producer_command[@]}" <<'PY'
import json
import os
import pathlib
import sys

record = {
    "schemaVersion": 1,
    "workingDirectory": os.getcwd(),
    "sourceSha256": sys.argv[2],
    "selectedFunction": sys.argv[3],
    "unitId": sys.argv[4],
    "argv": sys.argv[5:],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  set +e
  "${producer_command[@]}" >"$negative/producer.stdout" 2>"$negative/producer.stderr"
  local producer_status=$?
  set -e
  printf '%s\n' "$producer_status" >"$negative/producer-exit-status.txt"
  if [[ "$producer_status" -eq 0 \
      || -e "$negative/protected-image.bin" || -e "$negative/protected-image.json" \
      || -e "$negative/native-image.bin" || -e "$negative/native-image.json" \
      || -e "$negative/handoff.json" || -e "$negative/source-handoff.json" ]]; then
    echo "jump-table negative published an image or unexpectedly succeeded: $negative_name" >&2
    return 1
  fi
  python3 - "$negative" "$negative_unit" "$producer_status" "$expected_message" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
unit = sys.argv[2]
exit_status = int(sys.argv[3])
expected_message = sys.argv[4]
producer = json.loads((root / "producer.stdout").read_text(encoding="utf-8"))
stage = producer.get("stage")
if producer.get("success") is not False or not isinstance(stage, dict):
    raise SystemExit("negative producer did not emit a failed structured report")
if stage.get("status") != "failed" or stage.get("firstFailureStage") != "protected-image-producer":
    raise SystemExit("negative producer did not fail at the Protected Image producer stage")
diagnostics = producer.get("diagnostics", [])
if not any(item.get("code") == "IndirectTargetUnresolved" and item.get("message") == expected_message for item in diagnostics):
    raise SystemExit("negative producer did not emit the declared indirect-target diagnostic")
actual_stage = json.loads((root / "stage.json").read_text(encoding="utf-8"))
if actual_stage != stage:
    raise SystemExit("retained negative stage differs from the producer's structured output")
sha = lambda name: hashlib.sha256((root / name).read_bytes()).hexdigest()
record = {
    "schemaVersion": 1,
    "unitId": unit,
    "status": "passed",
    "producerExitStatus": exit_status,
    "producerStdoutSha256": sha("producer.stdout"),
    "producerStderrSha256": sha("producer.stderr"),
    "producerCommandSha256": sha("producer-command.json"),
    "sourceSha256": sha("source-image.bin"),
    "protectedImagePublished": False,
    "nativeImagePublished": False,
    "loaderInvoked": False,
    "expectedDiagnosticFamily": "IndirectTargetUnresolved",
    "expectedDiagnosticMessage": expected_message,
    "firstFailureStage": stage["firstFailureStage"],
}
if (root / "mutation.json").is_file():
    record["inputSourceSha256"] = sha("input-image.bin")
    record["mutationSha256"] = sha("mutation.json")
if (root / "external-table-facts.json").is_file():
    record["externalTableFactsSha256"] = sha("external-table-facts.json")
(root / "negative-result.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

run_negative \
  negative-malformed-table \
  "$source_file" \
  "A signed relative jump-table entry resolves outside the selected function closure." \
  out-of-closure || exit 1
run_negative \
  negative-out-of-range-target \
  "$source_file" \
  "A signed relative jump-table entry resolves outside an executable PT_LOAD range." \
  out-of-executable-range || exit 1
run_negative \
  negative-index-clobber \
  "$native_build_dir/host-context-jump-table-index-clobber-fixture.so" \
  "The checked jump-table index register W0/X0 is overwritten between B.HI and the indexed LDRSW." || exit 1
run_negative \
  negative-external-table \
  "$native_build_dir/host-context-external-jump-table-fixture.so" \
  "The selected instruction does not match the promoted relative jump-table family." || exit 1

(cd "$root" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$root/SHA256SUMS" || exit 1
python3 "$repo_root/scripts/check-indirect-control-evidence.py" "$root" --tier "$tier" --runtime "$runtime" --require-runtime-identity --unit "$unit"
printf 'Indirect jump-table HostContext evidence: PASS (all four table cases and four fail-closed negatives)\n'
