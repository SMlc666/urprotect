#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release [--runtime glibc|musl] [--artifact-root PATH] [--unit UNIT]\n' "$0" >&2
}

tier=
runtime=glibc
root_arg=
unit=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --runtime) [[ $# -ge 2 ]] || { usage; exit 2; }; runtime="$2"; shift 2 ;;
    --artifact-root) [[ $# -ge 2 ]] || { usage; exit 2; }; root_arg="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { usage; exit 2; }; unit="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo 'invalid shared jump-table tier' >&2; exit 2 ;; esac
case "$runtime" in glibc|musl|bionic) ;; *) echo 'invalid shared jump-table runtime' >&2; exit 2 ;; esac
[[ -n "$unit" ]] || unit="runtime.indirect-control.shared-table.${runtime}.host-context-entry"
[[ "$unit" == "runtime.indirect-control.shared-table.${runtime}.host-context-entry" ]] || { echo 'shared jump-table unit does not match the selected runtime' >&2; exit 2; }
case "$(uname -m)" in aarch64|arm64) ;; *) echo 'environment-unavailable: shared jump-table native evidence requires AArch64' >&2; exit 2 ;; esac
[[ "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo 'invalid shared jump-table unit' >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
native_build_dir_relative=build
make_args=()
if [[ "$runtime" == musl ]]; then
  command -v musl-gcc >/dev/null 2>&1 || { echo "environment-unavailable: pinned musl-gcc is required for native shared jump-table evidence" >&2; exit 2; }
  runtime_cc="$(command -v musl-gcc)"
  native_build_dir_relative=build/musl-shared-jump-table
  make_args+=("CC=$runtime_cc" "LD=ld" "HOST_ADAPTER_CFLAGS=-mno-outline-atomics")
elif [[ "$runtime" == bionic ]]; then
  native_build_dir_relative=build/bionic-indirect-control
  [[ -n "${BIONIC_INDIRECT_CONTROL_BUILD_ROOT:-}" ]] || { echo "environment-unavailable: pinned Bionic fixture build root is required" >&2; exit 2; }
  native_build_dir="$(realpath -e -- "$BIONIC_INDIRECT_CONTROL_BUILD_ROOT" 2>/dev/null || true)"
  [[ -n "$native_build_dir" && -d "$native_build_dir" && ! -L "$BIONIC_INDIRECT_CONTROL_BUILD_ROOT" ]] || { echo "Bionic fixture build root is not a real directory" >&2; exit 2; }
else
  native_build_dir="$native_root/$native_build_dir_relative"
fi
if [[ "$runtime" != bionic ]]; then make_args+=("BUILD_DIR=$native_build_dir_relative"); native_build_dir="$native_root/$native_build_dir_relative"; fi
artifact_base="$(realpath -m -- "$repo_root/.artifacts/indirect-control")"
if [[ -z "$root_arg" ]]; then
  root_arg="$artifact_base/shared-copy-${tier}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
root="$(realpath -m -- "$root_arg")"
[[ "$root" == "$artifact_base/"* ]] || { echo 'shared-table evidence root must be under .artifacts/indirect-control' >&2; exit 2; }
[[ ! -e "$root" && ! -L "$root" ]] || { echo "refusing to overwrite existing shared-table evidence root: $root" >&2; exit 2; }
mkdir -p "$root"
positive="$root/$unit"
mkdir -p "$positive"
if [[ "$runtime" == bionic ]]; then
  for diagnostic in native-build.command.txt native-build.stdout native-build.stderr; do
    [[ -f "$native_build_dir/$diagnostic" && ! -L "$native_build_dir/$diagnostic" ]] || { echo "Bionic native build is missing regular non-symlink diagnostic $diagnostic" >&2; exit 1; }
    cp -- "$native_build_dir/$diagnostic" "$root/$diagnostic"
  done
  if ! native_build_status="$(python3 "$repo_root/scripts/parse-native-build-status.py" "$native_build_dir/native-build.status")"; then
    echo "refusing Bionic shared-fixture continuation without an exact canonical native-build status" >&2
    exit 1
  fi
  printf '%s\n' "$native_build_status" >"$root/native-build.status" || exit 1
else
  native_build_command=(make -C "$native_root" "${make_args[@]}" shared-jump-table-fixture host-context-image-handoff)
  {
    printf 'cwd=%s\n' "$native_root"
    printf 'runtime=%s\n' "$runtime"
    printf 'argv='
    printf '%q ' "${native_build_command[@]}"
    printf '\n'
  } >"$root/native-build.command.txt"
  native_build_status=0
  "${native_build_command[@]}" >"$root/native-build.stdout" 2>"$root/native-build.stderr" || native_build_status=$?
  printf '%s\n' "$native_build_status" >"$root/native-build.status"
fi
if [[ "$native_build_status" != "0" ]]; then
  printf 'shared jump-table native fixture/helper build failed with status %s\n' "$native_build_status" >&2
  exit "$native_build_status"
fi
if [[ "$runtime" == bionic ]]; then
  [[ -n "${BIONIC_RUNTIME_RESULT:-}" && -f "$BIONIC_RUNTIME_RESULT" && ! -L "$BIONIC_RUNTIME_RESULT" ]] || { echo "Bionic runtime provenance result is missing" >&2; exit 2; }
  cp -- "$BIONIC_RUNTIME_RESULT" "$positive/bionic-runtime-environment.json" || exit 1
  chmod a+rwx "$positive" || exit 1
fi
source_file="$native_build_dir/host-context-shared-jump-table-fixture.so"
function_id="$(readelf -Ws "$source_file" | awk '$8 == "urp_entry" && $1 ~ /^[0-9]+:/ && $4 == "FUNC" { sub(":", "", $1); print "dynsym:" $1; exit }')"
[[ "$function_id" =~ ^dynsym:[0-9]+$ ]] || { echo 'shared fixture has no selected urp_entry dynsym' >&2; exit 1; }

PROTECTED_IMAGE_ARTIFACT_ROOT="$positive" "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" --runtime "$runtime" --unit "$unit" --source "$source_file" \
  --function-id "$function_id" --entry-status 91 --producer-id gcc-aarch64-shared-jump-table-fixture \
  --native-build-dir "$native_build_dir_relative" \
  >"$root/rehydration.stdout" 2>"$root/rehydration.stderr"

if [[ "$runtime" == bionic ]]; then
  helper="$repo_root/scripts/run-bionic-host-context-handoff.sh"
else
  helper="$native_build_dir/host-context-image-handoff"
fi
observer_source_identity_args=()
observer_transformed_identity_args=()
if [[ "$runtime" == musl || "$runtime" == bionic ]]; then
  mkdir -p "$positive/runtime-identity/observer-source" "$positive/runtime-identity/observer-transformed"
  if [[ "$runtime" == bionic ]]; then chmod a+rwx "$positive" "$positive/runtime-identity" "$positive/runtime-identity/observer-source" "$positive/runtime-identity/observer-transformed"; fi
  observer_source_identity_args=("$positive/runtime-identity/observer-source" runtime-identity/observer-source source)
  observer_transformed_identity_args=("$positive/runtime-identity/observer-transformed" runtime-identity/observer-transformed target)
fi
if [[ "$runtime" == bionic ]]; then
  python3 "$repo_root/scripts/capture-bionic-handoff.py" \
    --root "$positive" --label observer-source \
    --record "$positive/observer-source-handoff.json" --expected-status 91 -- \
    "$helper" "$BIONIC_TERMUX_IMAGE" "$positive/source-image.bin" urp_observer \
    "$positive/observer-source-handoff.json" "${observer_source_identity_args[@]}"
  observer_source_status="$(cat "$positive/observer-source.process-status")"
  python3 "$repo_root/scripts/capture-bionic-handoff.py" \
    --root "$positive" --label observer-transformed \
    --record "$positive/observer-transformed-handoff.json" --expected-status 91 -- \
    "$helper" "$BIONIC_TERMUX_IMAGE" "$positive/native-image.bin" urp_observer \
    "$positive/observer-transformed-handoff.json" "${observer_transformed_identity_args[@]}"
  observer_transformed_status="$(cat "$positive/observer-transformed.process-status")"
else
  set +e
  "$helper" "$positive/source-image.bin" urp_observer "$positive/observer-source-handoff.json" \
    "${observer_source_identity_args[@]}" \
    >"$positive/observer-source.stdout" 2>"$positive/observer-source.stderr"
  observer_source_status=$?
  "$helper" "$positive/native-image.bin" urp_observer "$positive/observer-transformed-handoff.json" \
    "${observer_transformed_identity_args[@]}" \
    >"$positive/observer-transformed.stdout" 2>"$positive/observer-transformed.stderr"
  observer_transformed_status=$?
  set -e
  printf '%s\n' "$observer_source_status" >"$positive/observer-source.process-status"
  printf '%s\n' "$observer_transformed_status" >"$positive/observer-transformed.process-status"
fi
[[ "$observer_source_status" -eq 91 && "$observer_transformed_status" -eq 91 ]] || {
  echo "unselected observer handoff differed from expected status 91 (source=$observer_source_status transformed=$observer_transformed_status)" >&2
  exit 1
}

python3 - "$positive" "$unit" "$function_id" "$runtime" "$observer_source_status" "$observer_transformed_status" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
unit, selected_function, runtime = sys.argv[2:5]
observer_source_status = int(sys.argv[5])
observer_transformed_status = int(sys.argv[6])
def sha(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()
def read(name):
    return json.loads((root / name).read_text(encoding="utf-8"))
def stream_facts(prefix, suffix):
    data = (root / f"{prefix}.{suffix}").read_bytes()
    label = "".join(part.title() for part in prefix.split("-"))
    label = label[0].lower() + label[1:]
    return {f"{label}{suffix.title()}Sha256": hashlib.sha256(data).hexdigest(),
            f"{label}{suffix.title()}Size": len(data)}
layout = read("rehydration.json").get("layoutEvidence", {})
clones = layout.get("jumpTableClones", [])
if len(clones) != 1:
    raise SystemExit("shared-table runner expected one retained physical table clone")
clone = clones[0]
report = {
    "schemaVersion": 2,
    "runtime": runtime,
    "unitId": unit,
    "selectedFunction": selected_function,
    "selectedEntryStatus": read("handoff.json").get("entryStatus"),
    "observerSourceStatus": read("observer-source-handoff.json").get("entryStatus"),
    "observerTransformedStatus": read("observer-transformed-handoff.json").get("entryStatus"),
    "observerSourceProcessStatus": observer_source_status,
    "observerTransformedProcessStatus": observer_transformed_status,
    "observerSourceProcessStatusSha256": sha("observer-source.process-status"),
    "observerTransformedProcessStatusSha256": sha("observer-transformed.process-status"),
    "observerSourceNativeImageSha256": sha("source-image.bin"),
    "observerTransformedNativeImageSha256": sha("native-image.bin"),
    "observerSourceReleaseStatus": read("observer-source-handoff.json").get("releaseStatus"),
    "observerTransformedReleaseStatus": read("observer-transformed-handoff.json").get("releaseStatus"),
    "selectedSourceHandoffSha256": sha("source-handoff.json"),
    "selectedTransformedHandoffSha256": sha("handoff.json"),
    "observerSourceHandoffSha256": sha("observer-source-handoff.json"),
    "observerTransformedHandoffSha256": sha("observer-transformed-handoff.json"),
    "sourceTableUnchanged": True,
    "selectedConsumerReadsClone": True,
    "unselectedObserverUsesOriginalTable": True,
    **stream_facts("observer-source", "stdout"),
    **stream_facts("observer-source", "stderr"),
    **stream_facts("observer-transformed", "stdout"),
    **stream_facts("observer-transformed", "stderr"),
    "clone": {
        "tableIdentity": clone.get("tableIdentity"),
        "sourceTableRange": clone.get("sourceTableRange"),
        "outputRange": clone.get("outputRange"),
        "permissions": clone.get("permissions"),
        "ownership": clone.get("ownership"),
        "rewritePolicy": clone.get("rewritePolicy"),
    },
}
(root / "shared-table-behavior.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(
  cd "$positive"
  find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum
) >"$positive/SHA256SUMS"
rehydration_checker_args=(--tier "$tier" --runtime "$runtime" --unit "$unit")
shared_checker_args=(--unit "$unit" --selected-function "$function_id" --runtime "$runtime")
if [[ "$runtime" == musl || "$runtime" == bionic ]]; then rehydration_checker_args+=(--require-runtime-identity); fi
python3 "$repo_root/scripts/check-rehydration-evidence.py" "$positive" \
  "${rehydration_checker_args[@]}"
python3 "$repo_root/scripts/check-shared-jump-table-evidence.py" "$positive" \
  "${shared_checker_args[@]}"
printf 'Shared jump-table copy-and-retarget: PASS (selected clone read and unselected observer preserved)\n'
printf 'Shared jump-table artifact root: %s\n' "$root"
