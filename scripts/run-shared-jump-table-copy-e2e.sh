#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release [--artifact-root PATH] [--unit UNIT]\n' "$0" >&2
}

tier=
root_arg=
unit=runtime.indirect-control.shared-table.glibc.host-context-entry
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --artifact-root) [[ $# -ge 2 ]] || { usage; exit 2; }; root_arg="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { usage; exit 2; }; unit="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo 'invalid shared jump-table tier' >&2; exit 2 ;; esac
case "$(uname -m)" in aarch64|arm64) ;; *) echo 'environment-unavailable: shared jump-table native evidence requires AArch64' >&2; exit 2 ;; esac
[[ "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo 'invalid shared jump-table unit' >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
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

make -C "$native_root" shared-jump-table-fixture host-context-image-handoff \
  >"$root/native-build.stdout" 2>"$root/native-build.stderr"
source_file="$native_root/build/host-context-shared-jump-table-fixture.so"
function_id="$(readelf -Ws "$source_file" | awk '$8 == "urp_entry" && $1 ~ /^[0-9]+:/ && $4 == "FUNC" { sub(":", "", $1); print "dynsym:" $1; exit }')"
[[ "$function_id" =~ ^dynsym:[0-9]+$ ]] || { echo 'shared fixture has no selected urp_entry dynsym' >&2; exit 1; }

PROTECTED_IMAGE_ARTIFACT_ROOT="$positive" "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" --runtime glibc --unit "$unit" --source "$source_file" \
  --function-id "$function_id" --entry-status 91 --producer-id gcc-aarch64-shared-jump-table-fixture \
  >"$root/rehydration.stdout" 2>"$root/rehydration.stderr"

helper="$native_root/build/host-context-image-handoff"
set +e
"$helper" "$positive/source-image.bin" urp_observer "$positive/observer-source-handoff.json" \
  >"$positive/observer-source.stdout" 2>"$positive/observer-source.stderr"
observer_source_status=$?
"$helper" "$positive/native-image.bin" urp_observer "$positive/observer-transformed-handoff.json" \
  >"$positive/observer-transformed.stdout" 2>"$positive/observer-transformed.stderr"
observer_transformed_status=$?
set -e
printf '%s\n' "$observer_source_status" >"$positive/observer-source.process-status"
printf '%s\n' "$observer_transformed_status" >"$positive/observer-transformed.process-status"
[[ "$observer_source_status" -eq 91 && "$observer_transformed_status" -eq 91 ]] || {
  echo "unselected observer handoff differed from expected status 91 (source=$observer_source_status transformed=$observer_transformed_status)" >&2
  exit 1
}

python3 - "$positive" "$unit" "$function_id" "$observer_source_status" "$observer_transformed_status" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
unit, selected_function = sys.argv[2:4]
observer_source_status = int(sys.argv[4])
observer_transformed_status = int(sys.argv[5])
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
python3 "$repo_root/scripts/check-rehydration-evidence.py" "$positive" \
  --tier "$tier" --runtime glibc --unit "$unit"
python3 "$repo_root/scripts/check-shared-jump-table-evidence.py" "$positive" \
  --unit "$unit" --selected-function "$function_id"
printf 'Shared jump-table copy-and-retarget: PASS (selected clone read and unselected observer preserved)\n'
printf 'Shared jump-table artifact root: %s\n' "$root"
