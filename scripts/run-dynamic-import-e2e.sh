#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release [--artifact-root PATH]\n' "$0" >&2
}

tier=pr
artifact_root_arg=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --artifact-root) [[ $# -ge 2 ]] || { usage; exit 2; }; artifact_root_arg="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid dynamic-import evidence tier: $tier" >&2; exit 2 ;; esac
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: dynamic-import HostContext evidence requires native AArch64" >&2; exit 2 ;; esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
unit='runtime.host-context.dynamic-import.glibc.host-context-entry'
artifact_base="$(realpath -m -- "$repo_root/.artifacts/dynamic-import")"
if [[ -n "$artifact_root_arg" ]]; then
  root="$(realpath -m -- "$artifact_root_arg")"
  [[ "$root" == "$artifact_base/"* ]] || { echo "dynamic-import evidence root must be under .artifacts/dynamic-import" >&2; exit 2; }
else
  root="$artifact_base/glibc-aarch64-getpid-20261018"
fi
[[ ! -e "$root" && ! -L "$root" ]] || { echo "refusing to overwrite existing dynamic-import evidence root: $root" >&2; exit 2; }
mkdir -p "$root"
positive="$root/$unit"

build_stdout="$root/dynamic-import-build.stdout"
build_stderr="$root/dynamic-import-build.stderr"
make -C "$native_root" dynamic-import-fixture >"$build_stdout" 2>"$build_stderr"
source_fixture="$native_root/build/host-context-dynamic-import-fixture.so"
source_assembly="$native_root/host_context_dynamic_import_fixture.S"
source_object="$native_root/build/host-context-dynamic-import-fixture.S.o"
managed_fixture="$repo_root/tests/UrProtect.Core.Tests/Fixtures/DynamicImports/liburp-glob-dat-indirect.so"
[[ -s "$source_fixture" && -s "$source_object" && -s "$source_assembly" ]] || { echo "project dynamic-import fixture build is incomplete" >&2; exit 1; }
mkdir -p "$(dirname "$managed_fixture")"
cp -- "$source_fixture" "$managed_fixture"

function_selector="$(PYTHONDONTWRITEBYTECODE=1 python3 - "$repo_root/scripts/check-dynamic-import-evidence.py" "$source_fixture" <<'PY'
import importlib.util
import pathlib
import sys
spec = importlib.util.spec_from_file_location("dynamic_import_evidence", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("cannot load the dynamic-import ELF binder")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
facts = module.ElfImage(pathlib.Path(sys.argv[2]).read_bytes(), "project fixture").facts()
print(facts["selectedFunction"]["selector"])
PY
)"
[[ "$function_selector" =~ ^dynsym:[0-9]+$ ]] || { echo "could not select the exact urp_entry dynsym index" >&2; exit 1; }

PROTECTED_IMAGE_ARTIFACT_ROOT="$positive" \
  "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
    --tier "$tier" \
    --runtime glibc \
    --unit "$unit" \
    --source "$source_fixture" \
    --function-id "$function_selector" \
    --entry-status 97 \
    --producer-id project-aarch64-glob-dat-import-fixture \
    >"$root/rehydration.stdout" 2>"$root/rehydration.stderr"

# Retain an observed generic rollback negative rather than the generic runner's
# placeholder witness. Corrupt the Protected Image digest and require failure
# before Native Image publication or any loader handoff.
cp -- "$positive/protected-image.bin" "$positive/negative-protected-image.bin"
python3 - "$positive/negative-protected-image.bin" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
image = bytearray(path.read_bytes())
if len(image) < 64:
    raise SystemExit("Protected Image is too small for a bounded negative mutation")
image[-1] ^= 1
path.write_bytes(image)
PY
role_path="$positive/protected-image.json"
original_rehydration="$positive/rehydration.json"
source_sha="$(sha256sum "$positive/source-image.bin" | cut -d' ' -f1)"
request_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["requestSha256"])' "$role_path")"
producer_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["producerId"])' "$role_path")"
producer_build="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["producerBuildSha256"])' "$role_path")"
consumer_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rehydratorConsumerId"])' "$role_path")"
consumer_build="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["consumerBuildSha256"])' "$original_rehydration")"
set +e
timeout --signal=TERM --kill-after=3s 45s dotnet "$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll" rehydrate-image \
  "$positive/source-image.bin" --artifact "$positive/negative-protected-image.bin" \
  --native-image "$positive/negative-native-image.bin" --role "$positive/negative-native-image.json" \
  --record "$positive/negative-rehydration.json" --unit "$unit" --profile host-context-entry \
  --source-sha256 "$source_sha" --request-sha256 "$request_sha" \
  --producer-id "$producer_id" --producer-build-sha256 "$producer_build" \
  --consumer-id "$consumer_id" --consumer-build-sha256 "$consumer_build" --json - \
  >"$positive/negative-rehydration-command.json" 2>"$positive/negative-rehydration-command.stderr"
negative_exit_status=$?
set -e
printf '%s\n' "$negative_exit_status" >"$positive/negative-rehydration-exit-status.txt"
python3 - "$positive" "$negative_exit_status" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
exit_status = int(sys.argv[2])
command = json.loads((root / "negative-rehydration-command.json").read_text(encoding="utf-8"))
record = json.loads((root / "negative-rehydration.json").read_text(encoding="utf-8"))
if command.get("success") is not False or command.get("record") != record:
    raise SystemExit("negative command output and retained rehydration record disagree")
diagnostics = record.get("diagnostics", [])
expected = [item for item in diagnostics if item.get("code") == "ProtectedImageIntegrityMismatch"]
if (
    exit_status != 5
    or record.get("status") != "failed"
    or record.get("firstFailureStage") != "rehydration"
    or len(expected) != 1
    or any((root / name).exists() or (root / name).is_symlink() for name in (
        "negative-native-image.bin", "negative-native-image.json", "negative-handoff.json"
    ))
):
    raise SystemExit("tampered Protected Image negative did not fail before Native Image/loader publication")
witness = {
    "schemaVersion": 1,
    "kind": "strict-chain-negative-witness",
    "status": "passed",
    "unitId": record["unitId"],
    "stage": record["firstFailureStage"],
    "failureClass": expected[0]["code"],
    "rollbackStatus": "passed",
    "nativeImagePublished": any((root / name).exists() or (root / name).is_symlink() for name in ("negative-native-image.bin", "negative-native-image.json")),
    "loaderInvoked": (root / "negative-handoff.json").exists() or (root / "negative-handoff.json").is_symlink(),
    "loaderMarkerObserved": (root / "negative-handoff.stdout").exists() or (root / "negative-handoff.stdout").is_symlink(),
    "artifactPath": "negative-protected-image.bin",
    "nativeImagePath": "negative-native-image.bin",
    "loaderMarkerPath": "negative-handoff.json",
    "producerExitStatus": exit_status,
    "negativeRecordSha256": hashlib.sha256((root / "negative-rehydration.json").read_bytes()).hexdigest(),
}
(root / "negative-rollback.json").write_text(json.dumps(witness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

mkdir -p "$positive"
cp -- "$source_assembly" "$positive/fixture-source.S"
cp -- "$source_object" "$positive/fixture-object.o"
readelf -hW -lW -dW -rW -Ws "$source_fixture" >"$positive/source-readelf.txt"
readelf -hW -lW -dW -rW -Ws "$positive/native-image.bin" >"$positive/native-readelf.txt"
as_version="$(as --version | head -n 1)"
ld_version="$(ld --version | head -n 1)"
source_assembly_sha="$(sha256sum "$source_assembly" | cut -d' ' -f1)"
object_sha="$(sha256sum "$source_object" | cut -d' ' -f1)"
makefile_sha="$(sha256sum "$native_root/Makefile" | cut -d' ' -f1)"
fixture_sha="$(sha256sum "$source_fixture" | cut -d' ' -f1)"
python3 - "$positive/dynamic-import-build.json" "$source_assembly_sha" "$object_sha" "$makefile_sha" "$fixture_sha" "$as_version" "$ld_version" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
record = {
    "buildCommand": ["make", "-C", "native/urprotect-runtime", "dynamic-import-fixture"],
    "sourceAssemblyPath": "native/urprotect-runtime/host_context_dynamic_import_fixture.S",
    "sourceAssemblySha256": sys.argv[2],
    "objectSha256": sys.argv[3],
    "makefileSha256": sys.argv[4],
    "fixtureSha256": sys.argv[5],
    "assembler": sys.argv[6],
    "linker": sys.argv[7],
}
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "$repo_root/scripts/tls_runtime_identity.py" >"$positive/runtime-identity.json"
python3 "$repo_root/scripts/check-dynamic-import-evidence.py" "$positive" \
  --tier "$tier" --unit "$unit" --write-report
printf 'Dynamic-import evidence: PASS (glibc AArch64 HostContext getpid GLOB_DAT; entry status 97)\n'
printf 'Evidence root: %s\n' "$positive"
printf 'Source SHA-256: %s\n' "$(sha256sum "$positive/source-image.bin" | cut -d' ' -f1)"
printf 'Protected Image SHA-256: %s\n' "$(sha256sum "$positive/protected-image.bin" | cut -d' ' -f1)"
printf 'Native Image SHA-256: %s\n' "$(sha256sum "$positive/native-image.bin" | cut -d' ' -f1)"
printf 'Source handoff SHA-256: %s\n' "$(sha256sum "$positive/source-handoff.json" | cut -d' ' -f1)"
printf 'Transformed handoff SHA-256: %s\n' "$(sha256sum "$positive/handoff.json" | cut -d' ' -f1)"
