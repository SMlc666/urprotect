#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s [--tier pr|nightly|release] [--artifact-root PATH]\n' "$0" >&2
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
case "$tier" in pr|nightly|release) ;; *) echo "invalid external-provider evidence tier: $tier" >&2; exit 2 ;; esac
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: external-provider evidence requires native AArch64" >&2; exit 2 ;; esac
case "$(python3 -c 'import os,platform; print(os.confstr("CS_GNU_LIBC_VERSION") or "")' 2>/dev/null || true)" in
  glibc\ *) ;;
  *) echo "environment-unavailable: external-provider evidence requires glibc" >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
unit='runtime.indirect-control.external-provider.glibc.host-context-entry'
producer_id='project-aarch64-external-jump-table-provider-fixture'
provider_soname='liburprotect-jump-table-provider.so.1'
artifact_base="$(realpath -m -- "$repo_root/.artifacts/indirect-control")"
if [[ -n "$artifact_root_arg" ]]; then
  root="$(realpath -m -- "$artifact_root_arg")"
  [[ "$root" == "$artifact_base/"* ]] || { echo "external-provider evidence root must be under .artifacts/indirect-control" >&2; exit 2; }
else
  root="$artifact_base/external-provider-glibc-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
[[ ! -e "$root" && ! -L "$root" ]] || { echo "refusing to overwrite existing external-provider evidence root: $root" >&2; exit 2; }
mkdir -p "$root"
positive="$root/$unit"
mkdir -p "$positive" "$positive/build-inputs/include/urp" "$positive/toolchain" "$positive/managed-build"

unset CC CXX AS LD CFLAGS CPPFLAGS HOST_CONTEXT_PLATFORM_CFLAGS ENTRY_FIXTURE_LDFLAGS MAKEFLAGS
make -C "$native_root" -B external-provider-image-handoff >"$positive/native-build.stdout" 2>"$positive/native-build.stderr"
provider_source="$native_root/host_context_external_provider_fixture.S"
provider_object="$native_root/build/host-context-external-provider-fixture.S.o"
provider_image="$native_root/build/$provider_soname"
consumer_source="$native_root/host_context_external_provider_consumer_fixture.S"
consumer_object="$native_root/build/host-context-external-provider-consumer-fixture.S.o"
consumer_image="$native_root/build/host-context-external-provider-consumer.so"
helper="$native_root/build/host-context-external-provider-image-handoff"
rollback_helper="$native_root/build/host-context-external-provider-rollback-self-test"
host_adapter_object="$native_root/build/host_adapter.o"
rollback_adapter_object="$native_root/build/host_adapter_provider_rollback_test.o"
host_image_validation_object="$native_root/build/host_image_validation.o"
rollback_validation_object="$native_root/build/host_image_validation_test.o"
sha256_object="$native_root/build/sha256.o"
for path in "$provider_source" "$provider_object" "$provider_image" "$consumer_source" "$consumer_object" "$consumer_image" "$helper" "$rollback_helper" "$host_adapter_object" "$rollback_adapter_object" "$host_image_validation_object" "$rollback_validation_object" "$sha256_object"; do
  [[ -s "$path" && ! -L "$path" ]] || { echo "native provider fixture output is missing or unsafe: $path" >&2; exit 1; }
done

cp -- "$provider_image" "$positive/provider-image.so"
cp -- "$provider_source" "$positive/provider-fixture.S"
cp -- "$provider_object" "$positive/provider-object.o"
cp -- "$consumer_source" "$positive/source-fixture.S"
cp -- "$consumer_object" "$positive/consumer-object.o"
cp -- "$consumer_image" "$positive/source-image.bin"
cp -- "$helper" "$positive/host-context-external-provider-image-handoff"
cp -- "$rollback_helper" "$positive/host-context-external-provider-rollback-self-test"
cp -- "$host_adapter_object" "$positive/host-adapter.o"
cp -- "$rollback_adapter_object" "$positive/rollback-host-adapter.o"
cp -- "$host_image_validation_object" "$positive/host-image-validation.o"
cp -- "$rollback_validation_object" "$positive/rollback-host-image-validation-test.o"
cp -- "$sha256_object" "$positive/sha256.o"
cp -- "$native_root/Makefile" "$positive/build-inputs/Makefile"
cp -- "$native_root/host_context_external_provider_image_handoff.c" "$positive/build-inputs/host_context_external_provider_image_handoff.c"
cp -- "$native_root/host_context_external_provider_self_test.c" "$positive/build-inputs/host_context_external_provider_self_test.c"
cp -- "$native_root/host_adapter_provider_rollback_test.h" "$positive/build-inputs/host_adapter_provider_rollback_test.h"
cp -- "$native_root/host_adapter.c" "$positive/build-inputs/host_adapter.c"
cp -- "$native_root/host_image_validation.c" "$positive/build-inputs/host_image_validation.c"
cp -- "$native_root/host_image_validation.h" "$positive/build-inputs/host_image_validation.h"
cp -- "$native_root/android_packed_relocation_tags.h" "$positive/build-inputs/android_packed_relocation_tags.h"
cp -- "$native_root/include/urp/host_adapter.h" "$positive/build-inputs/include/urp/host_adapter.h"
cp -- "$native_root/include/urp/host_context.h" "$positive/build-inputs/include/urp/host_context.h"
cp -- "$repo_root/native/urprotect-launcher/sha256.c" "$positive/build-inputs/sha256.c"
cp -- "$repo_root/native/urprotect-launcher/sha256.h" "$positive/build-inputs/sha256.h"
cp -- "$provider_source" "$positive/build-inputs/host_context_external_provider_fixture.S"
cp -- "$consumer_source" "$positive/build-inputs/host_context_external_provider_consumer_fixture.S"
evidence_tool_sources=(
  scripts/run-external-provider-e2e.sh
  scripts/check-external-provider-evidence.py
  scripts/check-dynamic-import-evidence.py
  scripts/check-indirect-control-evidence.py
  scripts/evidence_load_range.py
  scripts/tls_runtime_identity.py
  scripts/run-external-provider-rollback-oracle.sh
  scripts/check-external-provider-rollback-evidence.py
)
mkdir -p "$positive/build-inputs/evidence-tools/scripts"
for relative in "${evidence_tool_sources[@]}"; do
  cp -- "$repo_root/$relative" "$positive/build-inputs/evidence-tools/$relative"
done

source_sha="$(sha256sum "$positive/source-image.bin" | cut -d' ' -f1)"
provider_sha="$(sha256sum "$positive/provider-image.so" | cut -d' ' -f1)"
provider_build_id="$(readelf -n "$positive/provider-image.so" | awk '/Build ID:/ { print $3; exit }')"
[[ "$provider_build_id" =~ ^[0-9a-f]{40}$ ]] || { echo "provider fixture does not have the required 20-byte GNU build-id" >&2; exit 1; }
selected_function="$(PYTHONDONTWRITEBYTECODE=1 python3 - "$repo_root/scripts/check-external-provider-evidence.py" "$positive/source-image.bin" <<'PY'
import importlib.util
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("external_provider_selector", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("cannot load independent provider ELF checker")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
facts = module.parse_consumer(Path(sys.argv[2]).read_bytes(), "source consumer", require_source_dispatch=True)
print(facts["sourceDispatch"]["selectedFunction"]["selector"])
PY
)"
[[ "$selected_function" =~ ^dynsym:[0-9]+$ ]] || { echo "could not select the exact urp_entry dynamic symbol" >&2; exit 1; }

cli="$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
core="$repo_root/src/UrProtect.Core/bin/Release/net8.0/UrProtect.Core.dll"
(cd "$repo_root" && dotnet build UrProtect.sln --configuration Release --no-restore) >"$positive/managed-build.stdout" 2>"$positive/managed-build.stderr"
[[ -s "$cli" && -s "$core" ]] || { echo "managed Release assemblies are missing after the retained build command" >&2; exit 1; }
cp -- "$cli" "$positive/managed-build/urprotect.dll"
cp -- "$core" "$positive/managed-build/UrProtect.Core.dll"
dotnet --version >"$positive/managed-build/dotnet-version.txt"
cc_driver="$(readlink -f -- "$(command -v cc)")"
cc1_path="$(cc -print-prog-name=cc1)"
[[ "$cc1_path" = /* ]] || cc1_path="$(command -v "$cc1_path")"
as_path="$(readlink -f -- "$(command -v as)")"
ld_path="$(readlink -f -- "$(command -v ld)")"
cp --dereference -- "$cc_driver" "$positive/toolchain/cc-driver"
cp --dereference -- "$cc1_path" "$positive/toolchain/cc1"
cp --dereference -- "$as_path" "$positive/toolchain/as"
cp --dereference -- "$ld_path" "$positive/toolchain/ld"
cc --version >"$positive/toolchain/cc-version.txt"
as --version >"$positive/toolchain/as-version.txt" 2>&1
ld --version >"$positive/toolchain/ld-version.txt" 2>&1
cc -dumpmachine >"$positive/toolchain/target-triple.txt"

set +e
dotnet "$cli" protect-image "$positive/source-image.bin" \
  --artifact "$positive/protected-image.bin" --role "$positive/protected-image.json" \
  --manifest "$positive/producer-manifest.txt" --stage "$positive/stage.json" \
  --unit "$unit" --profile host-context-entry --producer-id "$producer_id" \
  --rehydrator urprotect.rehydrator.v1 --source-sha256 "$source_sha" \
  --function-id "$selected_function" --pass control-flow-flattening \
  --provider-file "$positive/provider-image.so" --provider-soname "$provider_soname" \
  --provider-build-id "$provider_build_id" --provider-sha256 "$provider_sha" --json - \
  >"$positive/producer.json" 2>"$positive/producer.stderr"
producer_status=$?
set -e
[[ "$producer_status" -eq 0 && -s "$positive/protected-image.bin" && -s "$positive/protected-image.json" && -s "$positive/stage.json" ]] || {
  echo "provider-aware Protected Image producer failed (status $producer_status)" >&2
  cat "$positive/producer.stderr" >&2
  exit 1
}

request_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["requestSha256"])' "$positive/protected-image.json")"
actual_producer="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["producerId"])' "$positive/protected-image.json")"
producer_build="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["producerBuildSha256"])' "$positive/protected-image.json")"
consumer_build="$(sha256sum "$core" | cut -d' ' -f1)"
[[ "$actual_producer" == "$producer_id" ]] || { echo "Protected Image producer id differs from requested fixture id" >&2; exit 1; }

set +e
dotnet "$cli" rehydrate-image "$positive/source-image.bin" \
  --artifact "$positive/protected-image.bin" --native-image "$positive/native-image.bin" \
  --role "$positive/native-image.json" --record "$positive/rehydration.json" \
  --unit "$unit" --profile host-context-entry --source-sha256 "$source_sha" \
  --request-sha256 "$request_sha" --producer-id "$actual_producer" --producer-build-sha256 "$producer_build" \
  --consumer-id urprotect.rehydrator.v1 --consumer-build-sha256 "$consumer_build" \
  --provider-file "$positive/provider-image.so" --provider-soname "$provider_soname" \
  --provider-build-id "$provider_build_id" --provider-sha256 "$provider_sha" --json - \
  >"$positive/rehydration-command.json" 2>"$positive/rehydration-command.stderr"
rehydration_status=$?
set -e
[[ "$rehydration_status" -eq 0 && -s "$positive/native-image.bin" && -s "$positive/native-image.json" && -s "$positive/rehydration.json" ]] || {
  echo "provider-aware Native Image rehydration failed (status $rehydration_status)" >&2
  cat "$positive/rehydration-command.stderr" >&2
  exit 1
}

wrong_sha="${provider_sha:0:63}"
if [[ "${provider_sha:63:1}" == 0 ]]; then wrong_sha+="1"; else wrong_sha+="0"; fi
set +e
dotnet "$cli" rehydrate-image "$positive/source-image.bin" \
  --artifact "$positive/protected-image.bin" --native-image "$positive/negative-native-image.bin" \
  --role "$positive/negative-native-image.json" --record "$positive/negative-rehydration.json" \
  --unit "$unit" --profile host-context-entry --source-sha256 "$source_sha" \
  --request-sha256 "$request_sha" --producer-id "$actual_producer" --producer-build-sha256 "$producer_build" \
  --consumer-id urprotect.rehydrator.v1 --consumer-build-sha256 "$consumer_build" \
  --provider-file "$positive/provider-image.so" --provider-soname "$provider_soname" \
  --provider-build-id "$provider_build_id" --provider-sha256 "$wrong_sha" --json - \
  >"$positive/negative-provider-sha256.stdout" 2>"$positive/negative-provider-sha256.stderr"
wrong_provider_status=$?
set -e
printf '%s\n' "$wrong_provider_status" >"$positive/negative-provider-sha256.exit-status"
[[ "$wrong_provider_status" -ne 0 && -s "$positive/negative-rehydration.json" ]] || {
  echo "wrong provider SHA-256 rollback did not produce an observed failed rehydration" >&2
  exit 1
}
for forbidden in negative-native-image.bin negative-native-image.json negative-loader.json negative-handoff.json; do
  [[ ! -e "$positive/$forbidden" && ! -L "$positive/$forbidden" ]] || {
    echo "wrong-provider rollback unexpectedly published $forbidden" >&2
    exit 1
  }
done

mkdir -p "$positive/handoffs"
python3 "$repo_root/scripts/tls_runtime_identity.py" >"$positive/runtime-identity.json"
python3 - "$positive/runtime-identity.json" "$positive/runtime-files" <<'PY'
import json
from pathlib import Path
import shutil
import sys
identity = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
destination = Path(sys.argv[2])
destination.mkdir(parents=True, exist_ok=True)
for key, name in (("libcPath", "libc.so.6"), ("loaderPath", "ld-linux-aarch64.so.1")):
    source = Path(identity[key])
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"native runtime identity input is not a regular file: {source}")
    shutil.copyfile(source, destination / name)
PY
libc_path="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["libcPath"])' "$positive/runtime-identity.json")"
loader_path="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["loaderPath"])' "$positive/runtime-identity.json")"
set +e
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT "$rollback_helper" \
  --native-image-provider-loaded-rollback "$positive/provider-image.so" \
  "$positive/native-image.bin" "$libc_path" "$loader_path" \
  >"$positive/transformed-native-rollback.json" 2>"$positive/transformed-native-rollback.stderr"
rollback_status=$?
set -e
printf '%s\n' "$rollback_status" >"$positive/transformed-native-rollback.exit-status"
if [[ "$rollback_status" -ne 0 || ! -s "$positive/transformed-native-rollback.json" ]]; then
  echo "transformed Native Image provider-loaded rollback oracle failed (status $rollback_status)" >&2
  cat "$positive/transformed-native-rollback.stderr" >&2
  exit 1
fi

handoff_records='[]'
for lane in source transformed; do
  if [[ "$lane" == source ]]; then image="$positive/source-image.bin"; else image="$positive/native-image.bin"; fi
  image_name="$lane-image.bin"
  for symbol in urp_entry urp_observer; do
    mkdir -p "$positive/handoffs/$lane/$symbol"
    for index in 0 1 2 3 4; do
      record="$positive/handoffs/$lane/$symbol/index-$index.json"
      stdout="$positive/handoffs/$lane/$symbol/index-$index.stdout"
      stderr="$positive/handoffs/$lane/$symbol/index-$index.stderr"
      status_file="$positive/handoffs/$lane/$symbol/index-$index.exit-status"
      set +e
      env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT "$helper" \
        "$positive/provider-image.so" "$provider_soname" "$provider_build_id" "$provider_sha" \
        "$image" "$symbol" "$index" "$record" >"$stdout" 2>"$stderr"
      actual_status=$?
      set -e
      printf '%s\n' "$actual_status" >"$status_file"
      expected_status=(17 103 249 91 255)
      if [[ "$actual_status" -ne "${expected_status[$index]}" || ! -s "$record" ]]; then
        echo "native $lane/$symbol/$index provider handoff failed (status $actual_status)" >&2
        cat "$stderr" >&2
        exit 1
      fi
      handoff_records="$(python3 - "$handoff_records" "$lane" "$symbol" "$index" "$image_name" "$record" "$stdout" "$stderr" "$actual_status" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
rows = json.loads(sys.argv[1])
lane, symbol, index_text, image_name, record_path, stdout_path, stderr_path = sys.argv[2:9]
index, status = int(index_text), int(sys.argv[9])
rows.append({
    "lane": lane,
    "entrySymbol": symbol,
    "argumentIndex": index,
    "argv": ["host-context-external-provider-image-handoff", "provider-image.so", "liburprotect-jump-table-provider.so.1", "BUILD_ID", "PROVIDER_SHA256", image_name, symbol, str(index), f"handoffs/{lane}/{symbol}/index-{index}.json"],
    "exitStatus": status,
    "streams": {
        "stdoutSha256": hashlib.sha256(Path(stdout_path).read_bytes()).hexdigest(),
        "stderrSha256": hashlib.sha256(Path(stderr_path).read_bytes()).hexdigest(),
    },
})
print(json.dumps(rows, separators=(",", ":")))
PY
)"
    done
  done
done

readelf -hW -lW -dW -rW -Ws "$positive/provider-image.so" >"$positive/provider-readelf.txt"
readelf -hW -lW -dW -rW -Ws "$positive/source-image.bin" >"$positive/source-readelf.txt"
readelf -hW -lW -dW -rW -Ws "$positive/native-image.bin" >"$positive/native-readelf.txt"

python3 - "$repo_root" "$positive" "$tier" "$unit" "$producer_id" "$provider_soname" "$provider_sha" "$provider_build_id" "$source_sha" "$selected_function" "$request_sha" "$actual_producer" "$producer_build" "$consumer_build" "$wrong_sha" "$wrong_provider_status" "$handoff_records" "$provider_source" "$provider_object" "$consumer_source" "$consumer_object" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
repo, root = Path(sys.argv[1]), Path(sys.argv[2])
tier, unit, producer_id, soname, provider_sha, build_id, source_sha, selected, request_sha, actual_producer, producer_build, consumer_build, wrong_sha = sys.argv[3:16]
wrong_status = int(sys.argv[16])
handoffs = json.loads(sys.argv[17])
provider_source, provider_object, consumer_source, consumer_object = map(Path, sys.argv[18:22])
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read_json(path): return json.loads(path.read_text(encoding="utf-8"))
for row in handoffs:
    row["argv"][3] = build_id
    row["argv"][4] = provider_sha
commands = {
    "schemaVersion": 1,
    "tier": tier,
    "unitId": unit,
    "producerId": producer_id,
    "actualProducerId": actual_producer,
    "sourceSha256": source_sha,
    "provider": {"file": "provider-image.so", "soname": soname, "buildId": build_id, "sha256": provider_sha},
    "execution": {"architecture": "aarch64", "runtime": "glibc", "emulated": False, "invocation": "direct-native-exec"},
    "selectedFunction": selected,
    "requestSha256": request_sha,
    "producerBuildSha256": producer_build,
    "consumerBuildSha256": consumer_build,
    "managedCliSha256": sha(root / "managed-build/urprotect.dll"),
    "wrongProviderSha256": wrong_sha,
    "nativeBuild": {
        "argv": ["make", "-C", "native/urprotect-runtime", "-B", "external-provider-image-handoff"],
        "exitStatus": 0,
        "stdoutSha256": sha(root / "native-build.stdout"),
        "stderrSha256": sha(root / "native-build.stderr"),
    },
    "managedBuild": {
        "argv": ["dotnet", "build", "UrProtect.sln", "--configuration", "Release", "--no-restore"],
        "exitStatus": 0,
        "stdoutSha256": sha(root / "managed-build.stdout"),
        "stderrSha256": sha(root / "managed-build.stderr"),
    },
    "producer": {"argv": ["dotnet", "urprotect.dll", "protect-image", "source-image.bin", "--artifact", "protected-image.bin", "--role", "protected-image.json", "--manifest", "producer-manifest.txt", "--stage", "stage.json", "--unit", unit, "--profile", "host-context-entry", "--producer-id", producer_id, "--rehydrator", "urprotect.rehydrator.v1", "--source-sha256", source_sha, "--function-id", selected, "--pass", "control-flow-flattening", "--provider-file", "provider-image.so", "--provider-soname", soname, "--provider-build-id", build_id, "--provider-sha256", provider_sha, "--json", "-"], "exitStatus": 0},
    "rehydration": {"argv": ["dotnet", "urprotect.dll", "rehydrate-image", "source-image.bin", "--artifact", "protected-image.bin", "--native-image", "native-image.bin", "--role", "native-image.json", "--record", "rehydration.json", "--unit", unit, "--profile", "host-context-entry", "--source-sha256", source_sha, "--request-sha256", request_sha, "--producer-id", actual_producer, "--producer-build-sha256", producer_build, "--consumer-id", "urprotect.rehydrator.v1", "--consumer-build-sha256", consumer_build, "--provider-file", "provider-image.so", "--provider-soname", soname, "--provider-build-id", build_id, "--provider-sha256", provider_sha, "--json", "-"], "exitStatus": 0},
    "wrongProviderSha256Rollback": {"argv": ["dotnet", "urprotect.dll", "rehydrate-image", "source-image.bin", "--artifact", "protected-image.bin", "--native-image", "negative-native-image.bin", "--role", "negative-native-image.json", "--record", "negative-rehydration.json", "--unit", unit, "--profile", "host-context-entry", "--source-sha256", source_sha, "--request-sha256", request_sha, "--producer-id", actual_producer, "--producer-build-sha256", producer_build, "--consumer-id", "urprotect.rehydrator.v1", "--consumer-build-sha256", consumer_build, "--provider-file", "provider-image.so", "--provider-soname", soname, "--provider-build-id", build_id, "--provider-sha256", wrong_sha, "--json", "-"], "exitStatus": wrong_status},
    "handoffs": handoffs,
}
commands["transformedNativeRollback"] = {
    "argv": [
        "host-context-external-provider-rollback-self-test",
        "--native-image-provider-loaded-rollback",
        "provider-image.so", "native-image.bin", "runtime-identity.json:libcPath",
        "runtime-identity.json:loaderPath",
    ],
    "exitStatus": int((root / "transformed-native-rollback.exit-status").read_text(encoding="ascii").strip()),
    "recordSha256": sha(root / "transformed-native-rollback.json"),
    "stderrSha256": sha(root / "transformed-native-rollback.stderr"),
    "sourceImageSha256": sha(root / "source-image.bin"),
    "protectedImageSha256": sha(root / "protected-image.bin"),
    "nativeImageSha256": sha(root / "native-image.bin"),
    "runtimeIdentitySha256": read_json(root / "runtime-identity.json")["identitySha256"],
}
(root / "commands.json").write_text(json.dumps(commands, sort_keys=True, indent=2) + "\n", encoding="utf-8")
negative_record = read_json(root / "negative-rehydration.json")
stdout = (root / "negative-provider-sha256.stdout").read_bytes()
stderr = (root / "negative-provider-sha256.stderr").read_bytes()
diagnostics = negative_record.get("diagnostics")
if not isinstance(diagnostics, list):
    raise SystemExit("wrong-provider negative record has no diagnostics list")
provider_diagnostics = [
    item for item in diagnostics
    if isinstance(item, dict)
    and (
        "provider" in str(item.get("code", "")).lower()
        or ("provider" in str(item.get("message", "")).lower() and "sha-256" in str(item.get("message", "")).lower())
    )
]
witness = {
    "schemaVersion": 1,
    "stage": negative_record.get("firstFailureStage"),
    "firstFailureStage": negative_record.get("firstFailureStage"),
    "status": negative_record.get("status"),
    "failureClass": provider_diagnostics[0]["code"] if len(provider_diagnostics) == 1 else None,
    "exitStatus": wrong_status,
    "providerSha256": provider_sha,
    "suppliedProviderSha256": wrong_sha,
    "nativeImagePublished": (root / "negative-native-image.bin").exists(),
    "loaderInvoked": (root / "negative-handoff.json").exists(),
    "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
    "stderrSha256": hashlib.sha256(stderr).hexdigest(),
    "negativeRecordSha256": sha(root / "negative-rehydration.json"),
}
(root / "negative-provider-sha256.json").write_text(json.dumps(witness, sort_keys=True, indent=2) + "\n", encoding="utf-8")
def first_line(path): return path.read_text(encoding="utf-8").splitlines()[0]
build_record = {
    "schemaVersion": 1,
    "buildCommand": ["make", "-C", "native/urprotect-runtime", "-B", "external-provider-image-handoff"],
    "managedBuildCommand": ["dotnet", "build", "UrProtect.sln", "--configuration", "Release", "--no-restore"],
    "makefileSha256": sha(root / "build-inputs/Makefile"),
    "providerAssemblySha256": sha(root / "provider-fixture.S"),
    "providerObjectSha256": sha(root / "provider-object.o"),
    "consumerAssemblySha256": sha(root / "source-fixture.S"),
    "consumerObjectSha256": sha(root / "consumer-object.o"),
    "helperSourceSha256": sha(root / "build-inputs/host_context_external_provider_image_handoff.c"),
    "helperBinarySha256": sha(root / "host-context-external-provider-image-handoff"),
    "hostAdapterSourceSha256": sha(root / "build-inputs/host_adapter.c"),
    "hostImageValidationSourceSha256": sha(root / "build-inputs/host_image_validation.c"),
    "hostImageValidationHeaderSha256": sha(root / "build-inputs/host_image_validation.h"),
    "androidPackedRelocationTagsSha256": sha(root / "build-inputs/android_packed_relocation_tags.h"),
    "hostAdapterHeaderSha256": sha(root / "build-inputs/include/urp/host_adapter.h"),
    "hostContextHeaderSha256": sha(root / "build-inputs/include/urp/host_context.h"),
    "sha256SourceSha256": sha(root / "build-inputs/sha256.c"),
    "sha256HeaderSha256": sha(root / "build-inputs/sha256.h"),
    "hostAdapterObjectSha256": sha(root / "host-adapter.o"),
    "rollbackAdapterObjectSha256": sha(root / "rollback-host-adapter.o"),
    "evidenceTools": {
        "providerProducerSha256": sha(root / "build-inputs/evidence-tools/scripts/run-external-provider-e2e.sh"),
        "providerCheckerSha256": sha(root / "build-inputs/evidence-tools/scripts/check-external-provider-evidence.py"),
        "dynamicImportParserSha256": sha(root / "build-inputs/evidence-tools/scripts/check-dynamic-import-evidence.py"),
        "indirectControlParserSha256": sha(root / "build-inputs/evidence-tools/scripts/check-indirect-control-evidence.py"),
        "evidenceLoadRangeHelperSha256": sha(root / "build-inputs/evidence-tools/scripts/evidence_load_range.py"),
        "runtimeIdentityVerifierSha256": sha(root / "build-inputs/evidence-tools/scripts/tls_runtime_identity.py"),
        "rollbackProducerSha256": sha(root / "build-inputs/evidence-tools/scripts/run-external-provider-rollback-oracle.sh"),
        "rollbackCheckerSha256": sha(root / "build-inputs/evidence-tools/scripts/check-external-provider-rollback-evidence.py"),
    },
    "hostImageValidationObjectSha256": sha(root / "host-image-validation.o"),
    "rollbackHostImageValidationTestObjectSha256": sha(root / "rollback-host-image-validation-test.o"),
    "rollbackHelperSourceSha256": sha(root / "build-inputs/host_context_external_provider_self_test.c"),
    "rollbackTestHeaderSha256": sha(root / "build-inputs/host_adapter_provider_rollback_test.h"),
    "rollbackHelperBinarySha256": sha(root / "host-context-external-provider-rollback-self-test"),
    "sha256ObjectSha256": sha(root / "sha256.o"),
    "providerImageSha256": provider_sha,
    "sourceConsumerSha256": source_sha,
    "nativeBuildStdoutSha256": sha(root / "native-build.stdout"),
    "nativeBuildStderrSha256": sha(root / "native-build.stderr"),
    "managedBuildStdoutSha256": sha(root / "managed-build.stdout"),
    "managedBuildStderrSha256": sha(root / "managed-build.stderr"),
    "toolchain": {
        "ccVersionLine": first_line(root / "toolchain/cc-version.txt"),
        "ccDriverSha256": sha(root / "toolchain/cc-driver"),
        "cc1Sha256": sha(root / "toolchain/cc1"),
        "assemblerVersionLine": first_line(root / "toolchain/as-version.txt"),
        "assemblerSha256": sha(root / "toolchain/as"),
        "linkerVersionLine": first_line(root / "toolchain/ld-version.txt"),
        "linkerSha256": sha(root / "toolchain/ld"),
        "targetTriple": (root / "toolchain/target-triple.txt").read_text(encoding="ascii").strip(),
        "cppFlags": ["-Iinclude", "-I../urprotect-launcher", "-I../../third_party/miniz"],
        "cFlags": ["-std=c11", "-O2", "-g0", "-Wall", "-Wextra", "-Werror", "-Wshadow", "-Wconversion", "-pthread"],
    },
    "managedBuild": {
        "cliAssemblySha256": sha(root / "managed-build/urprotect.dll"),
        "coreAssemblySha256": sha(root / "managed-build/UrProtect.Core.dll"),
        "producerBuildSha256": producer_build,
        "consumerBuildSha256": consumer_build,
        "dotnetVersion": first_line(root / "managed-build/dotnet-version.txt"),
    },
}
(root / "native-build.json").write_text(json.dumps(build_record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY

python3 - "$positive" <<'PY'
from pathlib import Path
import sys
import tarfile
root = Path(sys.argv[1])
files = [
    "native-build.stdout", "native-build.stderr", "managed-build.stdout", "managed-build.stderr",
    "host-adapter.o", "rollback-host-adapter.o", "host-image-validation.o",
    "rollback-host-image-validation-test.o", "sha256.o",
    "build-inputs/Makefile", "build-inputs/host_context_external_provider_image_handoff.c",
    "build-inputs/host_context_external_provider_self_test.c",
    "build-inputs/host_adapter_provider_rollback_test.h",
    "build-inputs/host_adapter.c", "build-inputs/host_image_validation.c", "build-inputs/host_image_validation.h",
    "build-inputs/android_packed_relocation_tags.h", "build-inputs/include/urp/host_adapter.h",
    "build-inputs/include/urp/host_context.h", "build-inputs/sha256.c", "build-inputs/sha256.h",
    "build-inputs/host_context_external_provider_fixture.S",
    "build-inputs/host_context_external_provider_consumer_fixture.S",
    *[f"build-inputs/evidence-tools/{relative}" for relative in (
        "scripts/run-external-provider-e2e.sh",
        "scripts/check-external-provider-evidence.py",
        "scripts/check-dynamic-import-evidence.py",
        "scripts/check-indirect-control-evidence.py",
        "scripts/evidence_load_range.py",
        "scripts/tls_runtime_identity.py",
        "scripts/run-external-provider-rollback-oracle.sh",
        "scripts/check-external-provider-rollback-evidence.py",
    )],
    "toolchain/cc-driver", "toolchain/cc1", "toolchain/as", "toolchain/ld",
    "toolchain/cc-version.txt", "toolchain/as-version.txt", "toolchain/ld-version.txt", "toolchain/target-triple.txt",
    "managed-build/urprotect.dll", "managed-build/UrProtect.Core.dll", "managed-build/dotnet-version.txt",
]
archive_path = root / "build-provenance.tar.gz"
with tarfile.open(archive_path, mode="w:gz", compresslevel=6) as archive:
    for relative in files:
        archive.add(root / relative, arcname=relative, recursive=False)
for relative in files:
    path = root / relative
    if path.is_dir():
        continue
    path.unlink()
for relative in ("build-inputs/evidence-tools/scripts", "build-inputs/evidence-tools", "build-inputs/include/urp", "build-inputs/include", "build-inputs", "toolchain", "managed-build"):
    (root / relative).rmdir()
PY

python3 "$repo_root/scripts/check-external-provider-evidence.py" "$positive" --write-report
URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT="$positive" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s "$repo_root/tests" -p 'test_external_provider_evidence.py' -v
python3 "$repo_root/scripts/check-external-provider-evidence.py" "$positive"
printf 'External provider evidence: PASS (native AArch64/glibc, 4 provider targets + safe default; status not promoted)\n'
printf 'Evidence root: %s\n' "$positive"
printf 'Provider SHA-256: %s\n' "$provider_sha"
printf 'Provider build-id: %s\n' "$provider_build_id"
printf 'Source SHA-256: %s\n' "$source_sha"
printf 'Native Image SHA-256: %s\n' "$(sha256sum "$positive/native-image.bin" | cut -d' ' -f1)"
