#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root=""
while (($#)); do
  case "$1" in
    --artifact-root)
      [[ $# -ge 2 ]] || { echo "--artifact-root requires a path" >&2; exit 2; }
      artifact_root="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done
if [[ -z "$artifact_root" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  artifact_root="$repo_root/.artifacts/indirect-control/provider-loaded-rollback-$stamp"
fi
mkdir -p "$(dirname "$artifact_root")"
artifact_root="$(realpath -m "$artifact_root")"
[[ ! -e "$artifact_root" && ! -L "$artifact_root" ]] || {
  echo "artifact root already exists: $artifact_root" >&2
  exit 2
}
mkdir -m 0755 "$artifact_root"
mkdir -p "$artifact_root/build-inputs/include/urp" "$artifact_root/build-outputs" "$artifact_root/evidence-tools" "$artifact_root/scripts" "$artifact_root/toolchain"

runtime_dir="$repo_root/native/urprotect-runtime"
set +e
make -C "$runtime_dir" -B external-provider-provider-loaded-rollback-test \
  >"$artifact_root/native-build.stdout" 2>"$artifact_root/native-build.stderr"
build_status=$?
set -e
printf '%s\n' "$build_status" >"$artifact_root/native-build.exit-status"

copy_build_input() {
  local source="$1" destination="$2"
  install -m 0644 "$runtime_dir/$source" "$artifact_root/build-inputs/$destination"
}
copy_build_output() {
  local source="$1" destination="$2"
  install -m 0644 "$runtime_dir/build/$source" "$artifact_root/build-outputs/$destination"
}
copy_build_input Makefile Makefile
copy_build_input host_adapter.c host_adapter.c
copy_build_input host_context_external_provider_self_test.c host_context_external_provider_self_test.c
copy_build_input host_adapter_provider_rollback_test.h host_adapter_provider_rollback_test.h
copy_build_input host_image_validation.c host_image_validation.c
copy_build_input host_image_validation.h host_image_validation.h
copy_build_input android_packed_relocation_tags.h android_packed_relocation_tags.h
copy_build_input include/urp/host_adapter.h include/urp/host_adapter.h
copy_build_input include/urp/host_context.h include/urp/host_context.h
copy_build_input host_context_external_provider_fixture.S host_context_external_provider_fixture.S
copy_build_input host_context_external_provider_consumer_fixture.S host_context_external_provider_consumer_fixture.S
install -m 0644 "$repo_root/native/urprotect-launcher/sha256.c" "$artifact_root/build-inputs/sha256.c"
install -m 0644 "$repo_root/native/urprotect-launcher/sha256.h" "$artifact_root/build-inputs/sha256.h"
install -m 0644 "$repo_root/scripts/check-external-provider-evidence.py" "$artifact_root/scripts/check-external-provider-evidence.py"
install -m 0644 "$repo_root/scripts/check-dynamic-import-evidence.py" "$artifact_root/scripts/check-dynamic-import-evidence.py"
install -m 0644 "$repo_root/scripts/check-indirect-control-evidence.py" "$artifact_root/scripts/check-indirect-control-evidence.py"
install -m 0644 "$repo_root/scripts/tls_runtime_identity.py" "$artifact_root/scripts/tls_runtime_identity.py"
install -m 0644 "$repo_root/scripts/check-external-provider-rollback-evidence.py" "$artifact_root/evidence-tools/check-external-provider-rollback-evidence.py"
copy_build_output host-context-external-provider-fixture.S.o provider-fixture.o
copy_build_output host-context-external-provider-consumer-fixture.S.o consumer-fixture.o
copy_build_output host_adapter_provider_rollback_test.o host-adapter-provider-rollback-test.o
copy_build_output host_image_validation_test.o host-image-validation-test.o
copy_build_output sha256.o sha256.o
copy_build_output host-context-external-provider-rollback-self-test rollback-self-test
chmod 0755 "$artifact_root/build-outputs/rollback-self-test"
copy_build_output liburprotect-jump-table-provider.so.1 provider-image.so
copy_build_output host-context-external-provider-consumer.so consumer-image.so

cc_path="$(command -v cc)"
as_path="$(command -v as)"
ld_path="$(command -v ld)"
cc1_path="$(cc -print-prog-name=cc1)"
python3 - "$artifact_root/toolchain" "$cc_path" "$cc1_path" "$as_path" "$ld_path" <<'PY'
from pathlib import Path
import os
import sys
root = Path(sys.argv[1])
for name, source in zip(("cc-driver", "cc1", "as", "ld"), sys.argv[2:]):
    destination = root / name
    destination.write_bytes(Path(source).read_bytes())
    os.chmod(destination, 0o644)
PY
cc -dumpmachine >"$artifact_root/toolchain/target-triple.txt"
cc --version >"$artifact_root/toolchain/cc-version.txt" 2>&1
as --version >"$artifact_root/toolchain/as-version.txt" 2>&1
ld --version >"$artifact_root/toolchain/ld-version.txt" 2>&1

set +e
(
  cd "$artifact_root"
  env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT \
    ./build-outputs/rollback-self-test --provider-loaded-rollback \
    "$artifact_root/build-outputs/provider-image.so" "$artifact_root/build-outputs/consumer-image.so" \
    >rollback-record.json 2>rollback-stderr.log
)
oracle_status=$?
set -e
printf '%s\n' "$oracle_status" >"$artifact_root/rollback-exit-status"

python3 - "$artifact_root" "$build_status" "$oracle_status" "$cc_path" "$as_path" "$ld_path" <<'PY'
import hashlib
import json
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
build_status, oracle_status = int(sys.argv[2]), int(sys.argv[3])
cc_path, as_path, ld_path = sys.argv[4:7]
def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def root_sha(relative):
    return sha(root / relative)
record = {
    "schemaVersion": 1,
    "nativeBuildCommand": ["make", "-C", "native/urprotect-runtime", "-B", "external-provider-provider-loaded-rollback-test"],
    "nativeBuildExitStatus": build_status,
    "nativeBuildStdoutSha256": root_sha("native-build.stdout"),
    "nativeBuildStderrSha256": root_sha("native-build.stderr"),
    "rollbackExitStatus": oracle_status,
    "rollbackStdoutSha256": root_sha("rollback-record.json"),
    "rollbackStderrSha256": root_sha("rollback-stderr.log"),
    "rollbackBinarySha256": root_sha("build-outputs/rollback-self-test"),
    "providerImageSha256": root_sha("build-outputs/provider-image.so"),
    "consumerImageSha256": root_sha("build-outputs/consumer-image.so"),
    "nativeBuildInputs": {
        "makefileSha256": root_sha("build-inputs/Makefile"),
        "hostAdapterSourceSha256": root_sha("build-inputs/host_adapter.c"),
        "rollbackHeaderSha256": root_sha("build-inputs/host_adapter_provider_rollback_test.h"),
        "selfTestSourceSha256": root_sha("build-inputs/host_context_external_provider_self_test.c"),
        "imageValidationSourceSha256": root_sha("build-inputs/host_image_validation.c"),
        "imageValidationHeaderSha256": root_sha("build-inputs/host_image_validation.h"),
        "providerFixtureSourceSha256": root_sha("build-inputs/host_context_external_provider_fixture.S"),
        "consumerFixtureSourceSha256": root_sha("build-inputs/host_context_external_provider_consumer_fixture.S"),
        "hostAdapterObjectSha256": root_sha("build-outputs/host-adapter-provider-rollback-test.o"),
        "imageValidationObjectSha256": root_sha("build-outputs/host-image-validation-test.o"),
        "sha256ObjectSha256": root_sha("build-outputs/sha256.o"),
        "providerObjectSha256": root_sha("build-outputs/provider-fixture.o"),
        "consumerObjectSha256": root_sha("build-outputs/consumer-fixture.o"),
    },
    "toolchain": {
        "compilerVersionSha256": root_sha("toolchain/cc-version.txt"),
        "assemblerVersionSha256": root_sha("toolchain/as-version.txt"),
        "linkerVersionSha256": root_sha("toolchain/ld-version.txt"),
        "targetTripleSha256": root_sha("toolchain/target-triple.txt"),
        "compilerDriverSha256": root_sha("toolchain/cc-driver"),
        "compilerFrontendSha256": root_sha("toolchain/cc1"),
        "assemblerSha256": root_sha("toolchain/as"),
        "linkerSha256": root_sha("toolchain/ld"),
    },
    "evidenceTools": {
        "providerElfParserSha256": root_sha("scripts/check-external-provider-evidence.py"),
        "dynamicImportParserSha256": root_sha("scripts/check-dynamic-import-evidence.py"),
        "indirectControlParserSha256": root_sha("scripts/check-indirect-control-evidence.py"),
        "runtimeIdentityVerifierSha256": root_sha("scripts/tls_runtime_identity.py"),
        "rollbackCheckerSha256": root_sha("evidence-tools/check-external-provider-rollback-evidence.py"),
    },
}
(root / "native-build.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY

set +e
python3 "$repo_root/scripts/check-external-provider-rollback-evidence.py" \
  --root "$artifact_root" --seal
check_status=$?
set -e
if [[ "$build_status" -ne 0 || "$oracle_status" -ne 0 || "$check_status" -ne 0 ]]; then
  echo "provider-loaded rollback oracle failed (build=$build_status oracle=$oracle_status checker=$check_status); evidence retained at $artifact_root" >&2
  exit 1
fi
chmod -R a-w "$artifact_root"
printf 'Provider-loaded rollback oracle accepted: %s\n' "$artifact_root"
