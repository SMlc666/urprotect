#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release --model MODEL --profile host-context-entry --runtime glibc --lifecycle current-thread --unit UNIT --source ELF --function-id TABLE:INDEX --entry-status 43 --producer-id ID\n' "$0" >&2
}

tier=''
unit=''
source_file=''
function_id=''
model=''
profile=''
runtime=''
lifecycle=''
expected_entry_status=''
producer_id=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { usage; exit 2; }; unit="$2"; shift 2 ;;
    --source) [[ $# -ge 2 ]] || { usage; exit 2; }; source_file="$2"; shift 2 ;;
    --function-id) [[ $# -ge 2 ]] || { usage; exit 2; }; function_id="$2"; shift 2 ;;
    --model) [[ $# -ge 2 ]] || { usage; exit 2; }; model="$2"; shift 2 ;;
    --profile) [[ $# -ge 2 ]] || { usage; exit 2; }; profile="$2"; shift 2 ;;
    --runtime) [[ $# -ge 2 ]] || { usage; exit 2; }; runtime="$2"; shift 2 ;;
    --lifecycle) [[ $# -ge 2 ]] || { usage; exit 2; }; lifecycle="$2"; shift 2 ;;
    --entry-status) [[ $# -ge 2 ]] || { usage; exit 2; }; expected_entry_status="$2"; shift 2 ;;
    --producer-id) [[ $# -ge 2 ]] || { usage; exit 2; }; producer_id="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid TLS evidence tier: $tier" >&2; exit 2 ;; esac
for field in model profile runtime lifecycle unit source_file function_id expected_entry_status producer_id; do
  [[ -n "${!field}" ]] || { echo "missing required TLS identity input: $field" >&2; usage; exit 2; }
done
case "$runtime" in glibc) ;; *) echo "TLS transformed HostContext evidence requires explicit runtime glibc" >&2; exit 2 ;; esac
case "$profile" in host-context-entry) ;; *) echo "TLS transformed evidence requires explicit profile host-context-entry" >&2; exit 2 ;; esac
case "$lifecycle" in current-thread) ;; *) echo "TLS transformed evidence requires explicit lifecycle current-thread" >&2; exit 2 ;; esac
case "$model" in
  initial-exec) selector_table=symtab; selector_name=urp_tls_read; expected_producer=gcc-c-tls-initial-exec ;;
  local-dynamic) selector_table=dynsym; selector_name=urp_entry; expected_producer=gcc-aarch64-tlsld-fixture ;;
  general-dynamic) selector_table=dynsym; selector_name=urp_entry; expected_producer=gcc-aarch64-tlsgd-fixture ;;
  tlsdesc) selector_table=dynsym; selector_name=urp_entry; expected_producer=gcc-aarch64-tlsdesc-fixture ;;
  *) echo "TLS transformed evidence requires one of the four promoted models" >&2; exit 2 ;;
esac
[[ "$producer_id" == "$expected_producer" ]] || { echo "producer ID does not belong to TLS model $model" >&2; exit 2; }
[[ "$expected_entry_status" == 43 ]] || { echo "TLS row expected entry status must be 43" >&2; exit 2; }
case "$unit" in
  "tls.$model.glibc.host-context-entry"|"$model.host-context-entry.glibc.current-thread") ;;
  *) echo "unit ID does not bind the selected TLS model/runtime/profile/lifecycle tuple" >&2; exit 2 ;;
esac
if [[ ! "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "invalid TLS evidence unit: $unit" >&2
  exit 2
fi
if [[ ! "$function_id" =~ ^(dynsym|symtab):[0-9]+$ ]]; then
  echo "invalid TLS function selector: $function_id" >&2
  exit 2
fi
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: TLS transformed handoff requires native AArch64" >&2; exit 2 ;; esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected_source_rel="$(python3 - "$repo_root" "$model" <<'PYREG'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
registry=json.loads((root/"fixtures/tls-runtime-matrix.json").read_text(encoding="utf-8"))
print(registry["sourceFixtures"][sys.argv[2]])
PYREG
)"
expected_source="$(realpath -e -- "$repo_root/$expected_source_rel")" || { echo "registered TLS fixture is missing" >&2; exit 2; }
if [[ "$source_file" != /* ]]; then source_file="$repo_root/$source_file"; fi
source_file="$(realpath -e -- "$source_file")" || { echo "TLS source fixture is missing" >&2; exit 2; }
[[ -f "$source_file" && ! -L "$source_file" ]] || { echo "TLS source is not a regular file" >&2; exit 2; }
[[ "$source_file" == "$expected_source" ]] || { echo "source fixture does not belong to TLS model $model" >&2; exit 2; }
if [[ "$selector_table" == dynsym ]]; then
  selector_listing="$(readelf --dyn-syms -W "$source_file")" || { echo "could not inspect TLS dynsym selector" >&2; exit 2; }
else
  selector_listing="$(readelf --syms -W "$source_file")" || { echo "could not inspect TLS symtab selector" >&2; exit 2; }
fi
mapfile -t selector_indices < <(printf '%s\n' "$selector_listing" | awk -v name="$selector_name" '$1 ~ /^[0-9]+:/ && $4 == "FUNC" && $NF == name { symidx=$1; sub(/:$/, "", symidx); print symidx }')
[[ "${#selector_indices[@]}" -eq 1 ]] || { echo "TLS model fixture has no unique owned function selector" >&2; exit 2; }
expected_function_id="$selector_table:${selector_indices[0]}"
[[ "$function_id" == "$expected_function_id" ]] || { echo "function selector does not belong to TLS model $model" >&2; exit 2; }

artifact_parent="${TLS_EVIDENCE_ARTIFACT_ROOT:-${PROTECTED_IMAGE_ARTIFACT_ROOT:-$repo_root/.artifacts/protected-image/tls}}"
artifact_parent="$(realpath -m -- "$artifact_parent")"
PROTECTED_IMAGE_ARTIFACT_ROOT="$artifact_parent/$unit" \
  "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" \
  --runtime "$runtime" \
  --unit "$unit" \
  --source "$source_file" \
  --function-id "$function_id" \
  --entry-status "$expected_entry_status" \
  --producer-id "$producer_id"

artifact_root="$artifact_parent/$unit"
readelf -hW -lW -rW -sW "$artifact_root/source-image.bin" > "$artifact_root/tls-readelf.txt"
python3 - "$artifact_root" "$model" "$runtime" "$profile" "$lifecycle" "$unit" "$expected_entry_status" "$repo_root" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
model, runtime, profile, lifecycle, unit = sys.argv[2:7]
expected_entry_status = int(sys.argv[7])
repo_root = Path(sys.argv[8]).resolve()
if not all((model, runtime, profile, lifecycle, unit)):
    raise SystemExit("TLS enrichment requires explicit model/runtime/profile/lifecycle/unit")
if model not in {"local-exec", "initial-exec", "local-dynamic", "general-dynamic", "tlsdesc"} or runtime != "glibc" or profile != "host-context-entry" or lifecycle != "current-thread":
    raise SystemExit("TLS enrichment arguments are outside the native glibc HostContext current-thread contract")
identity_command = [sys.executable, str(repo_root / "scripts/tls_runtime_identity.py")]
runtime_identity = json.loads(subprocess.check_output(identity_command, text=True, timeout=10))
source = root / "source-image.bin"
source_bytes = source.read_bytes()
if source_bytes[:6] != b"\x7fELF\x02\x01" or len(source_bytes) < 64:
    raise SystemExit("TLS evidence source is not bounded ELF64 little-endian")
phoff = struct.unpack_from("<Q", source_bytes, 32)[0]
phentsize = struct.unpack_from("<H", source_bytes, 54)[0]
phnum = struct.unpack_from("<H", source_bytes, 56)[0]
if phentsize != 56 or phnum == 0 or phnum > 4096:
    raise SystemExit("TLS evidence program-header table is unsupported")
if phoff > len(source_bytes) or phnum * phentsize > len(source_bytes) - phoff:
    raise SystemExit("TLS evidence program-header table is unbounded")
pt_tls = None
loads = []
for index in range(phnum):
    off = phoff + index * phentsize
    p_type, p_flags = struct.unpack_from("<II", source_bytes, off)
    p_offset, p_vaddr = struct.unpack_from("<QQ", source_bytes, off + 8)
    p_filesz, p_memsz, p_align = struct.unpack_from("<QQQ", source_bytes, off + 32)
    if p_type == 1:
        loads.append((index, p_vaddr, p_memsz))
    if p_type == 7:
        if pt_tls is not None:
            raise SystemExit("TLS evidence source has duplicate PT_TLS")
        pt_tls = (index, p_offset, p_vaddr, p_filesz, p_memsz, p_align, p_flags)
if pt_tls is None:
    raise SystemExit("TLS evidence source has no PT_TLS")
index, file_offset, virtual_address, file_size, memory_size, alignment, flags = pt_tls
if file_size > memory_size or file_offset > len(source_bytes) or file_size > len(source_bytes) - file_offset:
    raise SystemExit("TLS evidence PT_TLS range is unbounded")
owning_load = next(
    (load_index for load_index, load_vaddr, load_memsz in loads
     if virtual_address >= load_vaddr
     and virtual_address - load_vaddr <= load_memsz
     and memory_size <= load_memsz - (virtual_address - load_vaddr)),
    None,
)
if owning_load is None:
    raise SystemExit("TLS evidence PT_TLS has no owning PT_LOAD")
template = source_bytes[file_offset:file_offset + file_size]
template_path = root / "tls-template.bin"
template_path.write_bytes(template)

def version(command: list[str]) -> str:
    try:
        value = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return value.splitlines()[0][:240] if value.splitlines() else "unavailable"

gcc = version(["aarch64-linux-gnu-gcc", "--version"])
ld = version(["aarch64-linux-gnu-ld", "--version"])
toolchain = f"{gcc}; {ld}"

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

stage_path = root / "stage.json"
stage = json.loads(stage_path.read_text(encoding="utf-8"))
artifact = root / "protected-image.bin"
native_image = root / "native-image.bin"
rehydration = json.loads((root / "rehydration.json").read_text(encoding="utf-8"))
source_hash = digest(source)
artifact_hash = digest(artifact)
native_hash = digest(native_image)
if (
    stage.get("unitId") != unit
    or stage.get("profile") != profile
    or stage.get("sourceSha256") != source_hash
    or stage.get("artifactSha256") != artifact_hash
    or rehydration.get("nativeImageSha256") != native_hash
):
    raise SystemExit("TLS evidence unit/profile/source/protected/native hashes do not match retained artifacts")

evidence = {
    "schemaVersion": 1,
    "model": model,
    "profile": profile,
    "runtime": runtime,
    "lifecycle": lifecycle,
    "expectedEntryStatus": expected_entry_status,
    "result": "accepted-and-runs",
    "sourcePath": "source-image.bin",
    "sourceSha256": source_hash,
    "transformedPath": "protected-image.bin",
    "transformedSha256": artifact_hash,
    "artifactPath": "protected-image.bin",
    "artifactSha256": artifact_hash,
    "nativeImagePath": "native-image.bin",
    "nativeImageSha256": native_hash,
    "runtimeIdentity": runtime_identity,
    "runtimeIdentitySha256": runtime_identity["identitySha256"],
    "toolchainIdentity": toolchain,
    "loaderIdentity": "host-context.sealed-memfd.dlopen",
    "ptTls": {
        "templatePath": "tls-template.bin",
        "templateSha256": digest(template_path),
        "fileSize": file_size,
        "memorySize": memory_size,
        "zeroFillSize": memory_size - file_size,
        "alignment": alignment,
        "owningLoad": owning_load,
    },
    "perThread": "observed",
    "zeroFill": "not-run" if memory_size > file_size else "not-applicable",
    "teardown": "observed",
    "firstFailureStage": None,
    "publicationResult": "published",
    "rollbackResult": "not-applicable",
}
stage["tlsEvidence"] = evidence
fd, temporary = tempfile.mkstemp(prefix="stage.json.", suffix=".tmp", dir=root)
os.close(fd)
try:
    Path(temporary).write_text(json.dumps(stage, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, stage_path)
finally:
    Path(temporary).unlink(missing_ok=True)
PY
(
  cd "$artifact_root"
  find . -type f ! -name 'SHA256SUMS' -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum
) > "$artifact_root/SHA256SUMS"
python3 "$repo_root/scripts/check-protected-image-evidence.py" "$artifact_root" \
  --tier "$tier" --runtime glibc --unit "$unit"
python3 "$repo_root/scripts/check-rehydration-evidence.py" "$artifact_root" \
  --tier "$tier" --runtime glibc --unit "$unit"
printf 'TLS transformed HostContext evidence: PASS (model %s, entry status %s)\n' "$model" "$expected_entry_status"
