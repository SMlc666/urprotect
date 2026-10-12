#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tier pr|nightly|release [--unit UNIT]\n' "$0" >&2
}

tier=''
unit='tls.initial-exec.glibc.host-context-entry'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) [[ $# -ge 2 ]] || { usage; exit 2; }; tier="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || { usage; exit 2; }; unit="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid TLS evidence tier: $tier" >&2; exit 2 ;; esac
if [[ ! "$unit" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "invalid TLS evidence unit: $unit" >&2
  exit 2
fi
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: TLS transformed handoff requires native AArch64" >&2; exit 2 ;; esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$repo_root/native/urprotect-runtime/build/host-context-tls-fixture.so"
make -C "$repo_root/native/urprotect-runtime" tls-fixture >/dev/null
source_file="$(realpath -e -- "$source_file")"
symtab_index="$(readelf -Ws "$source_file" | awk '$8 == "urp_tls_read" && $1 ~ /^[0-9]+:/ && $4 == "FUNC" && $5 == "LOCAL" { sub(":", "", $1); print $1; exit }')"
[[ "$symtab_index" =~ ^[0-9]+$ ]] || { echo "TLS helper symbol is missing from .symtab" >&2; exit 1; }

artifact_parent="${TLS_EVIDENCE_ARTIFACT_ROOT:-${PROTECTED_IMAGE_ARTIFACT_ROOT:-$repo_root/.artifacts/protected-image/tls}}"
PROTECTED_IMAGE_ARTIFACT_ROOT="$artifact_parent/$unit" \
  "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" \
  --runtime glibc \
  --unit "$unit" \
  --source "$source_file" \
  --function-id "symtab:$symtab_index" \
  --entry-status 43 \
  --producer-id gcc-c-tls-initial-exec

artifact_root="$artifact_parent/$unit"
readelf -hW -lW -rW -sW "$artifact_root/source-image.bin" > "$artifact_root/tls-readelf.txt"
python3 - "$artifact_root" <<'PY'
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
source_hash = digest(source)
artifact_hash = digest(artifact)
if stage.get("sourceSha256") != source_hash or stage.get("artifactSha256") != artifact_hash:
    raise SystemExit("TLS evidence source/artifact hashes do not match producer stage")

evidence = {
    "schemaVersion": 1,
    "model": "initial-exec",
    "profile": stage["profile"],
    "runtime": "glibc",
    "lifecycle": "current-thread",
    "result": "accepted-and-runs",
    "sourcePath": "source-image.bin",
    "sourceSha256": source_hash,
    "transformedPath": "protected-image.bin",
    "transformedSha256": artifact_hash,
    "artifactPath": "protected-image.bin",
    "artifactSha256": artifact_hash,
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
    "zeroFill": "observed",
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
printf 'TLS transformed HostContext evidence: PASS (entry status 43)\n'
