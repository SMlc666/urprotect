#!/usr/bin/env bash
set -u -o pipefail

usage() { echo "usage: $0 --tier pr|nightly|release [--unit UNIT] [--artifact-root ROOT]" >&2; }
tier=
unit=runtime.cfi.transformed-backtrace.glibc.host-context-entry
requested_artifact_root=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier|--unit|--artifact-root)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case "$1" in
        --tier) tier="$2" ;;
        --unit) unit="$2" ;;
        --artifact-root) requested_artifact_root="$2" ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid CFI tier" >&2; exit 2 ;; esac
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: CFI requires AArch64" >&2; exit 2 ;; esac
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
artifact_base="$(realpath -m -- "$repo_root/.artifacts/cfi")"
if [[ -z "$requested_artifact_root" ]]; then
  artifact_root="$artifact_base/$tier"
elif [[ "$requested_artifact_root" == /* ]]; then
  artifact_root="$requested_artifact_root"
else
  artifact_root="$repo_root/$requested_artifact_root"
fi
artifact_root="$(realpath -m -- "$artifact_root")"
case "$artifact_root" in
  "$artifact_base"/*) ;;
  *) echo "CFI artifact root must remain under $artifact_base" >&2; exit 2 ;;
esac
if [[ -e "$artifact_root" || -L "$artifact_root" ]]; then
  echo "CFI artifact root already exists; refusing to overwrite: $artifact_root" >&2
  exit 2
fi
mkdir -p -- "$artifact_base"
mkdir -- "$artifact_root" || { echo "could not create fresh CFI artifact root" >&2; exit 2; }

cc_command="${CC:-cc}"
cxx_command="${CXX:-g++}"
[[ "$cc_command" != *[[:space:]]* && "$cxx_command" != *[[:space:]]* ]] || { echo "CFI compiler commands must each name one executable" >&2; exit 2; }
cc_path="$(command -v "$cc_command")" || { echo "CFI C compiler is missing: $cc_command" >&2; exit 2; }
cxx_path="$(command -v "$cxx_command")" || { echo "CFI C++ compiler is missing: $cxx_command" >&2; exit 2; }
make -B -C "$native_root" CC="$cc_command" CXX="$cxx_command" cfi-fixture cfi-runtime-test >"$artifact_root/native-build.stdout" 2>"$artifact_root/native-build.stderr" || exit 1
source_file="$native_root/build/host-context-cfi-fixture.so"
harness="$native_root/build/host-context-cfi-runtime-test"
readelf -dW "$source_file" >"$artifact_root/cfi-fixture-dynamic-readelf.txt" 2>"$artifact_root/cfi-fixture-dynamic-readelf.stderr" || exit 1
if grep -Eq 'libstdc\+\+|libgcc_s' "$artifact_root/cfi-fixture-dynamic-readelf.txt"; then
  echo "C++ runtime dependencies must remain host-harness-only" >&2
  exit 1
fi
cc_path="$(realpath -e -- "$cc_path")"
cxx_path="$(realpath -e -- "$cxx_path")"
cc_version="$("$cc_command" --version | head -n 1)"
cxx_version="$("$cxx_command" --version | head -n 1)"
cc_target="$("$cc_command" -dumpmachine)"
cxx_target="$("$cxx_command" -dumpmachine)"
[[ "$cc_target" == aarch64* && "$cxx_target" == aarch64* ]] || { echo "CFI oracle compilers must target AArch64" >&2; exit 2; }
cc_sha256="$(sha256sum "$cc_path" | awk '{print $1}')"
cxx_sha256="$(sha256sum "$cxx_path" | awk '{print $1}')"
cc_build_id="$(readelf -n "$cc_path" | awk '/Build ID:/ { print $3; exit }')"
cxx_build_id="$(readelf -n "$cxx_path" | awk '/Build ID:/ { print $3; exit }')"
[[ "$cc_build_id" =~ ^[0-9a-fA-F]+$ && "$cxx_build_id" =~ ^[0-9a-fA-F]+$ ]] || { echo "CFI compilers must expose ELF build IDs" >&2; exit 1; }
python3 "$repo_root/scripts/tls_runtime_identity.py" >"$artifact_root/glibc-runtime-identity.json" || exit 1
link_dependencies="$(ldd "$harness")" || { echo "could not resolve CFI C++ runtime dependencies" >&2; exit 1; }
resolve_runtime_library() {
  local soname="$1" path build_id sha
  path="$(printf '%s\n' "$link_dependencies" | awk -v soname="$soname" '$1 == soname && $2 == "=>" { print $3; exit }')"
  [[ -n "$path" && -f "$path" ]] || { echo "missing required CFI runtime library: $soname" >&2; return 1; }
  path="$(realpath -e -- "$path")"
  sha="$(sha256sum "$path" | awk '{print $1}')"
  build_id="$(readelf -n "$path" | awk '/Build ID:/ { print $3; exit }')"
  [[ "$build_id" =~ ^[0-9a-fA-F]+$ ]] || { echo "runtime library lacks a bounded ELF build ID: $soname" >&2; return 1; }
  printf '%s\t%s\t%s\t%s\n' "$soname" "$path" "$sha" "$build_id"
}
libstdcxx_identity="$(resolve_runtime_library libstdc++.so.6)" || exit 1
libgcc_identity="$(resolve_runtime_library libgcc_s.so.1)" || exit 1
python3 - "$artifact_root/cpp-runtime-identity.json" "$(uname -m)" "$cc_path" "$cc_version" "$cc_target" "$cc_sha256" "$cc_build_id" "$cxx_path" "$cxx_version" "$cxx_target" "$cxx_sha256" "$cxx_build_id" "$libstdcxx_identity" "$libgcc_identity" "$artifact_root/glibc-runtime-identity.json" <<'PYIDENTITY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1])
def runtime(row):
    soname,resolved,sha,build_id=row.split("\t")
    return {"soname":soname,"resolvedPath":resolved,"sha256":sha,"buildId":build_id}
record={"schemaVersion":1,"hostArchitecture":sys.argv[2],
 "cCompiler":{"path":sys.argv[3],"version":sys.argv[4],"target":sys.argv[5],"sha256":sys.argv[6],"buildId":sys.argv[7]},
 "cxxCompiler":{"path":sys.argv[8],"version":sys.argv[9],"target":sys.argv[10],"sha256":sys.argv[11],"buildId":sys.argv[12]},
 "libstdcxx":runtime(sys.argv[13]),"libgccUnwinder":runtime(sys.argv[14]),
 "glibcRuntimeIdentity":json.loads(pathlib.Path(sys.argv[15]).read_text(encoding="utf-8"))}
path.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n",encoding="utf-8")
PYIDENTITY
readelf -SW --debug-dump=frames -Ws "$harness" >"$artifact_root/cpp-harness-unwind-readelf.txt" 2>"$artifact_root/cpp-harness-unwind-readelf.stderr" || exit 1
entry_record="$(readelf --dyn-syms -W "$source_file" | awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "urp_entry" { sub(":", "", $1); print "dynsym:" $1, "0x" $2, $3 }')"
target_record="$(readelf -Ws "$source_file" | awk '$4 == "FUNC" && $5 == "LOCAL" && $8 == "urp_transform_target" && $1 ~ /^[0-9]+:/ { print "0x" $2, $3 }')"
read -r function_id entry_source_vaddr entry_source_size <<<"$entry_record"
read -r target_source_vaddr target_source_size <<<"$target_record"
[[ "$function_id" =~ ^dynsym:[0-9]+$ && "$target_source_vaddr" =~ ^0x[0-9a-fA-F]+$ && "$entry_source_vaddr" =~ ^0x[0-9a-fA-F]+$ ]]
[[ "$entry_source_vaddr" == "$target_source_vaddr" && "$entry_source_size" == "$target_source_size" ]] || {
  echo "selected CFI target must share the exact urp_entry source address and extent" >&2
  exit 1
}
positive="$artifact_root/positive/$unit"
mkdir -p "$artifact_root/positive"
PROTECTED_IMAGE_ARTIFACT_ROOT="$positive" "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" --runtime glibc --unit "$unit" --source "$source_file" \
  --function-id "$function_id" --entry-status 42 --producer-id gcc-c-cfi-fixture \
  >"$artifact_root/rehydration.stdout" 2>"$artifact_root/rehydration.stderr" || exit 1
# The positive artifact root already ends in the selected unit ID.

set +e
"$harness" "$positive/source-image.bin" >"$positive/baseline-unwind.txt" 2>"$positive/baseline-unwind.stderr"
baseline_status=$?
read -r target_vaddr target_size < <(python3 - "$positive/rehydration.json" "$target_source_vaddr" <<'PYMAP'
import json,sys
record=json.load(open(sys.argv[1]))
entries=record["layoutEvidence"]["addressMap"]
source_vaddr=int(sys.argv[2], 0)
def address_value(value):
    if isinstance(value, bool):
        raise SystemExit("CFI address map contains a Boolean address")
    return value if isinstance(value, int) else int(value, 0)
regions=[entry for entry in entries if address_value(entry["sourceRange"]["virtualAddress"]["value"]) == source_vaddr]
if len(regions) != 1:
    raise SystemExit("CFI source function is not uniquely mapped")
region=regions[0]["outputRange"]
print(region["virtualAddress"]["value"], region["size"])
PYMAP
)
# urp_entry remains the public stub; the protected CFI body is a relocated
# address-map range. Pass the actual emitted FDE interval to the harness so its
# frame checks follow code that can really unwind rather than the stub.
read -r emitted_frame_vaddr emitted_frame_size < <(python3 - "$positive/source-image.bin" "$positive/native-image.bin" "$target_vaddr" "$target_size" <<'PYFDE'
import re, struct, subprocess, sys

def fdes(path):
    dump = subprocess.check_output(["readelf", "--debug-dump=frames", path], text=True)
    return [(int(a, 16), int(b, 16)) for a, b in re.findall(
        r"\bFDE cie=[0-9a-fA-F]+\s+pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)", dump
    )]

source_ranges = fdes(sys.argv[1])
emitted_ranges = fdes(sys.argv[2])
map_start, map_size = int(sys.argv[3], 0), int(sys.argv[4], 0)
if len(source_ranges) == 0 or len(emitted_ranges) == 0:
    raise SystemExit("CFI fixture lacks source or emitted FDE records")
output_fdes = [item for item in emitted_ranges if map_start <= item[0] < item[1] <= map_start + map_size]
if len(output_fdes) != 1:
    raise SystemExit("CFI mapped target must contain exactly one emitted FDE")
start, end = output_fdes[0]
if start <= 0 or end <= start:
    raise SystemExit("CFI relocated FDE must have a nonzero extent")
image = open(sys.argv[2], "rb").read()
if image[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<HH", image, 16) != (3, 183):
    raise SystemExit("CFI transformed image must be AArch64 ELF64 little-endian ET_DYN")
phoff = struct.unpack_from("<Q", image, 32)[0]
ehsize, phentsize, phnum = struct.unpack_from("<HHH", image, 52)
if ehsize != 64 or phentsize < 56 or phnum == 0 or phoff + phentsize * phnum > len(image):
    raise SystemExit("invalid CFI program-header table")
loads = []
owners = []
for index in range(phnum):
    off = phoff + phentsize * index
    kind, flags, file_offset, vaddr, _paddr, filesz, memsz, _align = struct.unpack_from("<IIQQQQQQ", image, off)
    if kind != 1:
        continue
    if file_offset + filesz > len(image) or filesz > memsz or vaddr + memsz > 1 << 64:
        raise SystemExit("invalid CFI PT_LOAD bounds")
    loads.append((file_offset, file_offset + filesz, vaddr, vaddr + memsz))
    if flags & 1 and vaddr <= start < end <= vaddr + filesz:
        owners.append((file_offset, vaddr, filesz))
for index, (file_start, file_end, va_start, va_end) in enumerate(loads):
    for other_file_start, other_file_end, other_va_start, other_va_end in loads[index + 1:]:
        if va_start < other_va_end and other_va_start < va_end:
            raise SystemExit("overlapping CFI PT_LOAD virtual ranges")
        if file_start < file_end and other_file_start < other_file_end and file_start < other_file_end and other_file_start < file_end:
            raise SystemExit("overlapping CFI PT_LOAD file ranges")
if len(owners) != 1:
    raise SystemExit("relocated FDE does not lie uniquely inside a file-backed executable LOAD")
print(hex(start), end - start)
PYFDE
)
if [[ -z "$target_vaddr" || -z "$target_size" || -z "$emitted_frame_vaddr" || -z "$emitted_frame_size" ]]; then
  echo 'CFI mapped target or relocated FDE proof absent' >&2
  exit 1
fi
printf 'mappedFdeVaddr=%s mappedFdeSize=%s\n' \
  "$emitted_frame_vaddr" "$emitted_frame_size" >"$positive/transformed-fde-range.txt"
"$harness" "$positive/native-image.bin" --expect-transformed --target-vaddr "$emitted_frame_vaddr" --target-size "$emitted_frame_size" >"$positive/transformed-unwind.txt" 2>"$positive/transformed-unwind.stderr"
transformed_status=$?
set -e
[ "$baseline_status" -eq 0 ] && [ "$transformed_status" -eq 0 ] || exit 1

python3 - "$positive" "$function_id" "$source_file" "$baseline_status" "$transformed_status" "$artifact_root/cpp-runtime-identity.json" "$target_source_vaddr" "$target_vaddr" "$target_size" "$emitted_frame_vaddr" "$emitted_frame_size" <<'PY'
import hashlib, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
def parse(path):
    output = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        for key, value in re.findall(r"([A-Za-z][A-Za-z0-9]*)=([^ ]+)", line):
            output[key] = int(value, 16) if value.startswith("0x") else int(value) if value.isdigit() else value
    return output
baseline = parse(root / "baseline-unwind.txt")
transformed = parse(root / "transformed-unwind.txt")
cpp_keys = (
    "cppBoundaryStatus", "cppRegisterCallAttempted", "cppRegisterCallReturned",
    "cppTargetNormalReturned", "cppCaughtSpecificType", "cppCaughtToken",
    "cppRaiiCleanupCount", "cppHostCallbackEntered", "cppHostCallbackReturned",
    "cppThrowSiteTargetFrameObserved", "cppThrowSiteFrameCount",
    "cppThrowSiteReturnAddressInTarget", "cppThrowSiteReturnPc",
    "cppThrowSiteTargetFramePc", "imageLoadBias", "loadedEntryAddress",
    "loadedEntryVaddr", "mappedTargetVaddr", "mappedTargetSize",
    "callbackReturnPc", "targetFramePc", "targetRangeStart", "targetRangeEnd", "targetSymbolSize",
)
runtime_identity_path = pathlib.Path(sys.argv[6])
runtime_identity_digest = hashlib.sha256(runtime_identity_path.read_bytes()).hexdigest()
harness_readelf = (pathlib.Path(sys.argv[6]).parent / "cpp-harness-unwind-readelf.txt").read_text(encoding="utf-8", errors="replace")
def symbol_values(name, kind=None):
    type_pattern = re.escape(kind) if kind else r"\S+"
    pattern = re.compile(
        rf"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+{type_pattern}\s+\S+\s+\S+\s+\S+\s+{re.escape(name)}$",
        re.MULTILINE,
    )
    return {(int(address, 16), int(size)) for address, size in pattern.findall(harness_readelf)}
call_function = symbol_values("urp_cfi_invoke_with_registers", "FUNC")
call_return_symbol = symbol_values("urp_cfi_invoke_with_registers_call_return")
if len(call_function) != 1 or len(call_return_symbol) != 1:
    raise SystemExit("register-call function/return-PC symbols are not unique in retained readelf output")
call_function_start, call_function_size = next(iter(call_function))
call_return_pc, _ = next(iter(call_return_symbol))
if not (call_function_start <= call_return_pc < call_function_start + call_function_size):
    raise SystemExit("register-call return-PC symbol is outside the assembly function")
rehydration = json.loads((root / "rehydration.json").read_text(encoding="utf-8"))
def address_value(value):
    return int(value, 0) if isinstance(value, str) else int(value)
source_vaddr = int(sys.argv[7], 0)
output_vaddr = int(sys.argv[8], 0)
target_size = int(sys.argv[9], 0)
relocated_fde_vaddr = int(sys.argv[10], 0)
relocated_fde_size = int(sys.argv[11], 0)
address_entries = rehydration["layoutEvidence"]["addressMap"]
address_region = next(
    item for item in address_entries
    if address_value(item["sourceRange"]["virtualAddress"]["value"]) == source_vaddr
)
if (address_value(address_region["outputRange"]["virtualAddress"]["value"]) != output_vaddr
        or int(address_region["outputRange"]["size"]) != target_size):
    raise SystemExit("transformed CFI target invocation differs from the rehydration address map")
stage = json.loads((root / "stage.json").read_text(encoding="utf-8"))
record = {
    "schemaVersion": 2,
    "unitId": stage["unitId"],
    "selectedFunction": sys.argv[2],
    "sourceFixtureSha256": hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest(),
    "targetAddressMap": {
        "sourceVirtualAddress": source_vaddr,
        "outputVirtualAddress": output_vaddr,
        "size": target_size,
    },
    "relocatedFde": {
        "virtualAddress": relocated_fde_vaddr,
        "size": relocated_fde_size,
    },
    "registerCallUnwindWitness": {
        "functionSymbol": "urp_cfi_invoke_with_registers",
        "callReturnPcSymbol": "urp_cfi_invoke_with_registers_call_return",
        "functionStart": call_function_start,
        "functionSize": call_function_size,
        "callReturnPc": call_return_pc,
        "callReturnOffset": call_return_pc - call_function_start,
    },
    "sourceImageSha256": hashlib.sha256((root / "source-image.bin").read_bytes()).hexdigest(),
    "protectedImageSha256": hashlib.sha256((root / "protected-image.bin").read_bytes()).hexdigest(),
    "nativeImageSha256": hashlib.sha256((root / "native-image.bin").read_bytes()).hexdigest(),
    "baseline": baseline,
    "transformed": transformed,
    "baselineStatus": int(sys.argv[4]),
    "transformedStatus": int(sys.argv[5]),
    "frameCountEqual": baseline.get("frameCount") == transformed.get("frameCount"),
    "transformedFrameObserved": transformed.get("transformedFrameObserved") == 1,
    "entryStatusEqual": baseline.get("targetStatus") == transformed.get("targetStatus") == 42,
    "releaseStatusEqual": baseline.get("releaseStatus") == transformed.get("releaseStatus") == 0,
    "sourceDirectTargetTransformedAddressMap": baseline.get("targetInvocationMode") == "direct-symbol" and transformed.get("targetInvocationMode") == "address-map",
    "registerFrameStateEqual": all(baseline.get(key) == transformed.get(key) == 1 for key in ("framePointerAligned", "returnAddressInTarget", "registersPreserved")),
    "signalBoundaryEqual": baseline.get("signalBoundary") == transformed.get("signalBoundary") == 1,
    "signalFrameObserved": transformed.get("signalFrameObserved") == 1,
    "longjmpBoundaryEqual": baseline.get("longjmpBoundary") == transformed.get("longjmpBoundary") == 1,
    "cancellationBoundaryEqual": baseline.get("cancellationBoundary") == transformed.get("cancellationBoundary") == 1,
    "cppException": {
        "oracleKind": "typed-cpp-throw-catch-through-mapped-cfi-target-v1",
        "runtimeIdentitySha256": runtime_identity_digest,
        "requiredToken": int("0x4346495f45584331", 16),
        "baseline": {key: baseline.get(key) for key in cpp_keys},
        "transformed": {key: transformed.get(key) for key in cpp_keys},
    },
    "firstFailureStage": None,
}
(root / "cfi-behavior.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
readelf -SW --debug-dump=frames "$positive/source-image.bin" >"$positive/source-unwind-readelf.txt" 2>"$positive/source-unwind-readelf.stderr"
readelf -SW --debug-dump=frames "$positive/native-image.bin" >"$positive/native-unwind-readelf.txt" 2>"$positive/native-unwind-readelf.stderr"
(
  cd "$positive"
  find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum
) >"$positive/SHA256SUMS"

negative="$artifact_root/negative-malformed-eh-frame"
mkdir -p "$negative"
cp "$positive/source-image.bin" "$negative/source-image.bin"
python3 - "$negative/source-image.bin" <<'PY'
from pathlib import Path
import struct,sys
p=Path(sys.argv[1]); d=bytearray(p.read_bytes())
shoff=struct.unpack_from("<Q",d,40)[0]; ent=struct.unpack_from("<H",d,58)[0]
num=struct.unpack_from("<H",d,60)[0]; names_i=struct.unpack_from("<H",d,62)[0]
names_h=shoff+names_i*ent; names_off=struct.unpack_from("<Q",d,names_h+24)[0]; names_size=struct.unpack_from("<Q",d,names_h+32)[0]
names=d[names_off:names_off+names_size]; target=None
for i in range(num):
    h=shoff+i*ent; name=struct.unpack_from("<I",d,h)[0]; end=names.find(b"\0",name)
    if names[name:end]==b".eh_frame": target=struct.unpack_from("<Q",d,h+24)[0]; break
if target is None: raise SystemExit("missing eh_frame")
struct.pack_into("<I",d,target,0xffff); p.write_bytes(d)
PY
source_sha="$(sha256sum "$negative/source-image.bin" | cut -d' ' -f1)"
set +e
dotnet "$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll" protect-image "$negative/source-image.bin" \
  --artifact "$negative/protected-image.bin" --role "$negative/protected-image.json" \
  --manifest "$negative/SHA256SUMS" --stage "$negative/stage.json" \
  --unit "$unit.negative" --profile host-context-entry --producer-id gcc-c-cfi-negative \
  --rehydrator urprotect.rehydrator.v1 --source-sha256 "$source_sha" \
  --function-id "$function_id" --pass control-flow-flattening --json - \
  >"$negative/producer.stdout" 2>"$negative/producer.stderr"
negative_status=$?
set -e
[ "$negative_status" -ne 0 ] && [ ! -e "$negative/protected-image.bin" ] && [ ! -e "$negative/protected-image.json" ] || exit 1
python3 - "$negative" "$negative_status" <<'PY'
import json,pathlib,sys
pathlib.Path(sys.argv[1],"negative-result.json").write_text(json.dumps({
 "schemaVersion":1,"status":"passed","producerExitStatus":int(sys.argv[2]),
 "nativeImagePublished":False,"protectedImagePublished":False,"loaderInvoked":False,
 "expectedDiagnosticFamily":"UnwindMetadataMalformed","firstFailureStage":"protect-image"
},indent=2,sort_keys=True)+"\n")
PY
(cd "$artifact_root" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$artifact_root/SHA256SUMS"
python3 "$repo_root/scripts/check-cfi-evidence.py" "$artifact_root" --tier "$tier" --runtime glibc --unit "$unit"
python3 "$repo_root/scripts/check-rehydration-evidence.py" "$positive" --tier "$tier" --runtime glibc --unit "$unit"
printf 'CFI transformed HostContext evidence: PASS\n'
