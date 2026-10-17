#!/usr/bin/env bash
set -u -o pipefail

tier=
unit=runtime.cfi.transformed-backtrace.glibc.host-context-entry
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tier="$2"; shift 2 ;;
    --unit) unit="$2"; shift 2 ;;
    *) echo "usage: $0 --tier pr|nightly|release [--unit UNIT]" >&2; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid CFI tier" >&2; exit 2 ;; esac
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: CFI requires AArch64" >&2; exit 2 ;; esac
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
artifact_root="$repo_root/.artifacts/cfi/$tier"
rm -rf -- "$artifact_root"
mkdir -p "$artifact_root"

make -C "$native_root" cfi-fixture cfi-runtime-test >"$artifact_root/native-build.stdout" 2>"$artifact_root/native-build.stderr" || exit 1
source_file="$native_root/build/host-context-cfi-fixture.so"
harness="$native_root/build/host-context-cfi-runtime-test"
function_id="$(readelf -Ws "$source_file" | awk '$8 == "urp_transform_target" && $1 ~ /^[0-9]+:/ && $5 == "LOCAL" { sub(":", "", $1); print "symtab:" $1; exit }')"
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
# The public urp_entry remains the original stub, while the protected body
# and its .eh_frame FDE are relocated into the emitted executable LOAD.
# Independently extract the *one* real FDE coverage range from GNU readelf,
# prove it belongs to that new executable range, and pass it as the observed
# frame extent. Calling the stub and observing its relocated frame are distinct.
read -r emitted_frame_vaddr emitted_frame_size < <(
  python3 - "$positive/source-image.bin" "$positive/native-image.bin" <<'PY'
import re, subprocess, sys

def fdes(path):
    dump = subprocess.check_output(
        ["readelf", "--debug-dump=frames", path], text=True)
    return [(int(a, 16), int(b, 16)) for a, b in re.findall(
        r"\bFDE cie=[0-9a-fA-F]+\s+pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)",
        dump)]

source, emitted = map(fdes, sys.argv[1:])
if len(source) != 1 or len(emitted) != 1:
    raise SystemExit("CFI fixture requires exactly one source and one emitted FDE")
start, end = emitted[0]
if start <= 0 or end <= start or (start, end) == source[0]:
    raise SystemExit("CFI protected FDE must genuinely relocate and have nonzero extent")
# Prove the FDE lies wholly inside a newly materialized executable LOAD
# rather than accepting unrelated executable addresses as test evidence.
from pathlib import Path
import struct
image = Path(sys.argv[2]).read_bytes()
if image[:4] != b"\x7fELF" or image[4] != 2 or image[5] != 1:
    raise SystemExit("CFI transformed ELF must be little-endian ELF64")
phoff = struct.unpack_from("<Q", image, 32)[0]
phentsize = struct.unpack_from("<H", image, 54)[0]
phnum = struct.unpack_from("<H", image, 56)[0]
if phentsize != 56 or phnum == 0 or phoff + phentsize * phnum > len(image):
    raise SystemExit("invalid CFI program-header table")
covered = False
for i in range(phnum):
    off = phoff + phentsize * i
    kind, flags = struct.unpack_from("<II", image, off)
    vaddr, filesz, memsz = (
        struct.unpack_from("<Q", image, off + 16)[0],
        struct.unpack_from("<Q", image, off + 32)[0],
        struct.unpack_from("<Q", image, off + 40)[0])
    if kind == 1 and flags & 1 and vaddr <= start < end <= vaddr + filesz <= vaddr + memsz:
        covered = True
        break
if not covered:
    raise SystemExit("relocated FDE does not lie inside a file-backed executable LOAD")
print(hex(start), hex(end-start))
PY
)
if [[ -z "$emitted_frame_vaddr" || -z "$emitted_frame_size" ]]; then
  echo 'CFI relocated FDE proof absent' >&2
  exit 1
fi
printf 'mappedFdeVaddr=%s mappedFdeSize=%s\n' \
  "$emitted_frame_vaddr" "$emitted_frame_size" >"$positive/transformed-fde-range.txt"
"$harness" "$positive/native-image.bin" --expect-transformed \
  --target-vaddr "$emitted_frame_vaddr" --target-size "$emitted_frame_size" \
  >"$positive/transformed-unwind.txt" 2>"$positive/transformed-unwind.stderr"
transformed_status=$?
set -e
[ "$baseline_status" -eq 0 ] && [ "$transformed_status" -eq 0 ] || exit 1

python3 - "$positive" "$function_id" "$source_file" <<'PY'
import hashlib, json, pathlib, re, sys
root=pathlib.Path(sys.argv[1])
def parse(path):
    out={}
    for line in path.read_text().splitlines():
        for key,value in re.findall(r"([A-Za-z][A-Za-z0-9]*)=([^ ]+)", line):
            out[key]=int(value,16) if value.startswith("0x") else int(value) if value.isdigit() else value
    return out
b=parse(root/"baseline-unwind.txt")
t=parse(root/"transformed-unwind.txt")
stage=json.loads((root/"stage.json").read_text())
record={
 "schemaVersion":1,"unitId":stage["unitId"],"selectedFunction":sys.argv[2],
 "sourceFixtureSha256":hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest(),
 "sourceImageSha256":hashlib.sha256((root/"source-image.bin").read_bytes()).hexdigest(),
 "protectedImageSha256":hashlib.sha256((root/"protected-image.bin").read_bytes()).hexdigest(),
 "nativeImageSha256":hashlib.sha256((root/"native-image.bin").read_bytes()).hexdigest(),
 "baseline":b,"transformed":t,"baselineStatus":0,"transformedStatus":0,
 "frameCountEqual":b.get("frameCount")==t.get("frameCount"),
 "transformedFrameObserved":t.get("transformedFrameObserved")==1,
 "entryStatusEqual":b.get("targetStatus")==t.get("targetStatus")==42,
 "releaseStatusEqual":b.get("releaseStatus")==t.get("releaseStatus")==0,
 "firstFailureStage":None}
(root/"cfi-behavior.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
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
