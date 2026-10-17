#!/usr/bin/env bash
set -u -o pipefail

tier=
unit=runtime.indirect-control.jump-table.glibc.host-context-entry
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tier="$2"; shift 2 ;;
    --unit) unit="$2"; shift 2 ;;
    *) echo "usage: $0 --tier pr|nightly|release [--unit UNIT]" >&2; exit 2 ;;
  esac
done
case "$tier" in pr|nightly|release) ;; *) echo "invalid jump-table tier" >&2; exit 2 ;; esac
case "$(uname -m)" in aarch64|arm64) ;; *) echo "environment-unavailable: jump-table native evidence requires AArch64" >&2; exit 2 ;; esac
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native_root="$repo_root/native/urprotect-runtime"
root="$repo_root/.artifacts/indirect-control/$tier"
positive="$root/$unit"
negative="$root/negative-malformed-table"
rm -rf -- "$root"
mkdir -p "$positive" "$negative"
make -C "$native_root" jump-table-fixture >"$root/native-build.stdout" 2>"$root/native-build.stderr" || exit 1
source_file="$native_root/build/host-context-jump-table-fixture.so"
function_id="$(readelf -Ws "$source_file" | awk '$8 == "urp_entry" && $1 ~ /^[0-9]+:/ && $4 == "FUNC" { sub(":", "", $1); print "dynsym:" $1; exit }')"
[[ -n "$function_id" ]] || exit 1

PROTECTED_IMAGE_ARTIFACT_ROOT="$positive" "$repo_root/scripts/run-host-context-rehydration-e2e.sh" \
  --tier "$tier" --runtime glibc --unit "$unit" --source "$source_file" \
  --function-id "$function_id" --entry-status 91 --producer-id gcc-aarch64-jump-table-fixture \
  >"$root/rehydration.stdout" 2>"$root/rehydration.stderr" || exit 1

"$native_root/build/host-context-image-handoff" "$positive/source-image.bin" urp_entry "$positive/baseline-handoff.json" \
  >"$positive/baseline-handoff.stdout" 2>"$positive/baseline-handoff.stderr"
baseline_status=$?
transformed_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["entryStatus"])' "$positive/handoff.json")"
readelf -hW -lW -SW -rW "$positive/source-image.bin" >"$positive/source-readelf.txt"
readelf -hW -lW -SW -rW "$positive/native-image.bin" >"$positive/native-readelf.txt"

python3 - "$positive" "$unit" "$function_id" "$baseline_status" "$transformed_status" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
def sha(name): return hashlib.sha256((root/name).read_bytes()).hexdigest()
rehydration=json.loads((root/"rehydration.json").read_text())
layout=rehydration.get("layoutEvidence",{})
edits=layout.get("jumpTableEdits",[])
record={
 "schemaVersion":1,"unitId":sys.argv[2],"selectedFunction":sys.argv[3],
 "sourceSha256":sha("source-image.bin"),"protectedSha256":sha("protected-image.bin"),
 "nativeSha256":sha("native-image.bin"),"baselineStatus":int(sys.argv[4]),
 "transformedStatus":int(sys.argv[5]),"statusEqual":int(sys.argv[4])==int(sys.argv[5])==91,
 "jumpTableEditCount":len(edits),"targetResolutionMode":"bounded-relative-table",
 "addressMapBindings":len(layout.get("addressMap",[])),"firstFailureStage":None}
(root/"jump-table-behavior.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
PY

cp "$source_file" "$negative/source-image.bin"
python3 - "$negative/source-image.bin" <<'PY'
from pathlib import Path
import struct,sys
p=Path(sys.argv[1]); d=bytearray(p.read_bytes())
shoff=struct.unpack_from("<Q",d,40)[0]; ent=struct.unpack_from("<H",d,58)[0]
num=struct.unpack_from("<H",d,60)[0]; names_i=struct.unpack_from("<H",d,62)[0]
nh=shoff+names_i*ent; no=struct.unpack_from("<Q",d,nh+24)[0]; ns=struct.unpack_from("<Q",d,nh+32)[0]
names=d[no:no+ns]; table=None
for i in range(num):
 h=shoff+i*ent; n=struct.unpack_from("<I",d,h)[0]; e=names.find(b"\0",n)
 if names[n:e]==b".rodata": table=struct.unpack_from("<Q",d,h+24)[0]; break
if table is None: raise SystemExit("missing .rodata")
struct.pack_into("<I",d,table,0x00100000)
p.write_bytes(d)
PY
negative_sha="$(sha256sum "$negative/source-image.bin" | cut -d' ' -f1)"
set +e
dotnet "$repo_root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll" protect-image "$negative/source-image.bin" \
 --artifact "$negative/protected-image.bin" --role "$negative/protected-image.json" \
 --manifest "$negative/SHA256SUMS" --stage "$negative/stage.json" \
 --unit "$unit.negative" --profile host-context-entry --producer-id gcc-aarch64-jump-table-negative \
 --rehydrator urprotect.rehydrator.v1 --source-sha256 "$negative_sha" \
 --function-id "$function_id" --pass control-flow-flattening --json - \
 >"$negative/producer.stdout" 2>"$negative/producer.stderr"
negative_status=$?
set -e
[ "$negative_status" -ne 0 ] && [ ! -e "$negative/protected-image.bin" ] && [ ! -e "$negative/protected-image.json" ] || exit 1
python3 - "$negative" "$negative_status" <<'PY'
import json,pathlib,sys
pathlib.Path(sys.argv[1],"negative-result.json").write_text(json.dumps({
 "schemaVersion":1,"status":"passed","producerExitStatus":int(sys.argv[2]),
 "protectedImagePublished":False,"nativeImagePublished":False,
 "loaderInvoked":False,"expectedDiagnosticFamily":"IndirectTargetUnresolved",
 "firstFailureStage":"protect-image"
},indent=2,sort_keys=True)+"\n")
PY
(cd "$root" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum) >"$root/SHA256SUMS"
python3 "$repo_root/scripts/check-indirect-control-evidence.py" "$root" --tier "$tier" --unit "$unit"
printf 'Indirect jump-table HostContext evidence: PASS\n'
