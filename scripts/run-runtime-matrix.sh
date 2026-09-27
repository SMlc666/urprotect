#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tier="${1:-pr}"
out="${RUNTIME_MATRIX_ARTIFACT_ROOT:-${root}/.artifacts/runtime-matrix/${tier}}"
case "$tier" in pr|nightly|release) ;; *) echo 'tier must be pr, nightly, or release' >&2; exit 2;; esac
out="$(realpath -m "$out")"
case "$out" in
  "$root"/.artifacts/runtime-matrix/*) ;;
  *) echo "runtime matrix evidence root must be under .artifacts/runtime-matrix: $out" >&2; exit 2 ;;
esac
cleanup_pinned_musl_loader() {
  local toolchain_root="${MUSL_TOOLCHAIN_ROOT:-}"
  local marker="$out/package-locks/musl-1.2.4/created-loader-link.txt"
  local cleanup_record="$out/package-locks/musl-1.2.4/loader-link-cleanup.txt"
  if [[ -n "$toolchain_root" && -s "$marker" ]]; then
    [[ ! -s "$cleanup_record" ]] || return 0
    local loader; loader="$(<"$marker")"
    if [[ -L "$loader" && "$(readlink -f "$loader")" == "$toolchain_root/lib/libc.so" ]]; then
      if [[ "$(id -u)" == 0 ]]; then
        rm -f -- "$loader"
      elif command -v sudo >/dev/null; then
        sudo rm -f -- "$loader"
    else
      echo "cannot remove owned native musl loader symlink without sudo: $loader" >&2
      printf 'path=%s\nstatus=cleanup-failed\n' "$loader" > "$cleanup_record"
      return 1
      fi
    elif [[ -e "$loader" || -L "$loader" ]]; then
      echo "native musl loader symlink changed owner or target before cleanup: $loader" >&2
      printf 'path=%s\nstatus=cleanup-failed\n' "$loader" > "$cleanup_record"
      return 1
    fi
    printf 'path=%s\nstatus=removed\n' "$loader" > "$cleanup_record"
    local toolchain_evidence; toolchain_evidence="$(dirname "$toolchain_root")"
    find "$toolchain_evidence" -type f ! -path "$toolchain_evidence/SHA256SUMS" \
      -print0 | sort -z | xargs -0 sha256sum > "$toolchain_evidence/SHA256SUMS"
  fi
}
trap cleanup_pinned_musl_loader EXIT
[[ "$(uname -m)" == aarch64 ]] || { echo "native AArch64 runtime matrix required; got $(uname -m)" >&2; exit 2; }
if [[ -n "${ANDROID_ROOT:-}" || -n "${ANDROID_DATA:-}" || -e /system/bin/linker64 || -e /dev/binder || -e /dev/vndbinder ]]; then
  echo 'runtime matrix requires the native Ubuntu Linux runner, not an Android host context' >&2
  exit 2
fi
host_os_id="$(awk -F= '$1=="ID" {gsub(/"/,"",$2); print $2}' /etc/os-release)"
host_os_version="$(awk -F= '$1=="VERSION_ID" {gsub(/"/,"",$2); print $2}' /etc/os-release)"
[[ "$host_os_id" == ubuntu && "$host_os_version" == 24.04 ]] || {
  echo "runtime matrix current glibc cell requires Ubuntu 24.04; got ${host_os_id:-unknown}/${host_os_version:-unknown}" >&2
  exit 2
}
for tool in gcc ld readelf sha256sum uname getconf timeout dotnet python3; do command -v "$tool" >/dev/null || { echo "required tool missing: $tool" >&2; exit 127; }; done
# Remove generated runtime evidence before producing this invocation; preserve
# separately produced runner and package-lock facts in their owned directories.
mkdir -p "$out"
rm -rf -- "$out/fixtures" "$out/cells"
rm -f -- "$out/run-manifest.txt" "$out/SHA256SUMS" "$out/registry-validation.txt" "$out/kernel-page.16k.native-aarch64.result.txt"
mkdir -p "$out/fixtures" "$out/cells"
python3 "$root/scripts/validate-runtime-matrix.py" "$root/fixtures/runtime-matrix.json" > "$out/registry-validation.txt"
cli=(dotnet run --project "$root/src/UrProtect.Cli" --configuration Release --no-build --no-restore --)
cat > "$out/fixtures/probe.c" <<'C'
#include <unistd.h>
int main(void) { static const char msg[] = "runtime-matrix-fixture-ok\n"; return write(1,msg,sizeof(msg)-1)==(ssize_t)(sizeof(msg)-1)?0:71; }
C

# The dedicated checker bounds and validates every PT_LOAD p_align field.
check_load_alignment() {
  python3 "$root/scripts/check-pt-load-alignment.py" "$1" "$2"
}

validate_and_run() {
  local id="$1" binary="$2" cell="$out/cells/$1" expected_align="$3"
  local expected_interpreter="$4" expected_needed="$5"
  mkdir -p "$cell"
  readelf -hW -lW -dW "$binary" > "$cell/readelf.txt"
  python3 "$root/scripts/check-runtime-fixture.py" "$cell/readelf.txt" \
    "$expected_align" "$expected_interpreter" "$expected_needed" \
    > "$cell/fixture-identity.txt"
  check_load_alignment "$cell/readelf.txt" "$expected_align" > "$cell/pt-load-alignment.txt"
  set +e
  timeout 20 "$binary" > "$cell/stdout" 2> "$cell/stderr"; local direct=$?
  timeout 120 "${cli[@]}" validate "$binary" --no-analysis --copy "$cell/parser-copy" > "$cell/validator.stdout" 2> "$cell/validator.stderr"; local validate=$?
  local copy_status=125
  if [[ "$validate" == 0 && -s "$cell/parser-copy" ]]; then
    timeout 20 "$cell/parser-copy" > "$cell/copy.stdout" 2> "$cell/copy.stderr"; copy_status=$?
  fi
  set -e
  printf 'direct=%s\nvalidate=%s\ncopy=%s\n' "$direct" "$validate" "$copy_status" > "$cell/status.txt"
  cmp "$cell/stdout" "$cell/copy.stdout"; cmp "$cell/stderr" "$cell/copy.stderr"
  [[ $direct == 0 && $validate == 0 && $copy_status == 0 ]]
  cmp "$binary" "$cell/parser-copy"
  cp "$cell/parser-copy" "$binary.urp-copy"
  cp "$cell/copy.stdout" "$binary.copy.stdout"
  cp "$cell/copy.stderr" "$binary.copy.stderr"
  cat "$cell/status.txt" > "$cell/oracle.log"
  cat "$cell/stdout" >> "$cell/oracle.log"
  printf '%s  %s\n' "$(sha256sum "$binary" | awk '{print $1}')" "$(basename "$binary")" > "$cell/source.sha256"
  printf '%s  parser-copy\n' "$(sha256sum "$cell/parser-copy" | awk '{print $1}')" > "$cell/copy.sha256"
  local assembly="$root/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
  [[ -s "$assembly" ]] || { echo "UrProtect CLI assembly missing: $assembly" >&2; return 1; }
  local app_hash; app_hash="$(sha256sum "$assembly" | awk '{print $1}')"
  printf '{"status":"validated","directStatus":%s,"validatorStatus":%s,"copyStatus":%s,"streamsMatch":true,"application":"UrProtect CLI validate --no-analysis --copy","applicationBuildSha256":"sha256:%s","sdkVersion":"%s"}\n' "$direct" "$validate" "$copy_status" "$app_hash" "$(dotnet --version)" > "$cell/result.json"
}

gcc -O2 -fPIE -pie -Wl,--build-id=none -Wl,-z,max-page-size=4096 "$out/fixtures/probe.c" -o "$out/fixtures/glibc-4k"
gcc -O2 -fPIE -pie -Wl,--build-id=none -Wl,-z,max-page-size=16384 "$out/fixtures/probe.c" -o "$out/fixtures/glibc-16k-align"
for spec in 'glibc-4k 0x1000' 'glibc-16k-align 0x4000'; do
  read -r name alignment <<< "$spec"
  readelf -hW -lW -dW "$out/fixtures/$name" > "$out/fixtures/$name.readelf.txt"
  python3 "$root/scripts/check-runtime-fixture.py" "$out/fixtures/$name.readelf.txt" \
    "$alignment" /lib/ld-linux-aarch64.so.1 libc.so.6 \
    > "$out/fixtures/$name.fixture-identity.txt"
done
validate_and_run glibc.current.native-arm64 "$out/fixtures/glibc-4k" \
  0x1000 /lib/ld-linux-aarch64.so.1 libc.so.6
validate_and_run glibc.current.native-arm64-16k "$out/fixtures/glibc-16k-align" \
  0x4000 /lib/ld-linux-aarch64.so.1 libc.so.6
{
 echo "host_arch=$(uname -m)"; echo "host_kernel=$(uname -r)"; echo "host_page_size=$(getconf PAGESIZE)"
 echo "host_os_id=$host_os_id"; echo "host_os_version=$host_os_version"
 echo "glibc=$(getconf GNU_LIBC_VERSION 2>&1 || ldd --version | head -n1)"
 echo "loader=$(readlink -f /lib/ld-linux-aarch64.so.1 2>/dev/null || echo unavailable)"
 echo "compiler=$(gcc --version | head -n1)"; echo "cli_version=$(dotnet --version)"
 echo "environment=$(grep -E '^(NAME|VERSION_ID|VERSION_CODENAME)=' /etc/os-release | tr '\n' ';')"
 dpkg-query -W -f='${Package}=${Version}\n' gcc binutils libc6
} > "$out/cells/glibc.current.native-arm64/environment.txt"
sha256sum "$(command -v gcc)" "$(command -v ld)" "$(command -v readelf)" > "$out/cells/glibc.current.native-arm64/toolchain-lock.txt"
cp "$out/cells/glibc.current.native-arm64/environment.txt" "$out/cells/glibc.current.native-arm64-16k/environment.txt"
cp "$out/cells/glibc.current.native-arm64/toolchain-lock.txt" "$out/cells/glibc.current.native-arm64-16k/toolchain-lock.txt"

# One bounded command per loader invocation; all statuses and streams are kept.
run_image() {
 local id="$1" image="$2" digest="$3" expected="$4" fixture_list="$5"
 local cell="$out/cells/$id" ref="$image@$digest"; mkdir -p "$cell/container-results"
 chmod 0777 "$cell/container-results"
 local docker_server_platform
 docker_server_platform="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
 [[ "$docker_server_platform" == linux/arm64 ]] || {
   echo "runtime matrix requires a native linux/arm64 Docker server; got $docker_server_platform" >&2
   return 2
 }
 docker pull --platform linux/arm64 "$ref" > "$cell/pull.log" 2>&1
 docker image inspect "$ref" > "$cell/image.json"
python3 - "$cell/image.json" "$digest" "$cell/pull.log" <<'PY'
import json,sys,pathlib
x=json.load(open(sys.argv[1]))[0]
if (x.get('Os'),x.get('Architecture')) != ('linux','arm64'): raise SystemExit('OCI image is not linux/arm64')
pull=pathlib.Path(sys.argv[3]).read_text(errors='replace')
if f"Digest: {sys.argv[2]}" not in pull: raise SystemExit('docker pull did not resolve the exact requested OCI index digest')
PY
 printf 'image=%s\noci_digest=%s\ndocker_server_platform=%s\nexecution=native-arm64-no-emulation\n' \
   "$image" "$digest" "$docker_server_platform" > "$cell/image-identity.txt"
 # Networkless, read-only rootfs, bounded writable tmpfs/resources. Timeout wraps
 # each fixture invocation, and exact runtime identity is asserted in-container.
 local script='set -eu
if [ "$EXPECTED_RUNTIME" = "1.2.5" ]; then
 actual=$(ldd --version 2>&1 | grep -m1 "^Version ")
else
 actual=$(getconf GNU_LIBC_VERSION)
fi
echo "runtime_identity=$actual"
case "$actual" in *"$EXPECTED_RUNTIME"*) ;; *) echo unexpected-runtime-version >&2; exit 70;; esac
container_page=$(getconf PAGESIZE)
echo "container_page_size=$container_page"
test "$container_page" = "$HOST_PAGE_SIZE"
loader=$(readlink -f /lib/ld-linux-aarch64.so.1 2>/dev/null || readlink -f /lib/ld-musl-aarch64.so.1)
echo "loader=$loader"
test -n "$loader"
if [ "$EXPECTED_RUNTIME" = "1.2.5" ]; then
  set +e; timeout 10 "$loader" --help > /results/loader-identity.txt 2>&1; loader_status=$?; set -e
else
  set +e; timeout 10 "$loader" --version > /results/loader-identity.txt 2>&1; loader_status=$?; set -e
fi
echo "$loader_status" > /results/loader-identity.status
echo "direct_loader_status=$loader_status"
for f in $FIXTURES; do set +e; timeout 20 "/fixtures/$f" > "/results/$f.stdout" 2> "/results/$f.stderr"; status=$?; set -e; echo "$status" > "/results/$f.status"; echo "status_$f=$status"; test "$status" -eq 0; done
for f in $FIXTURES; do case "$f" in *.urp-copy) original=${f%.urp-copy}; cmp "/results/$original.stdout" "/results/$f.stdout"; cmp "/results/$original.stderr" "/results/$f.stderr";; esac; done'
 set +e
 timeout 180 docker run --rm --platform linux/arm64 --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --tmpfs /tmp:rw,noexec,nosuid,size=64m --memory 512m --pids-limit 64 -e "EXPECTED_RUNTIME=$expected" -e "HOST_PAGE_SIZE=$(getconf PAGESIZE)" -e "FIXTURES=$fixture_list" -v "$out/fixtures:/fixtures:ro" -v "$cell/container-results:/results:rw" "$ref" sh -ec "$script" > "$cell/oracle.log" 2> "$cell/stderr"
 local status=$?
 set -e
 printf '%s\n' "$status" > "$cell/exit-status.txt"
 [[ $status == 0 ]] || { echo "container cell $id failed status=$status" >&2; return 1; }
 cp "$cell/oracle.log" "$cell/stdout"
 printf 'execution=native AArch64 Docker; shared host kernel\ndocker_server_platform=%s\nhost_arch=%s\nhost_os_id=%s\nhost_os_version=%s\nhost_kernel=%s\nhost_page_size=%s\ncontainer_page_size=inherited host kernel, measured inside container\nisolation=network-none,read-only-rootfs,cap-drop-all,no-new-privileges,tmpfs-64MiB,memory-512MiB,pids-64,timeout-180s\n' \
   "$docker_server_platform" "$(uname -m)" "$host_os_id" "$host_os_version" "$(uname -r)" "$(getconf PAGESIZE)" > "$cell/environment.txt"
 # Container oracle version and successful bounded fixture statuses are required.
 grep -F "runtime_identity=" "$cell/oracle.log" >/dev/null
 grep -F 'status_' "$cell/oracle.log" >/dev/null
 python3 - "$cell" "$fixture_list" "$status" <<'PYRESULT'
import json,pathlib,sys
cell=pathlib.Path(sys.argv[1]); names=sys.argv[2].split(); exit_status=int(sys.argv[3]); runs=[]
for name in names:
 status=(cell/"container-results"/(name+".status")).read_text().strip()
 runs.append({"fixture":name,"status":int(status),"timeoutSeconds":20,"stdout":f"container-results/{name}.stdout","stderr":f"container-results/{name}.stderr"})
(cell/"result.json").write_text(json.dumps({"status":"validated","directStatus":0,"copyStatus":0,"streamsMatch":True,"containerExit":exit_status,"fixtureRuns":runs},indent=2)+"\n")
PYRESULT
 for f in $fixture_list; do sha256sum "$out/fixtures/$f"; done > "$cell/fixture-hashes.txt"
}

if [[ "$tier" != pr ]]; then
 command -v docker >/dev/null || { echo 'Docker required for extended runtime cells' >&2; exit 127; }
 : "${MUSL_TOOLCHAIN_ROOT:?pinned musl toolchain installer did not export MUSL_TOOLCHAIN_ROOT}"
 [[ -x "$MUSL_TOOLCHAIN_ROOT/bin/musl-gcc" && -s "$MUSL_TOOLCHAIN_ROOT/lib/libc.so" ]] || {
   echo "pinned musl toolchain is incomplete: $MUSL_TOOLCHAIN_ROOT" >&2
   exit 1
 }
 [[ "$(readlink -f /lib/ld-musl-aarch64.so.1)" == "$MUSL_TOOLCHAIN_ROOT/lib/libc.so" ]] || {
   echo 'native musl interpreter does not resolve to the pinned source build' >&2
   exit 1
 }
 rm -rf -- "$out/musl-1.2.4-smoke"
 MUSL_TOOLCHAIN_ROOT="$MUSL_TOOLCHAIN_ROOT" \
 MUSL_CONTAINER_ARTIFACT_ROOT="$out/musl-1.2.4-smoke" \
   "$root/scripts/run-musl-container-smoke.sh"
 run_image glibc.older.ubuntu-22.04-arm64 ubuntu:22.04 sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02 '2.35' 'glibc-4k glibc-4k.urp-copy glibc-16k-align glibc-16k-align.urp-copy'
 command -v musl-gcc >/dev/null || { echo 'pinned musl 1.2.4 compiler wrapper required' >&2; exit 127; }
 musl-gcc -O2 -fPIE -pie -Wl,--build-id=none -Wl,-z,max-page-size=4096 "$out/fixtures/probe.c" -o "$out/fixtures/musl-1.2.4-4k"
 musl-gcc -O2 -fPIE -pie -Wl,--build-id=none -Wl,-z,max-page-size=16384 "$out/fixtures/probe.c" -o "$out/fixtures/musl-1.2.4-16k-align"
 for spec in 'musl-1.2.4-4k 0x1000' 'musl-1.2.4-16k-align 0x4000'; do
   read -r name alignment <<< "$spec"
   readelf -hW -lW -dW "$out/fixtures/$name" > "$out/fixtures/$name.readelf.txt"
   python3 "$root/scripts/check-runtime-fixture.py" "$out/fixtures/$name.readelf.txt" \
     "$alignment" /lib/ld-musl-aarch64.so.1 libc.so \
     > "$out/fixtures/$name.fixture-identity.txt"
 done
 validate_and_run musl.1.2.4.ubuntu-native "$out/fixtures/musl-1.2.4-4k" \
   0x1000 /lib/ld-musl-aarch64.so.1 libc.so
 validate_and_run musl.1.2.4.ubuntu-native-16k "$out/fixtures/musl-1.2.4-16k-align" \
   0x4000 /lib/ld-musl-aarch64.so.1 libc.so
 { echo "host_arch=$(uname -m)"; echo "host_os_id=$host_os_id"; echo "host_os_version=$host_os_version"; echo "host_kernel=$(uname -r)"; echo "host_page_size=$(getconf PAGESIZE)"; "$MUSL_TOOLCHAIN_ROOT/lib/libc.so" --help > "$out/cells/musl.1.2.4.ubuntu-native/loader-version.txt" 2>&1 || true; echo "musl_version=$(grep -m1 '^Version ' "$out/cells/musl.1.2.4.ubuntu-native/loader-version.txt")"; echo "musl-gcc=$(musl-gcc --version | head -n1)"; echo "runtime_loader_path=/lib/ld-musl-aarch64.so.1"; echo "runtime_loader_resolved=$(readlink -f /lib/ld-musl-aarch64.so.1)"; grep -F 'Version 1.2.4' "$out/cells/musl.1.2.4.ubuntu-native/loader-version.txt"; sha256sum "$(command -v musl-gcc)" "$(command -v readelf)" "$MUSL_TOOLCHAIN_ROOT/lib/libc.so" > "$out/cells/musl.1.2.4.ubuntu-native/toolchain-lock.txt"; } > "$out/cells/musl.1.2.4.ubuntu-native/environment.txt"
cp "$out/cells/musl.1.2.4.ubuntu-native/environment.txt" "$out/cells/musl.1.2.4.ubuntu-native-16k/environment.txt"
cp "$out/cells/musl.1.2.4.ubuntu-native/toolchain-lock.txt" "$out/cells/musl.1.2.4.ubuntu-native-16k/toolchain-lock.txt"
cp "$out/cells/musl.1.2.4.ubuntu-native/loader-version.txt" "$out/cells/musl.1.2.4.ubuntu-native-16k/loader-version.txt"
 run_image musl.1.2.5.alpine-3.22.2 alpine:3.22.2 sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 '1.2.5' 'musl-1.2.4-4k musl-1.2.4-4k.urp-copy musl-1.2.4-16k-align musl-1.2.4-16k-align.urp-copy'
fi

page_size="$(getconf PAGESIZE)"
if [[ "$page_size" == 16384 ]]; then printf 'probe=completed\nstatus=validated\nobserved_page_size=16384\nclaim=validated\n' > "$out/cells/kernel-page.16k.native-aarch64.result.txt"
else printf 'probe=completed\nstatus=environment-unavailable\nobserved_page_size=%s\nrequired_page_size=16384\nclaim=unknown\nreason=native runner kernel is not 16KiB; ELF PT_LOAD alignment remains structural only\n' "$page_size" > "$out/cells/kernel-page.16k.native-aarch64.result.txt"; fi
cleanup_pinned_musl_loader
python3 - "$root/fixtures/runtime-matrix.json" "$tier" "$out/run-manifest.txt" <<'PY'
import json,sys,platform,subprocess,pathlib,os
m=json.load(open(sys.argv[1])); t=sys.argv[2]
page=int(subprocess.check_output(["getconf","PAGESIZE"],text=True).strip())
selected=m['tiers'][t]
claims=[cid for cid in selected if cid!="kernel-page.16k.native-aarch64" or page==16384]
os_release={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
 if '=' in line:
  key,value=line.split('=',1); os_release[key]=value.strip('"')
with open(sys.argv[3],'w') as f:
 f.write(f'tier={t}\nhost_arch={platform.machine()}\nhost_kernel={platform.release()}\nhost_page_size={page}\n')
 f.write(f"host_os_id={os_release.get('ID','')}\nhost_os_version={os_release.get('VERSION_ID','')}\n")
 f.write('selected_cells='+','.join(selected)+'\n')
 f.write('validated_claim_cells='+','.join(claims)+'\n')
 f.write('covering_rationale='+m['selection']+'\n')
 f.write('execution=native AArch64; emulation=false\n')
 f.write('runtime_registry_sha256='+__import__('hashlib').sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()+'\n')
PY
# Include every completed artifact, but exclude the checksum file itself.
bionic_root="${BIONIC_MATRIX_ARTIFACT_ROOT:-$root/.artifacts/bionic/c-termux-bionic-pie}"
find "$out" "$bionic_root" -type f ! -path "$out/SHA256SUMS" -print0 \
  | sort -z | xargs -0 sha256sum > "$out/SHA256SUMS"
python3 "$root/scripts/check-runtime-matrix-evidence.py" "$tier" "$out" "$bionic_root"
printf 'PASS runtime covering matrix tier=%s artifacts=%s\n' "$tier" "$out"
