#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --input NODE --artifact-root DIR --image IMAGE --version VERSION --sha256 SHA256 --archive-sha256 SHA256 --launcher LAUNCHER" >&2
}

input=''
artifact_root=''
image=''
version=''
sha256=''
archive_sha256=''
launcher=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) input="$2"; shift 2 ;;
    --artifact-root) artifact_root="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --sha256) sha256="$2"; shift 2 ;;
    --archive-sha256) archive_sha256="$2"; shift 2 ;;
    --launcher) launcher="$2"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
if [[ -z "$input" || -z "$artifact_root" || -z "$image" || -z "$version" || -z "$sha256" || -z "$archive_sha256" || -z "$launcher" ]]; then
  usage
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$artifact_root"
chmod a+rwx "$artifact_root"
mkdir -p "$artifact_root/node-apt-archives"
chmod a+rwx "$artifact_root/node-apt-archives"
cleanup_raw_inputs() {
  rm -rf -- "$artifact_root/node" "$artifact_root/node-wrapper" "$artifact_root/node-apt-archives"
}
trap cleanup_raw_inputs EXIT
for command in docker dotnet readelf sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required for bionic Node.js evidence" >&2; exit 127; }
done
[[ "$(uname -m)" == aarch64 ]] || { echo 'bionic Node.js witness requires native AArch64' >&2; exit 2; }
[[ "$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" == linux/arm64 ]] || {
  echo 'bionic Node.js witness requires a native Linux/arm64 Docker engine' >&2
  exit 2
}
[[ -f "$input" ]] || { echo "missing Node.js input: $input" >&2; exit 1; }
[[ "$(sha256sum "$input" | awk '{print $1}')" == "$sha256" ]] || {
  echo 'Node.js input hash does not match the locked real-sample manifest' >&2
  exit 1
}

input_dir="$(cd "$(dirname "$input")" && pwd)"
input_name="$(basename "$input")"
container_args=(
  run --rm --platform linux/arm64 --user 1000:1000
  --mount "type=bind,src=${input_dir},dst=/input,readonly"
  --mount "type=bind,src=${artifact_root},dst=/artifacts"
  --env PREFIX=/data/data/com.termux/files/usr
  "$image"
  /data/data/com.termux/files/usr/bin/sh
)

run_shell() { docker "${container_args[@]}" -c "$1"; }
run_shell 'set -eu; test -x /system/bin/linker64; test "$(uname -m)" = aarch64'
run_shell "set -eu
  export PATH=\"\${PREFIX}/bin:\${PATH}\"
  apt-get update > /artifacts/node-apt-update.log 2>&1
  apt-get -o Dir::Cache::archives=/artifacts/node-apt-archives --download-only install -y nodejs=${version} > /artifacts/node-apt-download.log 2>&1
  apt-get -o Dir::Cache::archives=/artifacts/node-apt-archives --no-download install -y nodejs=${version} > /artifacts/node-apt-install.log 2>&1
  cp /input/${input_name} /artifacts/node
  chmod 0755 /artifacts/node
  /artifacts/node --version > /artifacts/node-baseline.stdout 2> /artifacts/node-baseline.stderr
  printf '0\\n' > /artifacts/node-baseline.status"

host_wrapper="${artifact_root}/node-wrapper"
dotnet run --project "$repo_root/src/UrProtect.Cli" --configuration Release --no-restore -- \
  pack "$input" --output "$host_wrapper" --launcher "$launcher" --profile outer-execveat \
  --path-preserving \
  --json "${artifact_root}/node-pack.json" > "${artifact_root}/node-pack.stdout" \
  2> "${artifact_root}/node-pack.stderr"
readelf -hW -lW "$host_wrapper" > "${artifact_root}/node-wrapper-readelf.txt"
run_shell '/artifacts/node-wrapper --version > /artifacts/node-outer.stdout 2> /artifacts/node-outer.stderr; printf "%s\n" "$?" > /artifacts/node-outer.status'

cmp -- "$artifact_root/node-baseline.stdout" "$artifact_root/node-outer.stdout"
cmp -- "$artifact_root/node-baseline.stderr" "$artifact_root/node-outer.stderr"
[[ "$(cat "$artifact_root/node-outer.status")" == 0 ]]
sha256sum "$input" "$host_wrapper" > "$artifact_root/node-hashes.txt"
rm -f -- "$artifact_root/node" "$host_wrapper"
rm -rf -- "$artifact_root/node-apt-archives"
printf 'runtime=bionic\nloader=/system/bin/linker64\nstatus=accepted-and-runs\nsourceArchiveSha256=%s\nartifactSha256=%s\n' \
  "$archive_sha256" "$sha256" > "$artifact_root/node-result.txt"
