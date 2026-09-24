#!/usr/bin/env bash
set -euo pipefail

launcher="${1:?launcher path is required}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
dotnet_command="${DOTNET:-dotnet}"

if ! command -v "${dotnet_command}" >/dev/null 2>&1; then
  echo "${dotnet_command} is required for managed handoff integration tests" >&2
  exit 127
fi
for command_name in cmp mktemp python3 timeout; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "${command_name} is required for managed handoff integration tests" >&2
    exit 127
  fi
done
if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "managed handoff tests require an aarch64 host" >&2
  exit 2
fi
if [[ ! -x "${launcher}" ]]; then
  echo "native launcher is unavailable: ${launcher}" >&2
  exit 1
fi

test_artifact_root="${MANAGED_HANDOFF_ARTIFACT_ROOT:-}"
if [[ -n "${test_artifact_root}" ]]; then
  mkdir -p "${test_artifact_root}"
  temporary_directory="$(mktemp -d "${test_artifact_root}/run.XXXXXX")"
else
  temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/urprotect-managed-handoff.XXXXXX")"
fi
cleanup() {
  local status=$?
  rm -rf -- "${temporary_directory}"
  return "${status}"
}
trap cleanup EXIT

publish_directory="${temporary_directory}/publish"
"${dotnet_command}" publish "${repo_root}/src/UrProtect.Cli/UrProtect.Cli.csproj" \
  --configuration Release \
  --runtime linux-arm64 \
  --self-contained true \
  --output "${publish_directory}" \
  --no-restore \
  --nologo \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:DebugType=None \
  -p:StripSymbols=true \
  > "${temporary_directory}/publish.log" 2>&1
managed_host="${publish_directory}/urprotect"
if [[ ! -x "${managed_host}" ]]; then
  echo "self-contained publish did not produce ${managed_host}" >&2
  cat "${temporary_directory}/publish.log" >&2
  exit 1
fi

wrapper="${temporary_directory}/shell.wrapped"
"${dotnet_command}" run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release --no-build --no-restore -- \
  pack /bin/sh --output "${wrapper}" --launcher "${launcher}" \
  --json "${wrapper}.json" > "${temporary_directory}/pack.log" 2>&1

managed_wrapper="${temporary_directory}/managed-shell"
python3 - "${managed_host}" "${wrapper}" "${managed_wrapper}" <<'PY'
import pathlib
import struct
import sys

host_path, wrapper_path, output_path = map(pathlib.Path, sys.argv[1:])
wrapper = wrapper_path.read_bytes()
frame_offset, frame_length = struct.unpack_from("<QQ", wrapper, len(wrapper) - 16)
frame = bytearray(wrapper[frame_offset:frame_offset + frame_length])
new_offset = host_path.stat().st_size
version = struct.unpack_from("<H", frame, 8)[0]
if version == 1:
    header_size = struct.unpack_from("<H", frame, 10)[0]
    name_size = struct.unpack_from("<I", frame, 20)[0]
    struct.pack_into("<Q", frame, 40, new_offset + header_size + name_size)
trailer = wrapper[-24:-16] + struct.pack("<QQ", new_offset, frame_length)
output_path.write_bytes(host_path.read_bytes() + frame + trailer)
output_path.chmod(0o755)
PY

execution_directory="${temporary_directory}/execution"
mkdir -p "${execution_directory}"
printf 'sh|%s\n' "${execution_directory}" > "${temporary_directory}/expected.txt"
(
  cd "${execution_directory}"
  timeout 15 "${managed_wrapper}" \
    -c 'printf "%s|%s\n" "$0" "$PWD"' > result.txt
)
cmp -- "${temporary_directory}/expected.txt" "${execution_directory}/result.txt"
echo "managed anonymous handoff integration tests: PASS"
