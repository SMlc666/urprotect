#!/usr/bin/env bash
set -euo pipefail

launcher="${1:?launcher path is required}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
dotnet_command="${DOTNET:-dotnet}"

if ! command -v "${dotnet_command}" >/dev/null 2>&1; then
  echo "${dotnet_command} is required for native launcher integration tests" >&2
  exit 127
fi
for command_name in cmp file grep head mktemp python3 readelf timeout; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "${command_name} is required for native launcher integration tests" >&2
    exit 127
  fi
done

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "native launcher tests require an aarch64 host" >&2
  exit 2
fi

run_expected_failure() {
  local executable="$1"
  local expected_status="$2"
  local expected_code="$3"
  local label="$4"
  set +e
  timeout 10 "${executable}" >"${temporary_directory}/${label}.out" 2>"${temporary_directory}/${label}.err"
  local status=$?
  set -e
  if [[ "${status}" -ne "${expected_status}" ]]; then
    echo "${label} returned ${status}, expected ${expected_status}" >&2
    exit 1
  fi
  grep -q "${expected_code}" "${temporary_directory}/${label}.err"
}

mutate_wrapper() {
  local input="$1"
  local output="$2"
  local mutation="$3"
  python3 - "${input}" "${output}" "${mutation}" <<'PY'
import hashlib
import pathlib
import sys

input_path, output_path, mutation = sys.argv[1:]
data = bytearray(pathlib.Path(input_path).read_bytes())
if len(data) < 24:
    raise SystemExit("wrapper is too short")
frame_offset = int.from_bytes(data[-16:-8], "little")
if mutation == "version":
    data[frame_offset + 8:frame_offset + 10] = (2).to_bytes(2, "little")
elif mutation == "flags":
    data[frame_offset + 12:frame_offset + 16] = (2).to_bytes(4, "little")
elif mutation == "architecture":
    data[frame_offset + 16:frame_offset + 18] = (62).to_bytes(2, "little")
elif mutation == "basename":
    encoded_offset = int.from_bytes(data[frame_offset + 40:frame_offset + 48], "little")
    encoded_size = int.from_bytes(data[frame_offset + 32:frame_offset + 40], "little")
    encoded = bytes(data[encoded_offset:encoded_offset + encoded_size])
    header = bytearray(data[frame_offset:frame_offset + 112])
    name = b".."
    header[20:24] = len(name).to_bytes(4, "little")
    header[40:48] = (frame_offset + 112 + len(name)).to_bytes(8, "little")
    frame = bytes(header) + name + encoded
    trailer = bytearray(data[-24:])
    trailer[16:24] = len(frame).to_bytes(8, "little")
    data = data[:frame_offset] + frame + bytes(trailer)
elif mutation == "source-digest":
    data[frame_offset + 48] ^= 1
elif mutation == "invalid-deflate":
    encoded_offset = int.from_bytes(data[frame_offset + 40:frame_offset + 48], "little")
    encoded_size = int.from_bytes(data[frame_offset + 32:frame_offset + 40], "little")
    data[encoded_offset:encoded_offset + encoded_size] = b"\x00" * encoded_size
    digest = hashlib.sha256(data[encoded_offset:encoded_offset + encoded_size]).digest()
    data[frame_offset + 80:frame_offset + 112] = digest
elif mutation in ("invalid-interpreter", "missing-interpreter"):
    import zlib

    name_size = int.from_bytes(data[frame_offset + 20:frame_offset + 24], "little")
    encoded_offset = int.from_bytes(data[frame_offset + 40:frame_offset + 48], "little")
    encoded_size = int.from_bytes(data[frame_offset + 32:frame_offset + 40], "little")
    encoded = bytes(data[encoded_offset:encoded_offset + encoded_size])
    source = bytearray(zlib.decompress(encoded, wbits=-15))
    phoff = int.from_bytes(source[32:40], "little")
    phentsize = int.from_bytes(source[54:56], "little")
    phnum = int.from_bytes(source[56:58], "little")
    interpreter_offset = None
    interpreter_size = None
    for index in range(phnum):
        program = phoff + index * phentsize
        if int.from_bytes(source[program:program + 4], "little") == 3:
            interpreter_offset = int.from_bytes(source[program + 8:program + 16], "little")
            interpreter_size = int.from_bytes(source[program + 32:program + 40], "little")
            break
    if interpreter_offset is None or interpreter_size is None:
        raise SystemExit("source has no PT_INTERP")
    replacement = (b"/bad/ld-linux-aarch64.so.1\x00"
                   if mutation == "missing-interpreter" else b"/invalid\x00")
    if len(replacement) > interpreter_size:
        raise SystemExit("replacement interpreter is too long")
    source[interpreter_offset:interpreter_offset + interpreter_size] = (
        replacement + b"\x00" * (interpreter_size - len(replacement)))
    compressor = zlib.compressobj(level=9, wbits=-15)
    encoded = compressor.compress(bytes(source)) + compressor.flush()
    header = bytearray(data[frame_offset:frame_offset + 112])
    header[32:40] = len(encoded).to_bytes(8, "little")
    header[48:80] = hashlib.sha256(source).digest()
    header[80:112] = hashlib.sha256(encoded).digest()
    name = bytes(data[frame_offset + 112:frame_offset + 112 + name_size])
    frame = bytes(header) + name + encoded
    trailer = bytearray(data[-24:])
    trailer[16:24] = len(frame).to_bytes(8, "little")
    data = data[:frame_offset] + frame + bytes(trailer)
elif mutation == "frame-offset-overflow":
    data[-16:-8] = (2**64 - 1).to_bytes(8, "little")
elif mutation == "frame-length-overflow":
    data[-8:] = (2**64 - 1).to_bytes(8, "little")
elif mutation == "encoded-offset":
    data[frame_offset + 40:frame_offset + 48] = (0).to_bytes(8, "little")
elif mutation == "source-size":
    source_size = int.from_bytes(data[frame_offset + 24:frame_offset + 32], "little")
    data[frame_offset + 24:frame_offset + 32] = (source_size + 1).to_bytes(8, "little")
elif mutation == "source-name-size":
    data[frame_offset + 20:frame_offset + 24] = (4096).to_bytes(4, "little")
elif mutation == "trailing-deflate":
    trailer_offset = len(data) - 24
    encoded_offset = int.from_bytes(data[frame_offset + 40:frame_offset + 48], "little")
    encoded_size = int.from_bytes(data[frame_offset + 32:frame_offset + 40], "little")
    data[trailer_offset:trailer_offset] = b"\x00"
    encoded_size += 1
    data[frame_offset + 32:frame_offset + 40] = encoded_size.to_bytes(8, "little")
    data[frame_offset + 80:frame_offset + 112] = hashlib.sha256(
        data[encoded_offset:encoded_offset + encoded_size]).digest()
    data[-8:] = (int.from_bytes(data[-8:], "little") + 1).to_bytes(8, "little")
else:
    raise SystemExit(f"unknown mutation: {mutation}")
pathlib.Path(output_path).write_bytes(data)
PY
  chmod 0755 "${output}"
}

test_artifact_root="${NATIVE_LAUNCHER_TEST_ARTIFACT_ROOT:-}"
if [[ -n "${test_artifact_root}" ]]; then
  mkdir -p "${test_artifact_root}"
  temporary_directory="$(mktemp -d "${test_artifact_root}/run.XXXXXX")"
else
  temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/urprotect-launcher-test.XXXXXX")"
fi
cleanup() {
  local status=$?
  if [[ -z "${test_artifact_root}" || "${status}" -eq 0 ]]; then
    rm -rf -- "${temporary_directory}"
  else
    printf 'native launcher failure artifacts: %s\n' "${temporary_directory}" >&2
  fi
  return "${status}"
}
trap cleanup EXIT

pack() {
  local input="$1"
  local output="$2"
  "${dotnet_command}" run --project "${repo_root}/src/UrProtect.Cli" \
    --configuration Release --no-build --no-restore -- \
    pack "${input}" --output "${output}" --launcher "${launcher}" \
    --json "${output}.json" >/dev/null
}

true_wrapper="${temporary_directory}/true.wrapped"
pack /bin/true "${true_wrapper}"
file "${true_wrapper}" | grep -q 'ARM aarch64'
readelf -hW "${true_wrapper}" | grep -q 'Type:.*DYN'
timeout 10 "${true_wrapper}"

repeat_wrapper="${temporary_directory}/true-repeat.wrapped"
pack /bin/true "${repeat_wrapper}"
cmp -- "${true_wrapper}" "${repeat_wrapper}"

echo_wrapper="${temporary_directory}/echo.wrapped"
pack /bin/echo "${echo_wrapper}"
printf 'hello native launcher\n' > "${temporary_directory}/expected.txt"
timeout 10 "${echo_wrapper}" 'hello native launcher' > "${temporary_directory}/actual.txt"
cmp -- "${temporary_directory}/expected.txt" "${temporary_directory}/actual.txt"

shell_wrapper="${temporary_directory}/shell.wrapped"
pack /bin/sh "${shell_wrapper}"
execution_directory="${temporary_directory}/execution"
mkdir -p "${execution_directory}"
printf 'sh|launcher-environment|%s\n' "${execution_directory}" > "${temporary_directory}/shell-expected.txt"
(
  cd "${execution_directory}"
  URPROTECT_LAUNCHER_TEST=launcher-environment timeout 10 "${shell_wrapper}" \
    -c 'printf "%s|%s|%s\n" "$0" "$URPROTECT_LAUNCHER_TEST" "$PWD" > result.txt'
)
cmp -- "${temporary_directory}/shell-expected.txt" "${execution_directory}/result.txt"
printf 'native launcher stderr\n' > "${temporary_directory}/stderr-expected.txt"
timeout 10 "${shell_wrapper}" -c 'printf "native launcher stderr\n" >&2' \
  > /dev/null 2> "${temporary_directory}/stderr-actual.txt"
cmp -- "${temporary_directory}/stderr-expected.txt" "${temporary_directory}/stderr-actual.txt"

set +e
timeout 10 "${shell_wrapper}" -c 'exit 17'
shell_status=$?
set -e
if [[ "${shell_status}" -ne 17 ]]; then
  echo "non-zero payload returned ${shell_status}, expected 17" >&2
  exit 1
fi

set +e
(/bin/sh -c 'kill -TERM $$') 2>/dev/null
baseline_signal_status=$?
("${shell_wrapper}" -c 'kill -TERM $$') 2>/dev/null
signal_status=$?
set -e
if [[ "${signal_status}" -ne "${baseline_signal_status}" || "${signal_status}" -eq 0 ]]; then
  echo "signaled payload returned ${signal_status}, baseline returned ${baseline_signal_status}" >&2
  exit 1
fi

tampered="${temporary_directory}/tampered.wrapped"
cp -- "${true_wrapper}" "${tampered}"
python3 -c 'from pathlib import Path; p=Path(__import__("sys").argv[1]); b=bytearray(p.read_bytes()); b[-25] ^= 1; p.write_bytes(b)' "${tampered}"
set +e
timeout 10 "${tampered}" >"${temporary_directory}/tampered.out" 2>"${temporary_directory}/tampered.err"
tampered_status=$?
set -e
if [[ "${tampered_status}" -ne 5 ]]; then
  echo "tampered wrapper returned ${tampered_status}, expected 5" >&2
  exit 1
fi
grep -q 'PayloadIntegrityMismatch' "${temporary_directory}/tampered.err"

for mutation in version flags architecture basename; do
  malformed="${temporary_directory}/${mutation}.wrapped"
  mutate_wrapper "${true_wrapper}" "${malformed}" "${mutation}"
  run_expected_failure "${malformed}" 4 WrapperMalformed "${mutation}"
done

for mutation in frame-offset-overflow frame-length-overflow encoded-offset source-name-size source-size trailing-deflate; do
  malformed="${temporary_directory}/${mutation}.wrapped"
  mutate_wrapper "${true_wrapper}" "${malformed}" "${mutation}"
  expected_code=WrapperMalformed
  if [[ "${mutation}" == source-size || "${mutation}" == trailing-deflate ]]; then
    expected_code=PayloadMalformed
  fi
  run_expected_failure "${malformed}" 4 "${expected_code}" "${mutation}"
done

source_digest="${temporary_directory}/source-digest.wrapped"
mutate_wrapper "${true_wrapper}" "${source_digest}" source-digest
run_expected_failure "${source_digest}" 5 PayloadIntegrityMismatch source-digest

invalid_deflate="${temporary_directory}/invalid-deflate.wrapped"
mutate_wrapper "${true_wrapper}" "${invalid_deflate}" invalid-deflate
run_expected_failure "${invalid_deflate}" 4 PayloadMalformed invalid-deflate

invalid_interpreter="${temporary_directory}/invalid-interpreter.wrapped"
mutate_wrapper "${true_wrapper}" "${invalid_interpreter}" invalid-interpreter
run_expected_failure "${invalid_interpreter}" 4 UnsupportedPackInput invalid-interpreter

missing_interpreter="${temporary_directory}/missing-interpreter.wrapped"
mutate_wrapper "${true_wrapper}" "${missing_interpreter}" missing-interpreter
before_payload_dirs="${temporary_directory}/payload-dirs-before.txt"
after_payload_dirs="${temporary_directory}/payload-dirs-after.txt"
find /tmp -maxdepth 1 -type d -name 'urprotect-payload-*' -printf '%f\n' | sort > "${before_payload_dirs}"
run_expected_failure "${missing_interpreter}" 3 OutputIoFailure missing-interpreter
find /tmp -maxdepth 1 -type d -name 'urprotect-payload-*' -printf '%f\n' | sort > "${after_payload_dirs}"
cmp -- "${before_payload_dirs}" "${after_payload_dirs}"

truncated="${temporary_directory}/truncated.wrapped"
head -c -1 "${true_wrapper}" > "${truncated}"
chmod 0755 "${truncated}"
set +e
timeout 10 "${truncated}" >"${temporary_directory}/truncated.out" 2>"${temporary_directory}/truncated.err"
truncated_status=$?
set -e
if [[ "${truncated_status}" -ne 4 ]]; then
  echo "truncated wrapper returned ${truncated_status}, expected 4" >&2
  exit 1
fi
grep -q 'WrapperMalformed' "${temporary_directory}/truncated.err"

printf '%s\n' 'native launcher integration tests: PASS'
