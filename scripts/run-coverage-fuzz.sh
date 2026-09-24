#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tier="pr"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      tier="${2:?--tier requires pr, nightly, or release}"
      shift 2
      ;;
    *)
      echo "usage: $0 [--tier pr|nightly|release]" >&2
      exit 2
      ;;
  esac
done
case "${tier}" in
  pr)
    runs="${URPROTECT_COVERAGE_FUZZ_RUNS:-1000}"
    max_total_time="${URPROTECT_COVERAGE_FUZZ_MAX_TOTAL_TIME:-0}"
    wall_timeout_seconds="${URPROTECT_COVERAGE_FUZZ_WALL_TIMEOUT_SECONDS:-60}"
    seed="${URPROTECT_COVERAGE_FUZZ_SEED:-20260924}"
    ;;
  nightly)
    runs="${URPROTECT_COVERAGE_FUZZ_RUNS:-0}"
    max_total_time="${URPROTECT_COVERAGE_FUZZ_MAX_TOTAL_TIME:-120}"
    wall_timeout_seconds="${URPROTECT_COVERAGE_FUZZ_WALL_TIMEOUT_SECONDS:-180}"
    seed="${URPROTECT_COVERAGE_FUZZ_SEED:-20260924}"
    ;;
  release)
    runs="${URPROTECT_COVERAGE_FUZZ_RUNS:-0}"
    max_total_time="${URPROTECT_COVERAGE_FUZZ_MAX_TOTAL_TIME:-60}"
    wall_timeout_seconds="${URPROTECT_COVERAGE_FUZZ_WALL_TIMEOUT_SECONDS:-120}"
    seed="${URPROTECT_COVERAGE_FUZZ_SEED:-20260924}"
    ;;
  *)
    echo "unsupported fuzz tier: ${tier}" >&2
    exit 2
    ;;
esac

for command_name in curl dotnet clang++ sha256sum timeout python3; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "${command_name} is required for coverage-guided fuzzing" >&2
    exit 127
  fi
done
export DOTNET_ROOT="${DOTNET_ROOT:-$(dirname "$(readlink -f "$(command -v dotnet)")")}"
export PATH="${DOTNET_ROOT}:${PATH}"

if [[ "$(uname -m)" != "aarch64" && "${URPROTECT_FUZZ_ALLOW_NON_ARM64:-}" != "1" ]]; then
  echo "coverage-guided fuzzing requires the native AArch64 runner; set URPROTECT_FUZZ_ALLOW_NON_ARM64=1 only for local tool validation" >&2
  exit 2
fi

artifact_root="${FUZZ_RESULTS_DIRECTORY:-${repo_root}/.artifacts/fuzz}/${tier}"
publish_directory="${artifact_root}/target"
generated_corpus="${artifact_root}/corpus"
crash_directory="${artifact_root}/crashes"
dependency_directory="${artifact_root}/dependencies"
mkdir -p "${publish_directory}" "${generated_corpus}/elf" \
  "${generated_corpus}/payload-frame" "${crash_directory}" "${dependency_directory}"
rm -rf "${publish_directory}"
mkdir -p "${publish_directory}"

runtime="${URPROTECT_FUZZ_RUNTIME:-linux-arm64}"
max_len="${URPROTECT_COVERAGE_FUZZ_MAX_LEN:-1048576}"
timeout_seconds="${URPROTECT_COVERAGE_FUZZ_TIMEOUT_SECONDS:-10}"
rss_limit_mb="${URPROTECT_COVERAGE_FUZZ_RSS_LIMIT_MB:-1024}"
bridge_revision="v2025.05.02.0904"
bridge_url="https://raw.githubusercontent.com/Metalnem/libfuzzer-dotnet/${bridge_revision}/libfuzzer-dotnet.cc"
bridge_sha256="90f019e2e9ad3a0b93c7ecc2c5afb2fbfc8b5aab6aac51c7e0d349ec79354f36"
bridge_source="${dependency_directory}/libfuzzer-dotnet.cc"
bridge_patched_source="${dependency_directory}/libfuzzer-dotnet-urprotect.cc"
bridge_binary="${dependency_directory}/libfuzzer-dotnet"

cat > "${artifact_root}/run-manifest.txt" <<EOF
engine=SharpFuzz 2.3.0 + libFuzzer bridge ${bridge_revision}
tier=${tier}
runtime=${runtime}
seed=${seed}
runs=${runs}
max_total_time=${max_total_time}
wall_timeout_seconds=${wall_timeout_seconds}
max_len=${max_len}
timeout_seconds=${timeout_seconds}
rss_limit_mb=${rss_limit_mb}
artifact_root=${artifact_root}
bridge_url=${bridge_url}
bridge_sha256=${bridge_sha256}
host_arch=$(uname -m)
host_kernel=$(uname -sr)
EOF

if [[ ! -f "${bridge_source}" ]]; then
  curl --fail --location --silent --show-error "${bridge_url}" --output "${bridge_source}"
fi
if [[ "$(sha256sum "${bridge_source}" | awk '{print $1}')" != "${bridge_sha256}" ]]; then
  echo "libFuzzer bridge source hash mismatch" >&2
  exit 1
fi
python3 "${repo_root}/scripts/prepare-libfuzzer-dotnet.py" \
  "${bridge_source}" "${bridge_patched_source}"
if [[ ! -x "${bridge_binary}" ]]; then
  clang++ -O2 -std=c++17 -fsanitize=fuzzer "${bridge_patched_source}" -o "${bridge_binary}"
fi

tool_directory="${dependency_directory}/sharpfuzz-tool"
if [[ ! -x "${tool_directory}/sharpfuzz" ]]; then
  dotnet tool install --tool-path "${tool_directory}" SharpFuzz.CommandLine \
    --version 2.3.0 --no-cache --ignore-failed-sources
fi

dotnet restore "${repo_root}/tests/UrProtect.Fuzz/UrProtect.Fuzz.csproj" --locked-mode
dotnet publish "${repo_root}/tests/UrProtect.Fuzz/UrProtect.Fuzz.csproj" \
  --configuration Release --runtime "${runtime}" --self-contained true \
  --output "${publish_directory}" --no-restore --nologo \
  -p:PublishSingleFile=false -p:DebugType=None -p:StripSymbols=true \
  > "${artifact_root}/publish.log" 2>&1

target="${publish_directory}/UrProtect.Fuzz"
core_assembly="${publish_directory}/UrProtect.Core.dll"
if [[ ! -x "${target}" || ! -f "${core_assembly}" ]]; then
  echo "fuzz publish did not produce the target and project assembly" >&2
  exit 1
fi
"${target}" --emit-seed "${generated_corpus}/elf/minimal-pie.elf"
"${target}" --emit-frame-seed "${generated_corpus}/payload-frame/valid-frame.bin"
python3 - "${repo_root}/tests/FuzzCorpus/payload-frame/invalid/truncated-frame.txt" \
  "${generated_corpus}/payload-frame/truncated-frame.bin" <<'PY'
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
destination.write_bytes(bytes.fromhex("".join(source.read_text().split())))
PY

"${tool_directory}/sharpfuzz" "${core_assembly}" \
  > "${artifact_root}/instrumentation.log" 2>&1

run_target() {
  local mode="$1"
  local corpus_directory="${generated_corpus}/${mode}"
  local log_file="${artifact_root}/${mode}.log"
  local -a flags=(
    "-max_len=${max_len}"
    "-rss_limit_mb=${rss_limit_mb}"
    "-timeout=${timeout_seconds}"
    "-seed=${seed}"
    "-artifact_prefix=${crash_directory}/${mode}-"
    "-print_final_stats=1"
  )
  if [[ "${runs}" != "0" ]]; then
    flags+=("-runs=${runs}")
  else
    flags+=("-max_total_time=${max_total_time}")
  fi
  printf 'target=%s\nmode=%s\ncorpus=%s\nflags=%q\n' \
    "${target}" "${mode}" "${corpus_directory}" "${flags[*]}" >> "${artifact_root}/run-manifest.txt"
  set +e
  timeout --signal=TERM --kill-after=5 "${wall_timeout_seconds}" \
    "${bridge_binary}" "${flags[@]}" \
    "--target_path=${target}" "--target_arg=${mode}" "${corpus_directory}" \
    > "${log_file}" 2>&1
  local status=$?
  set -e
  if [[ "${status}" -ne 0 ]]; then
    echo "coverage-guided fuzz target ${mode} failed with status ${status}" >&2
    return "${status}"
  fi
}

run_target elf
run_target payload-frame
printf 'coverage-guided fuzz: PASS\n'
