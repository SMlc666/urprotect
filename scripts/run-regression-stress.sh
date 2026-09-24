#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tier="pr"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      tier="${2:?--tier requires pr or nightly}"
      shift 2
      ;;
    *)
      echo "usage: $0 [--tier pr|nightly]" >&2
      exit 2
      ;;
  esac
done

case "${tier}" in
  pr)
    workers="${URPROTECT_STRESS_WORKERS:-4}"
    iterations="${URPROTECT_STRESS_ITERATIONS:-8}"
    large_input_bytes="${URPROTECT_LARGE_INPUT_BYTES:-2097152}"
    timeout_seconds="${URPROTECT_STRESS_TIMEOUT_SECONDS:-90}"
    ;;
  nightly)
    workers="${URPROTECT_STRESS_WORKERS:-16}"
    iterations="${URPROTECT_STRESS_ITERATIONS:-64}"
    large_input_bytes="${URPROTECT_LARGE_INPUT_BYTES:-8388608}"
    timeout_seconds="${URPROTECT_STRESS_TIMEOUT_SECONDS:-300}"
    ;;
  *)
    echo "unsupported stress tier: ${tier}" >&2
    exit 2
    ;;
esac

command -v dotnet >/dev/null 2>&1 || { echo "dotnet is required" >&2; exit 127; }
artifact_root="${STRESS_RESULTS_DIRECTORY:-${repo_root}/.artifacts/stress}/${tier}"
mkdir -p "${artifact_root}"
cat > "${artifact_root}/run-manifest.txt" <<EOF
tier=${tier}
workers=${workers}
iterations=${iterations}
large_input_bytes=${large_input_bytes}
timeout_seconds=${timeout_seconds}
host_arch=$(uname -m)
host_kernel=$(uname -sr)
EOF

export URPROTECT_STRESS_WORKERS="${workers}"
export URPROTECT_STRESS_ITERATIONS="${iterations}"
export URPROTECT_LARGE_INPUT_BYTES="${large_input_bytes}"
run_command=(
  dotnet test "${repo_root}/tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj"
  --configuration Release --no-restore
  --filter 'Category=Concurrency|Category=LargeInput'
  --logger "trx;LogFileName=regression-stress.trx"
  --results-directory "${artifact_root}"
)
if command -v /usr/bin/time >/dev/null 2>&1; then
  timeout --signal=TERM --kill-after=10 "${timeout_seconds}" \
    /usr/bin/time -v "${run_command[@]}" \
    > "${artifact_root}/run.log" 2> "${artifact_root}/resource.log"
else
  timeout --signal=TERM --kill-after=10 "${timeout_seconds}" \
    "${run_command[@]}" > "${artifact_root}/run.log" 2>&1
fi
cat "${artifact_root}/run.log"
printf 'regression stress: PASS\n'
