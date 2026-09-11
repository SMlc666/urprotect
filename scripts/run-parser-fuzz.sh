#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
results_directory="${FUZZ_RESULTS_DIRECTORY:-${repo_root}/.artifacts/fuzz}"
random_iterations="${URPROTECT_FUZZ_RANDOM_ITERATIONS:-4096}"
mutation_iterations="${URPROTECT_FUZZ_MUTATION_ITERATIONS:-2048}"
timeout_seconds="${URPROTECT_FUZZ_TIMEOUT_SECONDS:-120}"

mkdir -p "${results_directory}"
if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet is required to run the parser fuzz target" >&2
  exit 127
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is required to bound the parser fuzz target" >&2
  exit 127
fi

export URPROTECT_FUZZ_RANDOM_ITERATIONS="${random_iterations}"
export URPROTECT_FUZZ_MUTATION_ITERATIONS="${mutation_iterations}"

timeout "${timeout_seconds}" dotnet test \
  "${repo_root}/tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj" \
  --configuration Release \
  --no-build \
  --no-restore \
  --filter Category=Fuzz \
  --logger "trx;LogFileName=parser-fuzz.trx" \
  --results-directory "${results_directory}"
