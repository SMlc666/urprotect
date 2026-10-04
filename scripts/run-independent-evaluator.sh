#!/usr/bin/env bash
set -euo pipefail

# The evaluator is intentionally separate from product build/materialization. It
# receives the checkout and writes only .artifacts/evaluator/<tier>.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$repo_root/scripts/run-independent-evaluator.py" "$@"
