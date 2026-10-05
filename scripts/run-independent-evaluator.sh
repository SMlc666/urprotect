#!/usr/bin/env bash
set -euo pipefail

# The evaluator is intentionally separate from product build/materialization. It
# receives the checkout and writes only .artifacts/evaluator/<tier>.  The
# optional --baseline-reference PATH selects an immutable content-addressed
# denominator; omission retains the historical baseline-reference.json.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1

# CI invokes the control plane in a real read-only-input, networkless sandbox.
# Local runs deliberately stay unsandboxed and are recorded as
# environment-unavailable unless an equivalent runner proves every capability.
if [[ "${EVALUATOR_CI_ISOLATION:-0}" == "1" && "${EVALUATOR_ISOLATION_ACTIVE:-0}" != "1" ]]; then
  tier=pr
  output_root="${repo_root}/.artifacts/evaluator/${tier}"
  args=("$@")
  for ((index = 0; index < ${#args[@]}; index++)); do
    case "${args[index]}" in
      --tier)
        if (( index + 1 < ${#args[@]} )); then tier="${args[index + 1]}"; fi
        ;;
      --output-root)
        if (( index + 1 < ${#args[@]} )); then output_root="${args[index + 1]}"; fi
        ;;
    esac
  done
  if [[ "$output_root" != /* ]]; then output_root="${repo_root}/${output_root}"; fi
  case "$output_root" in
    "${repo_root}/.artifacts/evaluator/"*) ;;
    *) echo "FAIL evaluator isolation: output must remain under .artifacts/evaluator" >&2; exit 2 ;;
  esac
  mkdir -p "$output_root"
  bwrap \
    --die-with-parent \
    --new-session \
    --unshare-user-try \
    --ro-bind "$repo_root" "$repo_root" \
    --bind "$output_root" "$output_root" \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --chdir "$repo_root" \
    --setenv EVALUATOR_ISOLATION_ACTIVE 1 \
    -- \
    prlimit \
      --cpu=45 \
      --as=1073741824 \
      --nproc=32 \
      --fsize=268435456 \
      -- \
      setpriv \
        --no-new-privs \
        --inh-caps=-all \
        --ambient-caps=-all \
        --bounding-set=-all \
        -- \
        python3 "$repo_root/scripts/evaluator-seccomp-exec.py" \
          python3 "$repo_root/scripts/run-independent-evaluator.py" "$@"
fi

exec python3 "$repo_root/scripts/run-independent-evaluator.py" "$@"
