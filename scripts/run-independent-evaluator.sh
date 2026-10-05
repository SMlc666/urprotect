#!/usr/bin/env bash
set -euo pipefail

# The evaluator is intentionally separate from product build/materialization. It
# receives the checkout and writes only .artifacts/evaluator/<tier>.  The
# optional --baseline-reference PATH selects an immutable content-addressed
# denominator; omission retains the historical baseline-reference.json.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1

# Capture the checkout identity before entering the read-only staged fallback.
# The staged tree is intentionally allowed to omit .git, so the evaluator must
# receive an exact commit handoff rather than falling back to "unknown".
checkout_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)"
if [[ ! "$checkout_commit" =~ ^[0-9a-fA-F]{40}$ ]]; then
  checkout_commit="${GITHUB_SHA:-}"
fi
if [[ ! "$checkout_commit" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "FAIL evaluator: checkout commit is unavailable" >&2
  exit 2
fi
export EVALUATOR_CHECKOUT_COMMIT="${checkout_commit,,}"

# Capture host tool identity before seccomp is installed. Some hosted AArch64
# kernels reject a child tool's harmless --version probes even though the tool
# itself is available; the staged evaluator must verify, not guess, these facts.
capture_tool_identity() {
  local command_name="$1"
  local token="${command_name^^}"
  token="${token//[^A-Z0-9]/_}"
  local executable
  executable="$(command -v "$command_name" 2>/dev/null || true)"
  if [[ ! "$executable" =~ ^/ ]] || [[ ! -x "$executable" ]]; then
    return 0
  fi
  local version
  version="$(LC_ALL=C "$executable" --version 2>&1 | head -n 1 || true)"
  if [[ -z "$version" ]]; then
    return 0
  fi
  export "EVALUATOR_TOOL_${token}_PATH=$executable"
  export "EVALUATOR_TOOL_${token}_VERSION=$version"
}

for evaluator_tool in python3 dotnet readelf bwrap ldd; do
  capture_tool_identity "$evaluator_tool"
done

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
  set +e
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
    --setenv EVALUATOR_CHECKOUT_COMMIT "$EVALUATOR_CHECKOUT_COMMIT" \
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
        -- \
        python3 "$repo_root/scripts/evaluator-seccomp-exec.py" \
          python3 "$repo_root/scripts/run-independent-evaluator.py" "$@"
  status=$?
  set -e
  if (( status == 0 )) || [[ -f "$output_root/environment.json" ]]; then
    exit "$status"
  fi

  # Some hosted ARM images disable user namespaces even when bubblewrap is
  # installed.  Preserve the same effective isolation with a read-only staged
  # checkout, dropped capabilities, bounded limits, and the seccomp wrapper.
  if [[ "$output_root" != "$repo_root/.artifacts/evaluator/$tier" ]]; then
    echo "FAIL evaluator isolation: sandbox unavailable for a non-default output root" >&2
    exit "$status"
  fi
  staged_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/urprotect-evaluator-stage-$$"
  rm -rf -- "$staged_root"
  mkdir -p "$staged_root"
  cp -a --reflink=auto "$repo_root"/. "$staged_root"/
  find "$staged_root" -exec chmod a-w {} +
  find "$staged_root" -type d -exec chmod u+rwx,go+rx {} +
  find "$staged_root" -type f -exec chmod a+r {} +
  mkdir -p "$staged_root/.artifacts/evaluator/$tier"
  chmod u+rwx "$staged_root/.artifacts/evaluator"
  chmod -R u+rwX,go+rX "$staged_root/.artifacts/evaluator/$tier"
  set +e
  (
    cd "$staged_root" && \
    EVALUATOR_ISOLATION_ACTIVE=1 \
    EVALUATOR_STAGED_READONLY=1 \
    EVALUATOR_CHECKOUT_COMMIT="$EVALUATOR_CHECKOUT_COMMIT" \
    prlimit --cpu=45 --as=1073741824 --nproc=32 --fsize=268435456 -- \
      setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all -- \
      python3 "$staged_root/scripts/evaluator-seccomp-exec.py" \
        python3 "$staged_root/scripts/run-independent-evaluator.py" "$@"
  )
  status=$?
  set -e
  rm -rf -- "$output_root"
  mkdir -p "$output_root"
  if [[ -d "$staged_root/.artifacts/evaluator/$tier" ]]; then
    cp -a "$staged_root/.artifacts/evaluator/$tier/." "$output_root/"
  fi
  rm -rf -- "$staged_root"
  exit "$status"
fi

exec python3 "$repo_root/scripts/run-independent-evaluator.py" "$@"
