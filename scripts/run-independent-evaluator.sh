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
    seccomp_file="${TMPDIR:-/tmp}/urprotect-evaluator-seccomp-$$"
  python3 - "$seccomp_file" <<'PY'
import struct
import sys
path = sys.argv[1]
# Block network creation and connection syscalls while leaving filesystem and
# loader operations available.  The evaluator records the EPERM probe result.
AUDIT_ARCH_AARCH64 = 0xC00000B7
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000 | 1
SECCOMP_RET_ALLOW = 0x7FFF0000
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06
syscalls = (198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 243, 269)
program = [
    (BPF_LD_W_ABS, 0, 0, 4),
    (BPF_JMP_JEQ_K, 1, 0, AUDIT_ARCH_AARCH64),
    (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    (BPF_LD_W_ABS, 0, 0, 0),
]
for syscall in syscalls:
    program.extend(((BPF_JMP_JEQ_K, 0, 1, syscall), (BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO)))
program.append((BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
with open(path, "wb") as stream:
    for instruction in program:
        stream.write(struct.pack("<HBBI", *instruction))
PY
  set +e
  bwrap \
    --die-with-parent \
    --new-session \
    --unshare-user \
    --uid 0 \
    --gid 0 \
    --seccomp 3 \
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
        python3 "$repo_root/scripts/run-independent-evaluator.py" "$@" \
    3<"$seccomp_file"
  status=$?
  set -e
  rm -f -- "$seccomp_file"
  exit "$status"
fi

exec python3 "$repo_root/scripts/run-independent-evaluator.py" "$@"
