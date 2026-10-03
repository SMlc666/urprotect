#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/real_sample_worker_cleanup.sh
source "${repo_root}/scripts/real_sample_worker_cleanup.sh"

root="$(mktemp -d "${TMPDIR:-/tmp}/urprotect-worker-cleanup.XXXXXX")"
worker=""
pid_registry="${root}/worker.pids"
container_registry="${root}/worker.containers"
: > "${pid_registry}"
printf '{"name":"urp-test-bionic-container"}\n{"kind":"image","name":"urp-test-transient-image"}\n' > "${container_registry}"
fake_docker="${root}/fake-docker"
docker_state="${root}/container-state"
printf 'container:urp-test-bionic-container\nimage:urp-test-transient-image\n' > "${docker_state}"
cat > "${fake_docker}" <<'PY_DOCKER'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
state = Path(os.environ["URP_TEST_DOCKER_STATE"])
args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    kind, name = "image", args[-1]
elif args and args[0] == "inspect":
    kind, name = "container", args[-1]
else:
    kind = name = None
if kind is not None:
    rows = state.read_text(encoding="utf-8").splitlines() if state.is_file() else []
    if f"{kind}:{name}" in rows:
        print(json.dumps({"Status": "running"}))
        raise SystemExit(0)
    print(f"Error: No such {kind}: {name}", file=sys.stderr)
    raise SystemExit(1)
if args[:3] == ["image", "rm", "--force"] and len(args) == 4:
    kind, name = "image", args[3]
elif args[:2] == ["rm", "--force"] and len(args) == 3:
    kind, name = "container", args[2]
else:
    kind = name = None
if kind is not None:
    if kind == "image" and os.environ.get("URP_TEST_DOCKER_KEEP_IMAGE") == "1":
        print("simulated image removal failure", file=sys.stderr)
        raise SystemExit(1)
    rows = state.read_text(encoding="utf-8").splitlines() if state.is_file() else []
    remaining = [row for row in rows if row != f"{kind}:{name}"]
    if remaining:
        state.write_text("\n".join(remaining) + "\n", encoding="utf-8")
    else:
        state.unlink(missing_ok=True)
    raise SystemExit(0)
raise SystemExit(2)
PY_DOCKER
chmod 700 "${fake_docker}"
export BIONIC_CONTAINER_RUNTIME="${fake_docker}"
export URP_TEST_DOCKER_STATE="${docker_state}"
cleanup_ok=true
cleanup() {
  if [[ -n "${worker}" ]]; then
    worker_pgid="$(urp_worker_pgid "${worker}" || true)"
    if ! urp_stop_worker_group "${worker}" "${worker_pgid}" 8 "${pid_registry}" "${container_registry}"; then
      cleanup_ok=false
    fi
  fi
  if [[ "${cleanup_ok}" == true ]]; then
    rm -rf -- "${root}"
  else
    printf 'refusing to remove test worker root while cleanup is unproven: %s\n' "${root}" >&2
  fi
}
trap cleanup EXIT

child_pid_file="${root}/detached-child.pid"
ready_file="${root}/worker-ready"
child_code='import pathlib, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text(str(__import__("os").getpid())); time.sleep(30)'
worker_code='import pathlib, signal, subprocess, sys, time; child_code=sys.argv[3]; child_pid_file=sys.argv[1]; ready_file=sys.argv[2]; exec("def on_term(signum, frame):\n signal.signal(signal.SIGTERM, signal.SIG_IGN)\n child=subprocess.Popen([sys.executable, \"-c\", child_code, child_pid_file], start_new_session=True)\n pathlib.Path(child_pid_file).write_text(str(child.pid))\n"); signal.signal(signal.SIGTERM, on_term); pathlib.Path(ready_file).write_text("ready"); time.sleep(30)'
setsid --wait python3 "${repo_root}/scripts/real_sample_worker_supervisor.py" \
  --pid-registry "${pid_registry}" --container-registry "${container_registry}" -- \
  python3 -c "${worker_code}" "${child_pid_file}" "${ready_file}" "${child_code}" &
worker="$!"

for _ in $(seq 1 100); do
  [[ -s "${ready_file}" ]] && break
  sleep 0.05
done
[[ -s "${ready_file}" ]]
worker_pgid="$(urp_worker_pgid "${worker}" || true)"
[[ "${worker_pgid}" =~ ^[0-9]+$ ]]

# On SIGTERM, the worker starts a child in a new session and then stays alive.
# The subreaper must discover that child after its session differs, record its
# PID identity, terminate/reap it, and only then let cleanup authorize root removal.
if ! urp_stop_worker_group "${worker}" "${worker_pgid}" 8 "${pid_registry}" "${container_registry}"; then
  cleanup_ok=false
  echo 'worker cleanup failed to prove detached descendant reaping' >&2
  exit 1
fi
worker=""
[[ ! -e "${docker_state}" ]]
[[ -s "${child_pid_file}" ]]
detached_child="$(cat "${child_pid_file}")"
[[ "${detached_child}" =~ ^[0-9]+$ ]]
awk -F '\t' -v expected="${detached_child}" '$1 == expected { found = 1 } END { exit found ? 0 : 1 }' "${pid_registry}"
if urp_worker_process_alive "${detached_child}"; then
  cleanup_ok=false
  echo "detached descendant ${detached_child} remains alive after cleanup" >&2
  exit 1
fi

saved_fake_docker="${root}.fake-docker"
cp -- "${fake_docker}" "${saved_fake_docker}"
chmod 700 "${saved_fake_docker}"
cleanup
trap - EXIT
[[ ! -e "${root}" ]]
printf 'PASS detached-session worker descendants and transient image were registered, reaped, and removed before root cleanup\n'

# A forced worker loss between docker commit and the runner's finally block
# leaves the image registered.  If Docker cannot remove it, cleanup remains
# unproven and the owning temporary root must remain for inspection.
failure_root="$(mktemp -d "${TMPDIR:-/tmp}/urprotect-worker-image-failure.XXXXXX")"
failure_registry="${failure_root}/worker.resources"
printf '{"kind":"image","name":"urp-test-stuck-image"}\n' > "${failure_registry}"
printf 'image:urp-test-stuck-image\n' > "${failure_root}/container-state"
export URP_TEST_DOCKER_STATE="${failure_root}/container-state"
export BIONIC_CONTAINER_RUNTIME="${saved_fake_docker}"
export URP_TEST_DOCKER_KEEP_IMAGE=1
if urp_reap_worker_containers "${failure_registry}"; then
  echo 'expected transient image cleanup failure was reported as success' >&2
  exit 1
fi
[[ -e "${failure_root}" ]]
unset URP_TEST_DOCKER_KEEP_IMAGE
rm -rf -- "${failure_root}" "${saved_fake_docker}"
printf 'PASS unremovable registered transient image keeps cleanup unproven and root retained\n'
