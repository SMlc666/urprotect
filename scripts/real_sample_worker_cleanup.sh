#!/usr/bin/env bash
# Bounded cleanup for real-sample worker trees.
#
# Process groups are only a first signal-delivery mechanism: a descendant can
# call setsid(). Each worker therefore runs under real_sample_worker_supervisor.py,
# which is a Linux child subreaper and maintains PID/start-time and named-container
# registries. Cleanup repeatedly scans the live tree plus those registries, and
# the caller may remove temp_root only after this function proves both empty.

URP_WORKER_SUPERVISOR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/real_sample_worker_supervisor.py"

urp_worker_pgid() {
  local pid="$1"
  ps -o pgid= -p "${pid}" 2>/dev/null | awk 'NR == 1 { print $1; exit }'
}

urp_worker_descendants() {
  local root_pid="$1"
  ps -eo pid=,ppid= 2>/dev/null | awk -v root="${root_pid}" '
    {
      parent[$1] = $2
    }
    END {
      descendant[root] = 1
      changed = 1
      while (changed) {
        changed = 0
        for (pid in parent) {
          if ((parent[pid] in descendant) && !(pid in descendant)) {
            descendant[pid] = 1
            changed = 1
          }
        }
      }
      for (pid in descendant) {
        if (pid != root) print pid
      }
    }
  ' | sort -n
}

urp_worker_process_alive() {
  local pid="$1"
  kill -0 "${pid}" 2>/dev/null || return 1
  local state
  state="$(ps -o stat= -p "${pid}" 2>/dev/null | awk 'NR == 1 { print $1; exit }')"
  [[ -n "${state}" && "${state}" != Z* ]]
}

urp_worker_identity_alive() {
  local pid="$1"
  local expected_start="$2"
  [[ "${pid}" =~ ^[0-9]+$ && "${expected_start}" =~ ^[0-9]+$ ]] || return 1
  local stat rest
  [[ -r "/proc/${pid}/stat" ]] || return 1
  stat="$(cat "/proc/${pid}/stat" 2>/dev/null)" || return 1
  rest="${stat##*) }"
  local -a fields=()
  read -r -a fields <<< "${rest}"
  [[ "${#fields[@]}" -ge 20 && "${fields[0]}" != Z && "${fields[19]}" == "${expected_start}" ]]
}

urp_worker_registry_alive() {
  local pid_registry="${1:-}"
  [[ -n "${pid_registry}" && -f "${pid_registry}" && ! -L "${pid_registry}" ]] || return 1
  local pid start_time
  while IFS=$'\t' read -r pid start_time; do
    if urp_worker_identity_alive "${pid}" "${start_time}"; then
      return 0
    fi
  done < "${pid_registry}"
  return 1
}

urp_worker_group_alive() {
  local pgid="$1"
  [[ "${pgid}" =~ ^[0-9]+$ ]] || return 1
  ps -eo pid=,pgid=,stat= 2>/dev/null | awk -v group="${pgid}" '
    $2 == group && $3 !~ /^Z/ { found = 1 }
    END { exit found ? 0 : 1 }
  '
}

urp_worker_signal_descendants() {
  local root_pid="$1"
  local signal_name="$2"
  local pid_registry="${3:-}"
  local -A seen=()
  local pid start_time
  local descendants=()

  if urp_worker_process_alive "${root_pid}"; then
    mapfile -t descendants < <(urp_worker_descendants "${root_pid}")
    for pid in "${descendants[@]}"; do
      [[ "${pid}" =~ ^[0-9]+$ ]] || continue
      seen["${pid}"]=1
      kill "-${signal_name}" "${pid}" 2>/dev/null || true
    done
  fi

  if [[ -n "${pid_registry}" && -f "${pid_registry}" && ! -L "${pid_registry}" ]]; then
    while IFS=$'\t' read -r pid start_time; do
      [[ "${pid}" =~ ^[0-9]+$ ]] || continue
      [[ -z "${seen[${pid}]+present}" ]] || continue
      if urp_worker_identity_alive "${pid}" "${start_time}"; then
        kill "-${signal_name}" "${pid}" 2>/dev/null || true
      fi
    done < "${pid_registry}"
  fi
}

urp_worker_descendants_alive() {
  local root_pid="$1"
  local pid_registry="${2:-}"
  local pid
  local descendants=()
  if urp_worker_process_alive "${root_pid}"; then
    mapfile -t descendants < <(urp_worker_descendants "${root_pid}")
    for pid in "${descendants[@]}"; do
      if urp_worker_process_alive "${pid}"; then
        return 0
      fi
    done
  fi
  urp_worker_registry_alive "${pid_registry}"
}

urp_reap_worker_containers() {
  local container_registry="${1:-}"
  [[ -n "${container_registry}" && -f "${container_registry}" ]] || return 0
  [[ ! -L "${container_registry}" ]] || return 1
  python3 "${URP_WORKER_SUPERVISOR_SCRIPT}" --reap-containers "${container_registry}"
}

urp_stop_worker_group() {
  local worker_pid="$1"
  local worker_pgid="${2:-}"
  local grace_seconds="${3:-10}"
  local pid_registry="${4:-}"
  local container_registry="${5:-}"
  local self_pgid

  [[ "${worker_pid}" =~ ^[0-9]+$ ]] || return 1
  [[ "${grace_seconds}" =~ ^[0-9]+$ ]] || return 1
  if [[ -n "${pid_registry}" && ( ! -f "${pid_registry}" || -L "${pid_registry}" ) ]]; then
    printf 'worker PID registry is missing or unsafe: %s\n' "${pid_registry}" >&2
    return 1
  fi
  if [[ -n "${container_registry}" && ( ! -f "${container_registry}" || -L "${container_registry}" ) ]]; then
    printf 'worker container registry is missing or unsafe: %s\n' "${container_registry}" >&2
    return 1
  fi
  if [[ ! "${worker_pgid}" =~ ^[0-9]+$ ]]; then
    worker_pgid="$(urp_worker_pgid "${worker_pid}" || true)"
  fi
  self_pgid="$(urp_worker_pgid "$$" || true)"

  if [[ "${worker_pgid}" =~ ^[0-9]+$ && "${worker_pgid}" != "${self_pgid}" ]]; then
    kill -TERM -- "-${worker_pgid}" 2>/dev/null || true
  else
    kill -TERM "${worker_pid}" 2>/dev/null || true
  fi
  urp_worker_signal_descendants "${worker_pid}" TERM "${pid_registry}"

  local deadline=$((SECONDS + grace_seconds))
  while (( SECONDS < deadline )); do
    # Rescan every iteration. The supervisor adopts orphaned setsid() children,
    # while the durable registry retains identities that outlive their parent.
    urp_worker_signal_descendants "${worker_pid}" TERM "${pid_registry}"
    local alive=false
    urp_worker_process_alive "${worker_pid}" && alive=true
    if [[ "${worker_pgid}" =~ ^[0-9]+$ && "${worker_pgid}" != "${self_pgid}" ]] && urp_worker_group_alive "${worker_pgid}"; then
      alive=true
    fi
    if urp_worker_descendants_alive "${worker_pid}" "${pid_registry}"; then
      alive=true
    fi
    [[ "${alive}" == true ]] || break
    sleep 0.1
  done

  urp_worker_signal_descendants "${worker_pid}" KILL "${pid_registry}"
  if [[ "${worker_pgid}" =~ ^[0-9]+$ && "${worker_pgid}" != "${self_pgid}" ]]; then
    kill -KILL -- "-${worker_pgid}" 2>/dev/null || true
  else
    kill -KILL "${worker_pid}" 2>/dev/null || true
  fi
  local kill_deadline=$((SECONDS + 2))
  while (( SECONDS < kill_deadline )); do
    urp_worker_signal_descendants "${worker_pid}" KILL "${pid_registry}"
    local alive=false
    urp_worker_process_alive "${worker_pid}" && alive=true
    if [[ "${worker_pgid}" =~ ^[0-9]+$ && "${worker_pgid}" != "${self_pgid}" ]] && urp_worker_group_alive "${worker_pgid}"; then
      alive=true
    fi
    if urp_worker_descendants_alive "${worker_pid}" "${pid_registry}"; then
      alive=true
    fi
    [[ "${alive}" == true ]] || break
    sleep 0.1
  done

  local cleanup_ok=true
  if urp_worker_process_alive "${worker_pid}" || urp_worker_group_alive "${worker_pgid}" || urp_worker_descendants_alive "${worker_pid}" "${pid_registry}"; then
    cleanup_ok=false
  fi
  if ! urp_reap_worker_containers "${container_registry}"; then
    printf 'worker cleanup could not verify all named containers from %s\n' "${container_registry}" >&2
    cleanup_ok=false
  fi
  wait "${worker_pid}" 2>/dev/null || true
  [[ "${cleanup_ok}" == true ]]
}
