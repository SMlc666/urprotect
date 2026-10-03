#!/usr/bin/env bash
set -euo pipefail

# This is deliberately a CI-only entrypoint.  Local validation stops before
# curl, extraction, or target execution; developers use the metadata validator.
requested_tier="${1:---tier}"
if [[ "${requested_tier}" == "--tier" ]]; then
  requested_tier="${2:-pr}"
fi
case "${requested_tier}" in pr|nightly|release) ;; *) echo "unsupported real-sample tier: ${requested_tier}" >&2; exit 2 ;; esac

if [[ "${CI:-}" != "true" || "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "real samples are acquired and executed only inside GitHub Actions CI" >&2
  exit 2
fi
case "$(uname -m)" in aarch64|arm64) ;; *) echo "real-sample suite requires native AArch64; got $(uname -m)" >&2; exit 2 ;; esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Parallel workers run in private sessions so an interrupt can stop the full
# worker/Docker descendant tree before the source archive and rootfs are
# removed by the parent trap.
# shellcheck source=scripts/real_sample_worker_cleanup.sh
source "${repo_root}/scripts/real_sample_worker_cleanup.sh"
manifest="${repo_root}/fixtures/real-samples/manifest.json"
candidates="${repo_root}/fixtures/real-samples/candidates.json"
runtime_closures="${repo_root}/fixtures/real-samples/runtime-closures.json"
artifact_root="${REAL_SAMPLE_ARTIFACT_ROOT:-${repo_root}/.artifacts/real-samples/${requested_tier}}"
mkdir -p "${artifact_root}"
artifact_root="$(cd "${artifact_root}" && pwd)"

for command in curl sha256sum python3 readelf timeout dotnet musl-gcc setsid ps; do
  command -v "${command}" >/dev/null 2>&1 || { echo "${command} is required" >&2; exit 127; }
done

python3 "${repo_root}/scripts/validate-real-samples.py" "${manifest}" \
  --candidates "${candidates}" --tier "${requested_tier}" >/dev/null
python3 "${repo_root}/scripts/validate-runtime-closures.py" \
  "${runtime_closures}" "${manifest}" >/dev/null
bionic_lock="${repo_root}/fixtures/real-samples/bionic-node-runtime-lock.json"
mapfile -t bionic_identity < <(python3 - "${bionic_lock}" <<'PY_BIONIC_IMAGE'
import json
import sys
lock = json.load(open(sys.argv[1], encoding="utf-8"))
print(lock["baseImage"]["requestedRef"])
print(lock["baseImage"]["id"])
print(lock["execution"]["loader"])
PY_BIONIC_IMAGE
)
bionic_image="${bionic_identity[0]}"
bionic_image_id="${bionic_identity[1]}"
bionic_loader="${bionic_identity[2]}"
bionic_lock_sha="$(sha256sum "${bionic_lock}" | awk '{print $1}')"
mapfile -t bionic_locked_limits < <(python3 - "${bionic_lock}" <<'PY_BIONIC_LIMITS'
import json
import sys
lock=json.load(open(sys.argv[1], encoding="utf-8"))
execution=lock["execution"]
for key in ("timeoutSeconds", "outputBytes", "memoryBytes", "processLimit", "outerMode", "pathPolicy", "runpath"):
    print(execution[key])
PY_BIONIC_LIMITS
)
bionic_timeout_seconds="${bionic_locked_limits[0]}"
bionic_output_limit="${bionic_locked_limits[1]}"
bionic_memory_bytes="${bionic_locked_limits[2]}"
bionic_process_limit="${bionic_locked_limits[3]}"
bionic_outer_mode="${bionic_locked_limits[4]}"
bionic_path_policy="${bionic_locked_limits[5]}"
bionic_runpath="${bionic_locked_limits[6]}"

launcher_path="${REAL_SAMPLE_LAUNCHER:-${repo_root}/native/urprotect-launcher/build/urprotect-launcher}"
if [[ ! -x "${launcher_path}" ]]; then
  echo "the native AArch64 launcher is required for full real-sample outer execution: ${launcher_path}" >&2
  exit 127
fi

runner_temp="${RUNNER_TEMP:-}"
if [[ -z "${runner_temp}" || "${runner_temp}" != /* ]]; then
  echo 'RUNNER_TEMP must be an absolute CI temporary directory' >&2
  exit 2
fi
mkdir -p "${runner_temp}"
# Keep package archives and verified indexes outside each sample's temporary
# root so every identity shares them, while extracted roots and evidence stay
# private and are still removed by the normal cleanup trap.
package_cache_root="${runner_temp%/}/urprotect-real-sample-package-cache"
package_archive_cache="${package_cache_root}/archives"
package_index_cache="${package_cache_root}/indexes"
mkdir -p "${package_archive_cache}" "${package_index_cache}"
temp_root="$(mktemp -d "${runner_temp%/}/urprotect-real-samples-${requested_tier}.XXXXXX")"
# Keep private names while allowing the helper's normal sudo/bubblewrap
# namespace path to traverse the temporary root through read-only binds.
chmod 711 "${temp_root}"
isolation_lock="${temp_root}/isolation.lock"
: > "${isolation_lock}"
isolation_dropper_dir="${temp_root}/isolation-dropper"
mkdir -p "${isolation_dropper_dir}"
chmod 755 "${isolation_dropper_dir}"
isolation_dropper="${isolation_dropper_dir}/urp-dropper"
cat > "${isolation_dropper_dir}/urp-dropper.c" <<'DROPper'
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int signal_ready(void) {
    const char *token = getenv("URP_READY_TOKEN");
    if (token == NULL || strlen(token) != 64 ||
        strspn(token, "0123456789abcdef") != 64) {
        dprintf(2, "dropper: invalid readiness token\n");
        return 125;
    }
    if (dprintf(2, "__URP_ISOLATION_READY__:%s__", token) < 0) {
        dprintf(2, "dropper: readiness marker failed: %s\n", strerror(errno));
        return 125;
    }
    unsetenv("URP_READY_TOKEN");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { dprintf(2, "dropper: missing target\\n"); return 125; }
    if (geteuid() == 0) {
        if (setgroups(0, NULL) != 0 && errno != EPERM) { dprintf(2, "dropper: setgroups: %s\\n", strerror(errno)); return 125; }
        if (setgid(65534) != 0) { dprintf(2, "dropper: setgid: %s\\n", strerror(errno)); return 125; }
        if (setuid(65534) != 0) { dprintf(2, "dropper: setuid: %s\\n", strerror(errno)); return 125; }
    }
    char **child = calloc((size_t)argc, sizeof(*child));
    if (child == NULL) { dprintf(2, "dropper: calloc: %s\\n", strerror(errno)); return 125; }
    const char *argv0 = getenv("URP_ARGV0");
    child[0] = (argv0 != NULL && *argv0 != '\0') ? (char *)argv0 : argv[1];
    for (int index = 2; index < argc; ++index) child[index - 1] = argv[index];
    child[argc - 1] = NULL;
    int ready_status = signal_ready();
    if (ready_status != 0) return ready_status;
    execv(argv[1], child);
    perror("execv");
    return 127;
}
DROPper
musl-gcc -static -O2 -s "${isolation_dropper_dir}/urp-dropper.c" -o "${isolation_dropper}"
chmod 755 "${isolation_dropper}"
rm -f "${isolation_dropper_dir}/urp-dropper.c"
parallelism="${REAL_SAMPLE_PARALLELISM:-4}"
if [[ ! "${parallelism}" =~ ^[1-9][0-9]*$ || "${parallelism}" -gt 8 ]]; then
  echo 'REAL_SAMPLE_PARALLELISM must be an integer from 1 through 8' >&2
  exit 2
fi
active_pids=()
active_pgids=()
active_pid_registries=()
active_container_registries=()
worker_registry_dir="${temp_root}/worker-registry"
mkdir -m 700 -p "${worker_registry_dir}"
mark_sanitization_failure() {
  [[ -d "${artifact_root}" ]] || return 0
  printf 'evidence-sanitized=false\n' > "${artifact_root}/evidence-sanitized.txt" 2>/dev/null || true
}
sanitize_evidence() {
  if [[ ! -d "${artifact_root}" || -L "${artifact_root}" ]]; then
    mark_sanitization_failure
    return 1
  fi
  rm -f -- "${artifact_root}/evidence-sanitized.txt"
  if ! python3 - "${artifact_root}" "${temp_root}" "${runner_temp}" "${package_cache_root}" "${package_archive_cache}" "${package_index_cache}" <<'PYSANITIZE'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
replacements = [value.encode("utf-8") for value in sys.argv[2:] if value]
try:
    paths = list(root.rglob("*"))
except OSError as error:
    print(f"evidence sanitizer cannot enumerate artifact root: {error}", file=sys.stderr)
    raise SystemExit(1)
for path in paths:
    try:
        if path.is_symlink():
            print(f"evidence sanitizer found a symlink: {path}", file=sys.stderr)
            raise SystemExit(1)
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data[:4096]:
            print(f"evidence sanitizer found a binary file: {path}", file=sys.stderr)
            raise SystemExit(1)
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as error:
            print(f"evidence sanitizer found non-text evidence {path}: {error}", file=sys.stderr)
            raise SystemExit(1)
        sanitized = data
        for value in replacements:
            sanitized = sanitized.replace(value, b"<runner-temp>")
        if sanitized != data:
            path.write_bytes(sanitized)
        for value in replacements:
            if value and value in sanitized:
                print(f"evidence sanitizer left a raw temporary path in {path}", file=sys.stderr)
                raise SystemExit(1)
except (OSError, UnicodeError) as error:
    print(f"evidence sanitizer could not sanitize retained evidence: {error}", file=sys.stderr)
    raise SystemExit(1)
PYSANITIZE
  then
    mark_sanitization_failure
    return 1
  fi
  printf 'evidence-sanitized=true\n' > "${artifact_root}/evidence-sanitized.txt"
}
cleanup() {
  local index pid pgid cleanup_pid cleanup_ok=true
  local cleanup_pids=()
  # Signal and reap all workers concurrently.  Sequential ten-second grace
  # periods would make shutdown scale with the parallelism setting.
  for index in "${!active_pids[@]}"; do
    pid="${active_pids[${index}]}"
    pgid="${active_pgids[${index}]:-}"
    urp_stop_worker_group "${pid}" "${pgid}" 10 \
      "${active_pid_registries[${index}]:-}" "${active_container_registries[${index}]:-}" &
    cleanup_pids+=("$!")
  done
  for index in "${!cleanup_pids[@]}"; do
    cleanup_pid="${cleanup_pids[${index}]}"
    if ! wait "${cleanup_pid}"; then
      cleanup_ok=false
      pid="${active_pids[${index}]}"
      printf 'worker cleanup did not prove process-group reaping for pid %s\n' "${pid}" >&2
    fi
  done
  for pid in "${active_pids[@]}"; do
    wait "${pid}" 2>/dev/null || true
  done
  if [[ "${cleanup_ok}" != true ]]; then
    printf 'refusing to remove real-sample temporary root while cleanup is unproven: %s\n' "${temp_root}" >&2
    mark_sanitization_failure
    return 0
  fi
  if ! sanitize_evidence; then
    printf 'refusing to declare complete evidence because sanitization failed\n' >&2
    return 0
  fi
  rm -rf -- "${temp_root}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

manifest_sha="$(sha256sum "${manifest}" | awk '{print $1}')"
overall_status=0
max_archive_bytes="$(PYTHONPATH="${repo_root}/scripts${PYTHONPATH:+:${PYTHONPATH}}" \
  python3 -c 'from real_sample_schema import MAX_REAL_SAMPLE_ARCHIVE_BYTES; print(MAX_REAL_SAMPLE_ARCHIVE_BYTES)')"

cli_dll="${URPROTECT_CLI_DLL:-${repo_root}/src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll}"
if [[ ! -f "${cli_dll}" ]]; then
  echo "the Release CLI assembly is required: ${cli_dll}" >&2
  exit 127
fi
# The matrix invokes the already-built assembly directly; project-driven
# invocation would re-evaluate restore/build coordination for every sample.
dotnet_cli=(dotnet "${cli_dll}")

project_fields() {
  python3 "${repo_root}/scripts/real_sample_project_fields.py" "$1" "${runtime_closures}" "${requested_tier}"
}

write_result() {
  local sample_root="$1" id="$2" expected_static="$3" expected_baseline="$4" expected_outer="$5" expected_host="$6"
  local actual_static="$7" actual_baseline="$8" actual_outer="$9" actual_host="${10}" artifact_sha="${11}" reason_static="${12}" reason_baseline="${13}" reason_outer="${14}"
  SAMPLE_ROOT="${sample_root}" SAMPLE_ID="${id}" SAMPLE_TIER="${requested_tier}" \
  REPO_ROOT="${repo_root}" \
  EXPECTED_STATIC="${expected_static}" EXPECTED_BASELINE="${expected_baseline}" EXPECTED_OUTER="${expected_outer}" EXPECTED_HOST="${expected_host}" \
  ACTUAL_STATIC="${actual_static}" ACTUAL_BASELINE="${actual_baseline}" ACTUAL_OUTER="${actual_outer}" ACTUAL_HOST="${actual_host}" \
  ARTIFACT_SHA="${artifact_sha}" SOURCE_ARTIFACT_SHA="${SOURCE_ARTIFACT_SHA:-${artifact_sha}}" RUNTIME_ARTIFACT_SHA="${RUNTIME_ARTIFACT_SHA:-}" \
  REASON_STATIC="${reason_static}" REASON_BASELINE="${reason_baseline}" REASON_OUTER="${reason_outer}" \
  FIRST_FAILURE_LAYER="${FIRST_FAILURE_LAYER:-}" \
  python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ['REPO_ROOT'], 'scripts'))
from real_sample_schema import first_failure_layer

root=os.environ['SAMPLE_ROOT']
expected={'static':os.environ['EXPECTED_STATIC'],'baseline':os.environ['EXPECTED_BASELINE'],'outerWrapper':os.environ['EXPECTED_OUTER'],'hostContext':os.environ['EXPECTED_HOST']}
actual={'static':os.environ['ACTUAL_STATIC'],'baseline':os.environ['ACTUAL_BASELINE'],'outerWrapper':os.environ['ACTUAL_OUTER'],'hostContext':os.environ['ACTUAL_HOST']}
reasons={'static':os.environ.get('REASON_STATIC',''),'baseline':os.environ.get('REASON_BASELINE',''),'outerWrapper':os.environ.get('REASON_OUTER',''),'hostContext':'Ordinary public executable has no HostContext entry contract.'}
result={'schemaVersion':2,'tier':os.environ['SAMPLE_TIER'],'projectId':os.environ['SAMPLE_ID'],'artifactSha256':os.environ.get('ARTIFACT_SHA','') or None,'sourceArtifactSha256':os.environ.get('SOURCE_ARTIFACT_SHA','') or None,'runtimeArtifactSha256':os.environ.get('RUNTIME_ARTIFACT_SHA','') or None,'cliSuccess':os.environ.get('CLI_SUCCESS','false').lower() == 'true','layers':{}}
for layer in ('static','baseline','outerWrapper','hostContext'):
 result['layers'][layer]={'expected':expected[layer],'actual':actual[layer],'status':'passed' if expected[layer]==actual[layer] else 'failed','reason':reasons[layer]}
explicit=os.environ.get('FIRST_FAILURE_LAYER','')
result['firstFailureLayer']=first_failure_layer(result['layers'], explicit or None)
json.dump(result,open(os.path.join(root,'result.json'),'w'),indent=2,sort_keys=True); open(os.path.join(root,'result.json'),'a').write('\n')
PY
}

write_runtime_closure_record() {
  local sample_root="$1" id="$2" runtime="$3" loader="$4" status="$5" source_hash="$6" runtime_hash="$7" reason="$8"
  python3 - "${sample_root}/runtime-closure.json" "${id}" "${runtime}" "${loader}" "${status}" "${source_hash}" "${runtime_hash}" "${reason}" <<'PY_CLOSURE'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
record = {}
if path.is_file():
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            record = value
    except (OSError, UnicodeError, json.JSONDecodeError):
        record = {}
record.update({
    "schemaVersion": 1,
    "projectId": sys.argv[2],
    "runtime": sys.argv[3],
    "loader": sys.argv[4],
    "status": sys.argv[5],
    "sourceArtifactSha256": sys.argv[6] or None,
    "runtimeArtifactSha256": sys.argv[7] or None,
})
if sys.argv[8]:
    record["reason"] = sys.argv[8]
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_CLOSURE
}

record_pack_cli_status() {
  local sample_root="$1" cli_status="$2" reason="$3"
  if ! python3 - "${sample_root}/outer-pack.json" "${cli_status}" <<'PY_PACK_STATUS'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(value, dict) or not isinstance(value.get("success"), bool):
    raise SystemExit(1)
value["cliExitCode"] = int(sys.argv[2])
path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_PACK_STATUS
  then
    write_outer_pack_boundary "${sample_root}" "${reason}" true "${cli_status}" pack-failed
  fi
}

write_outer_pack_boundary() {
  local sample_root="$1" reason="$2" failed="${3:-false}" cli_status="${4:-}" diagnostic_code="${5:-environment-unavailable}"
  local sample_id="${id:-}" bionic_lock_sha_value="${bionic_lock_sha:-}" bionic_runpath_value="${bionic_runpath:-}"
  local bionic_image_value="${bionic_image:-}" bionic_image_id_value="${bionic_image_id:-}" bionic_loader_value="${bionic_loader:-}"
  if [[ "${failed}" == true ]]; then
    BIONIC_IMAGE="${bionic_image_value}" BIONIC_IMAGE_ID="${bionic_image_id_value}" BIONIC_LOADER="${bionic_loader_value}" \
    python3 - "${sample_root}/outer-pack.json" "${reason}" "${cli_status}" "${diagnostic_code}" "${sample_id}" "${bionic_lock_sha_value}" "${bionic_runpath_value}" <<'PY_PACKFAIL'
import json
import os
import sys
from pathlib import Path
record = {
    "schemaVersion": 1,
    "toolVersion": "runner-boundary",
    "success": False,
    "category": "pack" if sys.argv[3] not in {"", "null"} else "preflight",
    "payload": {},
    "output": {"published": False},
    "diagnostics": [{"code": sys.argv[4], "message": sys.argv[2]}],
}
record["cliExitCode"] = int(sys.argv[3]) if sys.argv[3] not in {"", "null"} else None
if sys.argv[5] == "nodejs":
    record.update({
        "executionMode": "outer-path-preserving",
        "pathPolicy": "absolute-dt-runpath-preserved",
        "runpath": sys.argv[7],
        "lockSha256": sys.argv[6],
        "image": os.environ.get("BIONIC_IMAGE", ""),
        "imageId": os.environ.get("BIONIC_IMAGE_ID", ""),
        "loader": os.environ.get("BIONIC_LOADER", "/system/bin/linker64"),
        "packInvocation": {"attempted": bool(sys.argv[3] not in {"", "null"}), "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
    })
Path(sys.argv[1]).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_PACKFAIL
  else
    python3 - "${sample_root}/outer-pack.json" "${reason}" "${sample_id}" "${bionic_lock_sha_value}" "${bionic_runpath_value}" <<'PY_PACKNA'
import json
import os
import sys
from pathlib import Path
record = {"schemaVersion": 1, "status": "not-applicable", "reason": sys.argv[2]}
if sys.argv[3] == "nodejs":
    record.update({
        "executionMode": "outer-path-preserving",
        "pathPolicy": "absolute-dt-runpath-preserved",
        "runpath": sys.argv[5],
        "lockSha256": sys.argv[4],
        "image": os.environ.get("BIONIC_IMAGE", ""),
        "imageId": os.environ.get("BIONIC_IMAGE_ID", ""),
        "loader": os.environ.get("BIONIC_LOADER", "/system/bin/linker64"),
        "packInvocation": {"attempted": False, "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
    })
Path(sys.argv[1]).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_PACKNA
  fi
}

remove_unreferenced_preflight_markers() {
  local sample_root="$1" layer="$2" pack_status="${3:-}"
  local log_layer="${layer}"
  [[ "${layer}" == "outerWrapper" ]] && log_layer=outer

  # A runner preflight has no target process and therefore cannot retain the
  # helper/target status files emitted by an earlier bionic runner phase.  The
  # execution record intentionally carries null statuses and only the
  # preflight JSON owns that outcome.
  rm -f -- \
    "${sample_root}/logs/${log_layer}.helper-status" \
    "${sample_root}/logs/${log_layer}.status"

  # A pack-status marker is retained only when the managed pack command was
  # actually attempted.  The bionic no-pack preflight report explicitly uses
  # packInvocation.attempted=false and cliExitCode=null.  The separate
  # container-setup.status marker remains owned by the bionic host summary when
  # that summary records a setup status; it is not a target-layer marker.
  if [[ "${layer}" == "outerWrapper" && -z "${pack_status}" ]]; then
    rm -f -- "${sample_root}/logs/outer-pack.status"
  fi

  # Keep the setup marker only when the host-generated bionic summary still
  # owns a concrete setup status.  A failed/invalid runner preflight can leave
  # this file behind even though the converted execution record has no such
  # reference.
  if [[ -f "${sample_root}/logs/container-setup.status" ]] && ! python3 - "${sample_root}/logs/bionic-node-result.json" <<'PY_BIONIC_SETUP_OWNER'
import json
import sys
from pathlib import Path
try:
    value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    statuses = value.get("containerStatuses") if isinstance(value, dict) else None
    setup = statuses.get("setup") if isinstance(statuses, dict) else None
except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
    raise SystemExit(1)
if isinstance(setup, bool) or not isinstance(setup, int) or not 0 <= setup <= 255:
    raise SystemExit(1)
PY_BIONIC_SETUP_OWNER
  then
    rm -f -- "${sample_root}/logs/container-setup.status"
  fi
}

write_execution_evidence() {
  local sample_root="$1" id="$2" artifact_path="$3"
  local baseline_applicable="$4" baseline_expected="$5" baseline_expected_status="$6" baseline_invocation="$7" baseline_command_b64="$8" baseline_status="$9" baseline_result="${10}" baseline_attempted="${11}" baseline_helper_status="${12}"
  local outer_applicable="${13}" outer_expected="${14}" outer_mode="${15}" outer_command_b64="${16}" outer_status="${17}" outer_result="${18}" outer_attempted="${19}" outer_helper_status="${20}" outer_pack_status="${21}"
  local baseline_preflight_outcome="${22:-}" outer_preflight_outcome="${23:-}" baseline_preflight_reason="${24:-}" outer_preflight_reason="${25:-}"
  local bionic_lock_sha_value="${26:-}" bionic_timeout_value="${27:-}" bionic_output_value="${28:-}" bionic_memory_value="${29:-}" bionic_pids_value="${30:-}" bionic_mode_value="${31:-}" bionic_path_policy_value="${32:-}" bionic_runpath_value="${33:-}"
  python3 - "${sample_root}/execution.json" "${id}" "${artifact_path}" "${baseline_applicable}" "${baseline_expected}" "${baseline_expected_status}" "${baseline_invocation}" "${baseline_command_b64}" "${baseline_status}" "${baseline_result}" "${baseline_attempted}" "${baseline_helper_status}" "${outer_applicable}" "${outer_expected}" "${outer_mode}" "${outer_command_b64}" "${outer_status}" "${outer_result}" "${outer_attempted}" "${outer_helper_status}" "${outer_pack_status}" "${baseline_preflight_outcome}" "${outer_preflight_outcome}" "${baseline_preflight_reason}" "${outer_preflight_reason}" "${bionic_lock_sha_value}" "${bionic_timeout_value}" "${bionic_output_value}" "${bionic_memory_value}" "${bionic_pids_value}" "${bionic_mode_value}" "${bionic_path_policy_value}" "${bionic_runpath_value}" <<'PY_EXECUTION'
import base64
import json
import sys
from pathlib import Path

PREFLIGHT_PRODUCER = "run-real-sample-matrix.sh"
PREFLIGHT_SCHEMA_VERSION = 1


def command(value):
    if not value:
        return None
    try:
        decoded = json.loads(base64.urlsafe_b64decode(value).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, list) and decoded else None


def as_bool(value):
    return value == "true"


def optional_int(value):
    if value in {"", "null"}:
        return None
    return int(value)


def helper_outcome(*, attempted, helper_status, target_status):
    if helper_status == 124:
        return "helper-timeout"
    if helper_status == 125:
        return "helper-environment"
    if helper_status == 126:
        return "helper-output-limit"
    if target_status is not None:
        return "target-exit"
    return "helper-protocol"


def execution_entry(*, applicable, expected, invocation, command_value, status_value,
                    result, attempted, helper_status, layer, expected_status,
                    pack_status=None, preflight_outcome="", preflight_reason="",
                    mode=None):
    is_applicable = as_bool(applicable)
    is_preflight = is_applicable and bool(preflight_outcome)
    is_attempted = as_bool(attempted) if is_applicable else False
    log_layer = "outer" if layer == "outerWrapper" else layer
    status = optional_int(status_value) if is_applicable and status_value not in {"", "null"} else None
    helper = optional_int(helper_status) if is_applicable and not is_preflight else None
    invocation_source = (
        "not-applicable" if not is_applicable
        else "runner-derived-wrapper" if layer == "outerWrapper"
        else "runner-preflight" if is_preflight
        else invocation
    )
    container_protocol = {}
    if project_id == "nodejs" and bionic_lock_sha:
        container_protocol = {
            "containerStatus": None,
            "dockerStatus": None,
            "cleanupContainerStatus": None,
            "timeoutSeconds": int(bionic_timeout),
            "outputLimitBytes": int(bionic_output),
            "outputBytes": 0,
            "memoryBytes": int(bionic_memory),
            "processLimit": int(bionic_pids),
            "lockSha256": bionic_lock_sha,
            "pathMode": bionic_mode,
            "pathPolicy": bionic_path_policy,
            "runpath": bionic_runpath,
            "protocolAuthority": "host-generated-runner-preflight",
            "cleanupAuthority": "host-generated-after-docker-inspect",
            "runpathVerified": False,
            "allNamedContainersReaped": False,
        }
    helper_path = root / f"logs/{log_layer}.helper.json"
    if is_applicable and not is_preflight and helper_path.is_file():
        try:
            helper_value = json.loads(helper_path.read_text(encoding="utf-8"))
            if helper_value.get("producer") == "run-bionic-node-sample.sh":
                container_protocol = {
                    "containerStatus": helper_value.get("containerStatus"),
                    "dockerStatus": helper_value.get("dockerStatus"),
                    "cleanupContainerStatus": helper_value.get("cleanupContainerStatus"),
                    "timeoutSeconds": helper_value.get("timeoutSeconds"),
                    "outputLimitBytes": helper_value.get("outputLimitBytes"),
                    "outputBytes": helper_value.get("outputBytes"),
                    "lockSha256": helper_value.get("lockSha256"),
                    "pathMode": helper_value.get("pathMode"),
                    "pathPolicy": helper_value.get("pathPolicy"),
                    "protocolAuthority": helper_value.get("protocolAuthority"),
                    "cleanupAuthority": helper_value.get("cleanupAuthority"),
                    "runpathVerified": helper_value.get("runpathVerified"),
                    "allNamedContainersReaped": helper_value.get("allNamedContainersReaped"),
                    "memoryBytes": helper_value.get("memoryBytes"),
                    "processLimit": helper_value.get("processLimit"),
                    "runpath": helper_value.get("runpath"),
                }
        except (OSError, UnicodeError, json.JSONDecodeError):
            container_protocol = {}
    return {
        "applicable": is_applicable,
        "attempted": is_attempted,
        "mode": mode if layer == "outerWrapper" and is_applicable else None,
        "invocationSource": invocation_source,
        "resolvedCommand": command(command_value) if is_applicable else None,
        "expectedStatus": int(expected_status) if is_applicable else None,
        "status": status,
        "targetStatus": status,
        "helperStatus": helper,
        "helperStatusPath": f"logs/{log_layer}.helper-status" if is_applicable and not is_preflight and helper is not None else None,
        "helperResultPath": f"logs/{log_layer}.helper.json" if is_applicable and not is_preflight else None,
        "preflightResultPath": f"logs/{log_layer}.preflight.json" if is_preflight else None,
        "outcome": (
            "not-applicable" if not is_applicable
            else preflight_outcome if is_preflight
            else helper_outcome(attempted=is_attempted, helper_status=helper, target_status=status)
        ),
        "packStatus": optional_int(pack_status) if layer == "outerWrapper" and is_applicable else None,
        "packStatusPath": "logs/outer-pack.status" if layer == "outerWrapper" and is_applicable and pack_status not in {"", "null"} else None,
        "result": result,
        "stdoutPath": f"logs/{log_layer}.stdout" if is_applicable else None,
        "stderrPath": f"logs/{log_layer}.stderr" if is_applicable else None,
        "statusPath": f"logs/{log_layer}.status" if is_applicable and status is not None else None,
        **container_protocol,
        "reason": f"{layer} policy is not applicable" if not is_applicable else preflight_reason or None,
        "expectedResult": expected,
    }


(
    _, execution_path, project_id, artifact_path, baseline_applicable, baseline_expected,
    baseline_expected_status, baseline_invocation, baseline_command_b64, baseline_status,
    baseline_result, baseline_attempted, baseline_helper_status, outer_applicable,
    outer_expected, outer_mode, outer_command_b64, outer_status, outer_result,
    outer_attempted, outer_helper_status, outer_pack_status, baseline_preflight_outcome,
    outer_preflight_outcome, baseline_preflight_reason, outer_preflight_reason,
    bionic_lock_sha, bionic_timeout, bionic_output, bionic_memory, bionic_pids,
    bionic_mode, bionic_path_policy, bionic_runpath,
) = sys.argv
root = Path(execution_path).parent
record = {
    "schemaVersion": 1,
    "projectId": project_id,
    "artifactPath": "/" + artifact_path.lstrip("/"),
    "baseline": execution_entry(
        applicable=baseline_applicable,
        expected=baseline_expected,
        invocation=baseline_invocation,
        command_value=baseline_command_b64,
        status_value=baseline_status,
        result=baseline_result,
        attempted=baseline_attempted,
        helper_status=baseline_helper_status,
        layer="baseline",
        expected_status=baseline_expected_status,
        preflight_outcome=baseline_preflight_outcome,
        preflight_reason=baseline_preflight_reason,
    ),
    "outerWrapper": execution_entry(
        applicable=outer_applicable,
        expected=outer_expected,
        invocation="declared",
        command_value=outer_command_b64,
        status_value=outer_status,
        result=outer_result,
        attempted=outer_attempted,
        helper_status=outer_helper_status,
        layer="outerWrapper",
        expected_status=baseline_expected_status,
        pack_status=outer_pack_status,
        preflight_outcome=outer_preflight_outcome,
        preflight_reason=outer_preflight_reason,
        mode=outer_mode,
    ),
}

for layer, log_layer in (("baseline", "baseline"), ("outerWrapper", "outer")):
    entry = record[layer]
    if entry["preflightResultPath"] is not None:
        preflight_path = root / entry["preflightResultPath"]
        preflight_path.parent.mkdir(parents=True, exist_ok=True)
        preflight_path.write_text(json.dumps({
            "schemaVersion": PREFLIGHT_SCHEMA_VERSION,
            "producer": PREFLIGHT_PRODUCER,
            "layer": layer,
            "stage": layer,
            "outcome": entry["outcome"],
            "reason": entry["reason"],
            "attempted": False,
            "helperStatus": None,
            "targetStatus": None,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for stream in ("stdoutPath", "stderrPath"):
        stream_path = entry.get(stream)
        if stream_path is not None:
            path = root / stream_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
Path(execution_path).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_EXECUTION
}

write_failure_evidence() {
  local sample_root="$1" id="$2" expected_static="$3" expected_baseline="$4"
  local expected_outer="$5" expected_host="$6" reason="$7" first_failure="${8:-acquisition}"
  local source_hash="${artifact_sha:-}"
  local baseline_actual=not-applicable outer_actual=not-applicable
  [[ "${expected_baseline}" != not-applicable ]] && baseline_actual=environment-unavailable
  [[ "${expected_outer}" != not-applicable ]] && outer_actual=environment-unavailable
  printf 'evidence unavailable: %s\n' "${reason}" > "${sample_root}/readelf.txt"
  python3 - "${sample_root}/elf-fingerprint.json" "${id}" "${reason}" <<'PY_FAILURE_FINGERPRINT'
import json
import sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schemaVersion": 2,
    "projectId": sys.argv[2],
    "error": sys.argv[3],
    "unknownFields": ["all"],
}) + "\n", encoding="utf-8")
PY_FAILURE_FINGERPRINT
  python3 - "${sample_root}/fingerprint-comparison.json" "${id}" "${reason}" <<'PY_FAILURE_COMPARISON'
import json
import sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schemaVersion": 2,
    "projectId": sys.argv[2],
    "status": "not-applicable",
    "reason": sys.argv[3],
}) + "\n", encoding="utf-8")
PY_FAILURE_COMPARISON
  python3 - "${sample_root}/urprotect-report.json" "${reason}" "${source_hash}" <<'PY_FAILURE_REPORT'
import json
import sys
from pathlib import Path
source_hash = sys.argv[3] or None
Path(sys.argv[1]).write_text(json.dumps({
    "schemaVersion": 1,
    "toolVersion": "runner-boundary",
    "success": False,
    "input": {"byteLength": None, "sha256": source_hash},
    "summary": {},
    "diagnostics": [{"severity": "Error", "code": "environment-unavailable", "message": sys.argv[2], "offset": None}],
}) + "\n", encoding="utf-8")
PY_FAILURE_REPORT
  if [[ -n "${source_hash}" ]]; then
    printf 'sourceArtifactSha256=%s\nartifactSha256=%s\nfailure=%s\n' "${source_hash}" "${source_hash}" "${reason}" > "${sample_root}/hashes.txt"
  else
    printf 'failure=%s\n' "${reason}" > "${sample_root}/hashes.txt"
  fi
  FIRST_FAILURE_LAYER="${first_failure}" CLI_SUCCESS=false SOURCE_ARTIFACT_SHA="${source_hash}" write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" "${expected_host}" \
    environment-unavailable "${baseline_actual}" "${outer_actual}" "${expected_host}" "${source_hash}" "${reason}" "${reason}" "${reason}"
  write_runtime_closure_record "${sample_root}" "${id}" "${runtime:-unknown}" "${loader:-unknown}" environment-unavailable "${source_hash}" "" "${reason}"
  if [[ "${expected_outer}" == not-applicable ]]; then
    write_outer_pack_boundary "${sample_root}" "${reason}" false
  else
    write_outer_pack_boundary "${sample_root}" "${reason}" true
  fi
  : > "${sample_root}/logs/baseline.stdout"
  : > "${sample_root}/logs/baseline.stderr"
  : > "${sample_root}/logs/outer.stdout"
  : > "${sample_root}/logs/outer.stderr"
  write_execution_evidence "${sample_root}" "${id}" "${artifact_path:-unknown}" \
    "${baseline_applicable:-false}" "${expected_baseline}" "${baseline_expected_status:-0}" "${baseline_invocation:-}" "${baseline_command_b64:-W10=}" "" "${baseline_actual}" false "" \
    "${outer_applicable:-false}" "${expected_outer}" "${outer_mode:-outer-execveat}" W10= "" "${outer_actual}" false "" "" \
    "preflight-environment-unavailable" "preflight-environment-unavailable" "${reason}" "${reason}" "${bionic_lock_sha}" "${bionic_timeout_seconds}" "${bionic_output_limit}" "${bionic_memory_bytes}" "${bionic_process_limit}" "${bionic_outer_mode}" "${bionic_path_policy}" "${bionic_runpath}"
  rm -rf -- "${temp_root}/${id}"
  printf 'raw-inputs-removed=true\n' > "${sample_root}/raw-inputs-removed.txt"
}

classify_isolation_result() {
  python3 - "$1" "$2" "$3" "$4" "${repo_root}/scripts" <<'PYSTATUS'
import sys
sys.path.insert(0, sys.argv[5])
from real_sample_schema import classify_isolated_result

def optional_int(value):
    return None if value in {"", "null"} else int(value)

print(classify_isolated_result(
    attempted=sys.argv[1] == "true",
    helper_status=optional_int(sys.argv[2]),
    target_status=optional_int(sys.argv[3]),
    expected=int(sys.argv[4]),
))
PYSTATUS
}

read_isolation_result() {
  python3 - "$1" "${repo_root}/scripts" <<'PYRESULT'
import json
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
from real_sample_schema import validate_isolation_result

path = Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid isolation result protocol: {error}")
errors = validate_isolation_result(value)
if errors:
    raise SystemExit("; ".join(errors))
attempted = value["attempted"]
helper_status = value.get("helperStatus")
target_status = value.get("targetStatus")
print("{}|{}|{}".format(
    "true" if attempted else "false",
    "" if helper_status is None else helper_status,
    "" if target_status is None else target_status,
))
PYRESULT
}

run_isolated_command() {
  local extract_root="$1" sample_root="$2" label="$3" command_b64="$4"
  local argv0="${5:-}"
  local -a argv0_args=()
  if [[ -n "${argv0}" ]]; then
    argv0_args=(--argv0 "${argv0}")
  fi
  local -a command_parts
  mapfile -t command_parts < <(python3 - "${command_b64}" <<'PYISO'
import base64, json, sys
try:
    values=json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode())
except (ValueError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid baseline command: {error}")
if not isinstance(values, list):
    raise SystemExit("baseline command must be a list")
for value in values:
    if not isinstance(value, str):
        raise SystemExit("baseline command arguments must be strings")
    print(value)
PYISO
  )
  if [[ "${#command_parts[@]}" -eq 0 ]]; then
    echo "isolated command is empty or malformed" >&2
    return 125
  fi
  {
    printf 'run-isolated command=%q\n' "${command_parts[@]}"
    set +e
    python3 "${repo_root}/scripts/run-isolated-real-sample.py" \
      --rootfs "${extract_root}" --stdout "${sample_root}/logs/${label}.stdout" \
      --stderr "${sample_root}/logs/${label}.stderr" \
      --result-json "${sample_root}/logs/${label}.helper.json" \
      --timeout 30 --memory-bytes 536870912 \
      --process-limit 32 --output-limit 1048576 --dropper "${isolation_dropper}" \
      --lock "${isolation_lock}" "${argv0_args[@]}" -- "${command_parts[@]}"
    local isolation_status=$?
    set -e
    printf 'status=%s\n' "${isolation_status}" >&2
    return "${isolation_status}"
  } 2>"${sample_root}/logs/${label}.isolation.log"
}

run_isolated_baseline() {
  local extract_root="$1" sample_root="$2" artifact_path="$3" command_b64="$4"
  local declared_path="/${artifact_path#/}"
  local -a values
  mapfile -t values < <(python3 - "${command_b64}" <<'PYISO'
import base64, json, sys
values=json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode())
for value in values:
    print(value)
PYISO
  )
  if [[ "${#values[@]}" -eq 0 || "${values[0]}" != "${declared_path}" ]]; then
    echo "baseline policy command does not launch declared artifact ${declared_path}" >&2
    return 125
  fi
  run_isolated_command "${extract_root}" "${sample_root}" baseline "${command_b64}" "$(basename -- "${declared_path}")"
}
prepare_runtime_root() {
  local root="$1" temporary_directory="${1%/}/tmp" proc_directory="${1%/}/proc" dev_directory="${1%/}/dev"
  chmod 755 "${root}"
  for directory in "${temporary_directory}" "${proc_directory}" "${dev_directory}"; do
    if [[ -L "${directory}" || ( -e "${directory}" && ! -d "${directory}" ) ]]; then
      echo "runtime closure has a non-directory mount target: ${directory}" >&2
      return 1
    fi
    mkdir -p "${directory}"
  done
  chmod 1777 "${temporary_directory}"
}


resolve_artifact() {
  local root="$1" relative="$2" candidate link target
  candidate="${root}/${relative}"
  for _ in 1 2 3 4 5 6 7 8; do
    if [[ ! -L "${candidate}" ]]; then
      if [[ -f "${candidate}" ]]; then
        printf '%s\n' "${candidate}"
        return 0
      fi
      return 1
    fi
    link="$(readlink -- "${candidate}")"
    if [[ "${link}" = /* ]]; then
      target="${root}/${link#/}"
    else
      target="$(dirname -- "${candidate}")/${link}"
    fi
    candidate="$(python3 - "${root}" "${target}" <<'PY'
import os, sys
root = os.path.realpath(sys.argv[1])
candidate = os.path.normpath(sys.argv[2])
if os.path.commonpath((root, candidate)) != root:
    raise SystemExit(1)
print(candidate)
PY
)" || return 1
  done
  return 1
}

process_project() {
  local json_record="$1"
  local id archive_url version archive_path archive_sha archive_format artifact_path producer expected_static baseline_applicable expected_baseline baseline_mode baseline_command_b64 baseline_expected_status baseline_invocation outer_applicable expected_outer outer_mode runtime loader apk_metadata_b64 source_kind
  IFS=$'\t' read -r id archive_url version archive_path archive_sha archive_format artifact_path producer expected_static baseline_applicable expected_baseline baseline_mode baseline_command_b64 baseline_expected_status baseline_invocation outer_applicable expected_outer outer_mode runtime loader apk_metadata_b64 source_kind < <(project_fields "${json_record}")
  local sample_root="${artifact_root}/${id}" sample_tmp archive extract_root
  sample_tmp="${temp_root}/${id}"
  archive="${sample_tmp}/source.archive"
  extract_root="${sample_tmp}/extract"
  rm -rf -- "${sample_root}" "${sample_tmp}"; mkdir -p "${sample_root}/logs" "${sample_tmp}"
  chmod 711 "${sample_tmp}"
  {
    printf 'projectId=%s\nversion=%s\narchiveUrl=%s\narchivePath=%s\narchiveSha256=%s\nartifactPath=%s\narchiveFormat=%s\n' \
      "${id}" "${version}" "${archive_url}" "${archive_path}" "${archive_sha}" "${artifact_path}" "${archive_format}"
    printf 'manifestSha256=%s\ntier=%s\nrawArtifactsUploaded=false\n' "${manifest_sha}" "${requested_tier}"
    printf 'parallelism=%s\n' "${parallelism}"
  } > "${sample_root}/source.txt"
  {
    uname -a; printf 'architecture=%s\n' "$(uname -m)"; getconf PAGESIZE 2>/dev/null || true
    printf 'network=none\nfilesystem=read-only-rootfs-temp-output\nprivileges=drop-all-no-new-privileges\ncleanup=runner-temp-trap\n'
    printf 'runtime=%s\nloader=%s\n' "${runtime}" "${loader}"
  } > "${sample_root}/environment.txt"
  : > "${sample_root}/readelf.txt"
  printf '{"schemaVersion":1,"projectId":"%s","status":"pending"}\n' "${id}" > "${sample_root}/elf-fingerprint.json"
  printf '{"schemaVersion":1,"projectId":"%s","status":"failed","reason":"acquisition-not-reached"}\n' "${id}" > "${sample_root}/fingerprint-comparison.json"
  printf '{"schemaVersion":1,"projectId":"%s","status":"pending"}\n' "${id}" > "${sample_root}/urprotect-report.json"
  printf 'pending archive verification\n' > "${sample_root}/hashes.txt"

  local archive_status=0
  if curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --retry-all-errors \
      --connect-timeout 20 --max-time 180 --max-filesize "${max_archive_bytes}" \
      --output "${archive}" "${archive_url}" \
      >"${sample_root}/logs/acquisition.log" 2>&1; then archive_status=0; else archive_status=$?; fi
  if [[ "${archive_status}" -ne 0 || ! -s "${archive}" ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable "archive download failed"
    return 1
  fi
  if [[ "$(stat -c '%s' "${archive}")" -gt "${max_archive_bytes}" ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable "archive exceeds ${max_archive_bytes} byte acquisition limit"
    return 1
  fi
  if printf '%s  %s\n' "${archive_sha}" "${archive}" | sha256sum -c - > "${sample_root}/logs/archive-sha256.log" 2>&1; then :; else
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable "archive SHA-256 mismatch"
    return 1
  fi
  printf 'archiveSha256=%s\n' "${archive_sha}" > "${sample_root}/hashes.txt"
  local -a apk_metadata_args=()
  if [[ "${archive_format}" == apk ]]; then
    mapfile -t apk_metadata_args < <(python3 - "${apk_metadata_b64}" <<'PYAPK'
import base64, json, sys
try:
    metadata = json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode("utf-8"))
except (ValueError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid locked APK metadata: {error}")
for key in ("package", "version", "architecture", "origin", "license"):
    value = metadata.get(key)
    if not isinstance(value, str) or not value or any(char in value for char in "\0\r\n\t"):
        raise SystemExit(f"locked APK metadata {key} is missing or invalid")
    print(f"--expected-apk-{key}")
    print(value)
PYAPK
    )
  fi
  if python3 "${repo_root}/scripts/extract-real-sample.py" --archive "${archive}" --format "${archive_format}" --destination "${extract_root}" "${apk_metadata_args[@]}" > "${sample_root}/logs/extraction.log" 2>&1; then :; else
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable "archive extraction failed"
    return 1
  fi
  local artifact
  if ! artifact="$(resolve_artifact "${extract_root}" "${artifact_path}")"; then
    find "${extract_root}" -maxdepth 5 \( -name '*redis*' -o -name '*server*' \) -ls \
      > "${sample_root}/logs/declared-artifact-search.log" 2>&1 || true
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable "declared artifact path is missing or a symlink"
    return 1
  fi
  local artifact_sha; artifact_sha="$(sha256sum "${artifact}" | awk '{print $1}')"
  printf 'artifactSha256=%s\nsourceArtifactSha256=%s\n' "${artifact_sha}" "${artifact_sha}" >> "${sample_root}/hashes.txt"
  local inspect_status=0
  if python3 "${repo_root}/scripts/inspect-real-sample.py" --input "${artifact}" --output "${sample_root}/elf-fingerprint.json" \
      --readelf-output "${sample_root}/readelf.txt" --project-id "${id}" --producer "${producer}" --runtime "${runtime}" > "${sample_root}/logs/inspect.log" 2>&1; then :; else inspect_status=$?; fi
  if [[ "${inspect_status}" -ne 0 ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable "ELF fingerprint inspection failed" fingerprint
    return 1
  fi
  printf '%s\n' "${json_record}" > "${sample_tmp}/project.json"
  local runtime_root="${sample_tmp}/runtime-root"
  local closure_failed=false closure_reason='' runtime_artifact='' runtime_artifact_sha=''
  local bionic_pending=false
  local needs_runtime_oracle=false
  if [[ "${expected_baseline}" != not-applicable || "${expected_outer}" != not-applicable ]]; then
    needs_runtime_oracle=true
  fi
  if [[ "${needs_runtime_oracle}" == false ]]; then
    printf 'resolver=not-applicable\n' > "${sample_root}/runtime-closure.txt"
    write_runtime_closure_record "${sample_root}" "${id}" "${runtime}" "${loader}" not-applicable "${artifact_sha}" "" 'No applicable baseline or outer-wrapper policy is enabled for this identity.'
  elif [[ "${baseline_mode}" == runtime-closure-unavailable ]]; then
    closure_failed=true
    closure_reason="locked runtime closure policy explicitly declares environment-unavailable for ${id}"
    printf 'resolver=policy-environment-boundary\n' > "${sample_root}/runtime-closure.txt"
  elif [[ "${runtime}" == bionic ]]; then
    # The bionic helper assembles the reviewed closure inside the fresh native
    # Termux container after the source archive has already been acquired and
    # fingerprinted by this runner. It owns both bionic process oracles.
    bionic_pending=true
    printf 'resolver=termux-node-lock-v1\n' > "${sample_root}/runtime-closure.txt"
  elif [[ "${source_kind}" == "alpine-minirootfs" ]]; then
    runtime_root="${extract_root}"
    printf 'resolver=provenance-archive\n' > "${sample_root}/runtime-closure.txt"
  elif [[ "${runtime}" == "glibc" || "${runtime}" == "musl" ]]; then
    if python3 "${repo_root}/scripts/build-runtime-closure.py" \
        --runtime "${runtime}" --runtime-closures "${runtime_closures}" \
        --project "${sample_tmp}/project.json" --rootfs "${runtime_root}" \
        --work-root "${sample_tmp}/closure-work" --index-dir "${package_index_cache}" \
        --package-cache "${package_archive_cache}" \
        --lock-output "${sample_root}/runtime-closure.json" \
        > "${sample_root}/logs/closure.log" 2>&1; then
      :
    else
      closure_failed=true
      closure_reason='runtime dependency closure failed'
    fi
    printf 'resolver=%s\n' "${runtime}" > "${sample_root}/runtime-closure.txt"
  else
    closure_failed=true
    closure_reason="unsupported runtime closure family: ${runtime}"
    printf 'resolver=unsupported\n' > "${sample_root}/runtime-closure.txt"
  fi
  if [[ "${closure_failed}" == false && "${needs_runtime_oracle}" == true && "${bionic_pending}" == false ]]; then
    if ! runtime_artifact="$(resolve_artifact "${runtime_root}" "${artifact_path}")"; then
      closure_failed=true
      closure_reason='runtime closure does not contain the declared artifact'
    else
      runtime_artifact_sha="$(sha256sum "${runtime_artifact}" | awk '{print $1}')"
      printf 'runtimeArtifactSha256=%s\n' "${runtime_artifact_sha}" >> "${sample_root}/hashes.txt"
      if [[ "${runtime_artifact_sha}" != "${artifact_sha}" ]]; then
        closure_failed=true
        closure_reason='reconstructed runtime artifact SHA-256 differs from the acquired source artifact'
      elif ! prepare_runtime_root "${runtime_root}"; then
        closure_failed=true
        closure_reason='runtime closure cannot provide an isolated writable /tmp'
      fi
    fi
  fi
  if [[ "${closure_failed}" == false && "${needs_runtime_oracle}" == true && "${bionic_pending}" == false ]]; then
    write_runtime_closure_record "${sample_root}" "${id}" "${runtime}" "${loader}" assembled "${artifact_sha}" "${runtime_artifact_sha}" ''
  elif [[ "${closure_failed}" == true ]]; then
    write_runtime_closure_record "${sample_root}" "${id}" "${runtime}" "${loader}" environment-unavailable "${artifact_sha}" "${runtime_artifact_sha}" "${closure_reason}"
  fi
  local command_json=W10= invocation_source=not-applicable
  if [[ "${expected_baseline}" != not-applicable ]]; then
    if [[ -n "${baseline_command_b64}" && "${baseline_command_b64}" != W10= ]]; then
      command_json="${baseline_command_b64}"
      invocation_source=declared
    elif [[ "${baseline_invocation}" == declared-artifact-version && "${runtime}" != bionic ]]; then
      command_json="$(python3 - "${artifact_path}" <<'PYCOMMAND'
import base64, json, sys
print(base64.urlsafe_b64encode(json.dumps(["/" + sys.argv[1].lstrip("/"), "--version"]).encode()).decode())
PYCOMMAND
      )"
      invocation_source=validated-wildcard
    elif [[ "${runtime}" == bionic ]]; then
      command_json=W10=
      invocation_source=declared
    else
      closure_failed=true
      closure_reason='baseline command is absent and its invocation policy is not the validated wildcard'
    fi
  fi
  local outer_command_json=W10=
  if [[ "${expected_outer}" != not-applicable && "${command_json}" != W10= ]]; then
    outer_command_json="$(python3 - "${command_json}" <<'PYOUTERPLAN'
import base64, json, sys
values = json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode("utf-8"))
values[0] = "/usr/local/bin/urprotect-packed"
print(base64.urlsafe_b64encode(json.dumps(values).encode()).decode())
PYOUTERPLAN
    )"
  fi
  local fingerprint_status=0
  if python3 "${repo_root}/scripts/compare-real-sample-fingerprint.py" --manifest "${manifest}" --project-id "${id}" \
      --fingerprint "${sample_root}/elf-fingerprint.json" --output "${sample_root}/fingerprint-comparison.json" > "${sample_root}/logs/fingerprint-compare.log" 2>&1; then :; else fingerprint_status=$?; fi
  local validator_status=0
  if "${dotnet_cli[@]}" validate "${artifact}" --no-analysis --json - > "${sample_root}/urprotect-report.json" 2> "${sample_root}/logs/urprotect.log"; then :; else validator_status=$?; fi
  local actual_static
  if [[ "${fingerprint_status}" -ne 0 ]]; then actual_static=unexpected-rejection
  elif [[ "${validator_status}" -eq 0 && "${expected_static}" == expected-rejected ]]; then actual_static=unexpected-acceptance
  elif [[ "${validator_status}" -eq 0 ]]; then actual_static=validated
  elif [[ "${expected_static}" == expected-rejected ]]; then actual_static=expected-rejected
  else actual_static=unexpected-rejection
  fi
  if [[ "${closure_failed}" == true ]]; then
    local closure_baseline_reason="${closure_reason}"
    local closure_outer_reason="${closure_reason}"
    local closure_baseline_actual=not-applicable closure_outer_actual=not-applicable
    [[ "${expected_baseline}" != not-applicable ]] && closure_baseline_actual=environment-unavailable
    [[ "${expected_outer}" != not-applicable ]] && closure_outer_actual=environment-unavailable
    : > "${sample_root}/logs/baseline.stdout"
    : > "${sample_root}/logs/baseline.stderr"
    : > "${sample_root}/logs/outer.stdout"
    : > "${sample_root}/logs/outer.stderr"
    if [[ "${expected_outer}" == not-applicable ]]; then
      write_outer_pack_boundary "${sample_root}" "Outer-wrapper policy is not applicable." false
    else
      write_outer_pack_boundary "${sample_root}" "${closure_outer_reason}" true
    fi
    FIRST_FAILURE_LAYER=environment CLI_SUCCESS="$([[ "${validator_status}" -eq 0 ]] && echo true || echo false)" SOURCE_ARTIFACT_SHA="${artifact_sha}" RUNTIME_ARTIFACT_SHA="${runtime_artifact_sha}" write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable \
      "${actual_static}" "${closure_baseline_actual}" "${closure_outer_actual}" not-applicable "${artifact_sha}" \
      "validation-only; fingerprintStatus=${fingerprint_status}; validatorStatus=${validator_status}" \
      "${closure_baseline_reason}" "${closure_outer_reason}"
    write_execution_evidence "${sample_root}" "${id}" "${artifact_path}" "${baseline_applicable}" "${expected_baseline}" "${baseline_expected_status}" "${invocation_source}" "${command_json}" "" "${closure_baseline_actual}" false "" "${outer_applicable}" "${expected_outer}" "${outer_mode}" "${outer_command_json}" "" "${closure_outer_actual}" false "" "" \
      "preflight-environment-unavailable" "preflight-environment-unavailable" "${closure_baseline_reason}" "${closure_outer_reason}" "${bionic_lock_sha}" "${bionic_timeout_seconds}" "${bionic_output_limit}" "${bionic_memory_bytes}" "${bionic_process_limit}" "${bionic_outer_mode}" "${bionic_path_policy}" "${bionic_runpath}"
    printf 'raw-inputs-removed=true\n' > "${sample_root}/raw-inputs-removed.txt"
    rm -rf -- "${sample_tmp}"
    return 1
  fi
  local baseline_status="" baseline_attempted=false baseline_helper_status="" baseline_target_status="" baseline_protocol=""
  local baseline_preflight_outcome="" baseline_preflight_reason=""
  local actual_baseline=not-applicable reason_baseline='baseline policy is not applicable'
  local actual_outer=not-applicable reason_outer='outer-wrapper policy is not applicable' actual_host=not-applicable
  local outer_status="" outer_target_status="" outer_protocol="" outer_attempted=false outer_helper_status="" outer_pack_status=""
  local outer_preflight_outcome="" outer_preflight_reason=""
  : > "${sample_root}/logs/outer.stdout"
  : > "${sample_root}/logs/outer.stderr"
  write_outer_pack_boundary "${sample_root}" 'Outer-wrapper policy is not applicable.' false
  if [[ "${expected_baseline}" != not-applicable && "${bionic_pending}" == false ]]; then
    run_isolated_baseline "${runtime_root}" "${sample_root}" "${artifact_path}" "${command_json}" || true
    if baseline_protocol="$(read_isolation_result "${sample_root}/logs/baseline.helper.json")"; then
      IFS='|' read -r baseline_attempted baseline_helper_status baseline_target_status <<< "${baseline_protocol}"
    else
      baseline_attempted=false
      baseline_helper_status=125
      baseline_target_status=""
    fi
    baseline_status="${baseline_target_status}"
    if [[ -n "${baseline_target_status}" ]]; then
      printf '%s\n' "${baseline_target_status}" > "${sample_root}/logs/baseline.status"
    else
      rm -f -- "${sample_root}/logs/baseline.status"
    fi
    if [[ -n "${baseline_helper_status}" ]]; then
      printf '%s\n' "${baseline_helper_status}" > "${sample_root}/logs/baseline.helper-status"
    else
      rm -f -- "${sample_root}/logs/baseline.helper-status"
    fi
    actual_baseline="$(classify_isolation_result "${baseline_attempted}" "${baseline_helper_status}" "${baseline_target_status}" "${baseline_expected_status}")"
    if [[ "${baseline_helper_status}" == 125 ]]; then
      reason_baseline='bubblewrap isolation capability is unavailable'
    elif [[ "${baseline_helper_status}" == 124 ]]; then
      reason_baseline='baseline helper exceeded its bounded execution limit'
    elif [[ "${actual_baseline}" == accepted-and-runs ]]; then
      reason_baseline="baseline target status=${baseline_target_status}"
    elif [[ -n "${baseline_target_status}" ]]; then
      reason_baseline="baseline target exited with status=${baseline_target_status}"
    else
      reason_baseline='baseline isolation result protocol was incomplete'
    fi
  fi

  if [[ "${bionic_pending}" == true && "${expected_baseline}" != not-applicable ]]; then
    bionic_cache_root="${package_archive_cache}/bionic-node"
    mkdir -p "${bionic_cache_root}"
    mapfile -t bionic_policy_values < <(python3 - "${repo_root}" "${bionic_lock}" "${manifest}" "${artifact_path}" <<'PY_BIONIC_POLICY'
import base64
import json
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from bionic_node_lock import lock_file_sha256, validate_lock_document
from pathlib import Path
_, lock_path, manifest_path, artifact_path = sys.argv
lock = json.load(open(lock_path, encoding="utf-8"))
manifest = json.load(open(manifest_path, encoding="utf-8"))
errors = validate_lock_document(lock, manifest=manifest)
if errors:
    raise SystemExit("; ".join(errors))
execution = lock["execution"]
if execution["artifactPath"] != "/" + artifact_path.lstrip("/"):
    raise SystemExit("Node.js artifact path differs from bionic runtime lock")
print(base64.urlsafe_b64encode(json.dumps(execution["argv"]).encode()).decode())
print(execution["expectedStatus"])
print(execution["outerMode"])
print(lock_file_sha256(Path(lock_path)))
print(execution["runpath"])
PY_BIONIC_POLICY
    )
    if [[ "${#bionic_policy_values[@]}" -ne 5 ]]; then
      actual_baseline=unexpected-rejection
      actual_outer=unexpected-rejection
      reason_baseline='bionic lock argv/status could not be resolved'
      reason_outer="${reason_baseline}"
      baseline_attempted=false; outer_attempted=false
      baseline_helper_status=""; outer_helper_status=""
      baseline_target_status=""; outer_target_status=""
      baseline_status=""; outer_status=""
      baseline_preflight_outcome=preflight-product-failure
      outer_preflight_outcome=preflight-product-failure
      baseline_preflight_reason="${reason_baseline}"
      outer_preflight_reason="${reason_outer}"
      bionic_runner_status=1
    else
      command_json="${bionic_policy_values[0]}"
      baseline_expected_status="${bionic_policy_values[1]}"
      outer_mode="${bionic_policy_values[2]}"
      bionic_expected_lock_sha="${bionic_policy_values[3]}"
      bionic_expected_runpath="${bionic_policy_values[4]}"
      invocation_source=declared
      outer_command_json="$(python3 - "${command_json}" <<'PY_LOCK_OUTER'
import base64, json, sys
argv=json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode("utf-8"))
argv[0]="/usr/local/bin/urprotect-packed"
print(base64.urlsafe_b64encode(json.dumps(argv).encode()).decode())
PY_LOCK_OUTER
      )"
    fi
    if [[ "${#bionic_policy_values[@]}" -eq 5 ]]; then
    set +e
    "${repo_root}/scripts/run-bionic-node-sample.sh" \
      --input "${artifact}" \
      --source-archive "${archive}" \
      --artifact-root "${sample_root}" \
      --image "${bionic_image}" \
      --version "${version}" \
      --sha256 "${artifact_sha}" \
      --archive-sha256 "${archive_sha}" \
      --launcher "${launcher_path}" \
      --cli-dll "${cli_dll}" \
      --lock "${bionic_lock}" \
      --manifest "${manifest}" \
      --cache-root "${bionic_cache_root}" \
      --outer-mode "${outer_mode}" \
      > "${sample_root}/logs/bionic-runner.log" 2>&1
    bionic_runner_status=$?
    set -e
    bionic_result_valid=false
    if [[ -f "${sample_root}/bionic-node-result.json" && "${#bionic_policy_values[@]}" -eq 5 ]]; then
      if bionic_values_text="$(python3 - "${sample_root}/bionic-node-result.json" "${bionic_expected_lock_sha}" "${bionic_expected_runpath}" "${bionic_runner_status}" "${bionic_image}" "${bionic_image_id}" "${bionic_loader}" "${repo_root}/scripts" <<'PY_BIONIC_RESULT'
import json
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[8])
from real_sample_schema import validate_bionic_node_result
path, expected_lock, expected_runpath, runner_status, expected_image, expected_image_id, expected_loader = sys.argv[1:8]
value = json.loads(Path(path).read_text(encoding="utf-8"))
errors = validate_bionic_node_result(
    value,
    expected_lock_sha256=expected_lock,
    expected_runpath=expected_runpath,
    expected_image=expected_image,
    expected_image_id=expected_image_id,
    expected_loader=expected_loader,
)
if int(runner_status) == 0 and value.get("status") != "passed":
    errors.append("runner exited 0 without a passed host-generated result")
if int(runner_status) == 125 and not any(value.get(layer, {}).get("actual") == "environment-unavailable" for layer in ("baseline", "outer")):
    errors.append("runner exited 125 without an environment-unavailable result")
if int(runner_status) == 124 and not any(value.get(layer, {}).get("protocol", {}).get("outcome") == "helper-timeout" for layer in ("baseline", "outer")):
    errors.append("runner exited 124 without a timeout protocol")
if int(runner_status) == 1 and value.get("status") == "passed":
    errors.append("runner exited nonzero despite a passed result")
if errors:
    raise SystemExit("; ".join(errors))
for layer in ("baseline", "outer"):
    item = value[layer]
    protocol = item["protocol"]
    print(item["actual"])
    print("true" if item.get("attempted") is True else "false")
    print("" if item.get("helperStatus") is None else str(item["helperStatus"]))
    print("" if item.get("targetStatus") is None else str(item["targetStatus"]))
    print(item.get("reason", "bionic helper result is incomplete").replace("\\n", " "))
    print(item.get("preflightOutcome") or "")
    print(item.get("reason", "bionic helper result is incomplete").replace("\\n", " ") if item.get("preflightOutcome") else "")
    print("" if item.get("containerStatus") is None else str(item["containerStatus"]))
print(value.get("runtimeArtifactSha256") or "")
print(value.get("packStatus") if value.get("packStatus") is not None else "")
print(value.get("status", "failed"))
PY_BIONIC_RESULT
      )"; then
        mapfile -t bionic_values <<< "${bionic_values_text}"
        if [[ "${#bionic_values[@]}" -eq 19 ]]; then
          bionic_result_valid=true
          actual_baseline="${bionic_values[0]}"
          baseline_attempted="${bionic_values[1]}"
          baseline_helper_status="${bionic_values[2]}"
          baseline_target_status="${bionic_values[3]}"
          reason_baseline="${bionic_values[4]}"
          baseline_preflight_outcome="${bionic_values[5]}"
          baseline_preflight_reason="${bionic_values[6]}"
          baseline_container_status="${bionic_values[7]}"
          actual_outer="${bionic_values[8]}"
          outer_attempted="${bionic_values[9]}"
          outer_helper_status="${bionic_values[10]}"
          outer_target_status="${bionic_values[11]}"
          reason_outer="${bionic_values[12]}"
          outer_preflight_outcome="${bionic_values[13]}"
          outer_preflight_reason="${bionic_values[14]}"
          outer_container_status="${bionic_values[15]}"
          runtime_artifact_sha="${bionic_values[16]}"
          outer_pack_status="${bionic_values[17]}"
          bionic_result_status="${bionic_values[18]}"
          baseline_status="${baseline_target_status}"
          outer_status="${outer_target_status}"
          if [[ -n "${outer_pack_status}" && -f "${sample_root}/outer-pack.json" ]]; then
            record_pack_cli_status "${sample_root}" "${outer_pack_status}" 'bionic outer pack report is missing or malformed'
          fi
          if [[ -n "${runtime_artifact_sha}" ]]; then
            printf 'runtimeArtifactSha256=%s\n' "${runtime_artifact_sha}" >> "${sample_root}/hashes.txt"
          fi
          if [[ -n "${baseline_preflight_outcome}" ]]; then
            baseline_attempted=false; baseline_helper_status=""; baseline_target_status=""; baseline_status=""
            remove_unreferenced_preflight_markers "${sample_root}" baseline
          fi
          if [[ -n "${outer_preflight_outcome}" ]]; then
            outer_attempted=false; outer_helper_status=""; outer_target_status=""; outer_status=""
            remove_unreferenced_preflight_markers "${sample_root}" outerWrapper "${outer_pack_status}"
            if [[ ! -f "${sample_root}/outer-pack.json" ]]; then
              write_outer_pack_boundary "${sample_root}" "${outer_preflight_reason}" true
            fi
          fi
        else
          bionic_result_valid=false
        fi
      fi
    fi
    if [[ "${bionic_result_valid}" != true ]]; then
      case "${bionic_runner_status}" in
        125)
          actual_baseline=environment-unavailable; actual_outer=environment-unavailable
          bionic_preflight_outcome=preflight-environment-unavailable
          ;;
        124)
          actual_baseline=runtime-failure; actual_outer=runtime-failure
          bionic_preflight_outcome=preflight-runtime-failure
          ;;
        *)
          actual_baseline=unexpected-rejection; actual_outer=unexpected-rejection
          bionic_preflight_outcome=preflight-product-failure
          ;;
      esac
      reason_baseline="bionic runner returned status ${bionic_runner_status} without a valid inspected-result protocol"
      reason_outer="${reason_baseline}"
      baseline_attempted=false; outer_attempted=false
      baseline_helper_status=""; outer_helper_status=""
      baseline_target_status=""; outer_target_status=""
      baseline_status=""; outer_status=""
      baseline_preflight_outcome="${bionic_preflight_outcome}"
      outer_preflight_outcome="${bionic_preflight_outcome}"
      baseline_preflight_reason="${reason_baseline}"
      outer_preflight_reason="${reason_outer}"
      remove_unreferenced_preflight_markers "${sample_root}" baseline
      remove_unreferenced_preflight_markers "${sample_root}" outerWrapper "${outer_pack_status}"
      [[ -f "${sample_root}/logs/baseline.stdout" ]] || : > "${sample_root}/logs/baseline.stdout"
      [[ -f "${sample_root}/logs/baseline.stderr" ]] || : > "${sample_root}/logs/baseline.stderr"
      [[ -f "${sample_root}/logs/outer.stdout" ]] || : > "${sample_root}/logs/outer.stdout"
      [[ -f "${sample_root}/logs/outer.stderr" ]] || : > "${sample_root}/logs/outer.stderr"
      if ! python3 - "${sample_root}/outer-pack.json" <<'PY_BIONIC_PACK_PRESENT'
import json
import sys
from pathlib import Path
try:
    value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(value, dict) or not isinstance(value.get("success"), bool):
    raise SystemExit(1)
PY_BIONIC_PACK_PRESENT
      then
        write_outer_pack_boundary "${sample_root}" "${reason_outer}" true
      fi
    fi
    fi
    if [[ ! -f "${sample_root}/runtime-closure.json" ]]; then
      write_runtime_closure_record "${sample_root}" "${id}" "${runtime}" "${loader}" environment-unavailable "${artifact_sha}" "${runtime_artifact_sha}" "${reason_baseline}"
    fi
  fi

  local path_sensitive=false
  path_sensitive="$(python3 - "${sample_root}/elf-fingerprint.json" <<'PYPATH'
import json, sys
try:
    value = json.load(open(sys.argv[1]))
    dependencies = value.get("dependencies", {}) if isinstance(value, dict) else {}
    path_sensitive = isinstance(dependencies, dict) and bool(dependencies.get("rpath") or dependencies.get("runpath"))
    print("true" if path_sensitive else "false")
except (OSError, UnicodeError, json.JSONDecodeError):
    print("false")
PYPATH
)"
  local wrapper="${sample_tmp}/outer-wrapper"
  if [[ "${expected_outer}" != not-applicable && "${runtime}" != bionic && "${actual_baseline}" == accepted-and-runs ]]; then
    if [[ "${outer_mode}" != outer-execveat ]]; then
      actual_outer=environment-unavailable
      reason_outer='outer path-preserving mode is not implemented by this evidence runner'
      outer_status=""
      outer_attempted=false
      outer_helper_status=""
      outer_preflight_outcome=preflight-environment-unavailable
      outer_preflight_reason="${reason_outer}"
      write_outer_pack_boundary "${sample_root}" "${reason_outer}" true
    elif [[ "${path_sensitive}" == true ]]; then
      actual_outer=environment-unavailable
      reason_outer='path-sensitive ELF metadata requires the unimplemented outer-path-preserving profile'
      outer_status=""
      outer_attempted=false
      outer_helper_status=""
      outer_preflight_outcome=preflight-environment-unavailable
      outer_preflight_reason="${reason_outer}"
      write_outer_pack_boundary "${sample_root}" "${reason_outer}" true
    elif "${dotnet_cli[@]}" pack "${artifact}" --output "${wrapper}" --launcher "${launcher_path}" \
        --profile outer-execveat --json "${sample_root}/outer-pack.json" \
        > "${sample_root}/logs/outer-pack.log" 2>&1; then
      mkdir -p "${runtime_root}/usr/local/bin"
      cp --preserve=mode "${wrapper}" "${runtime_root}/usr/local/bin/urprotect-packed"
      local outer_command
      outer_command="$(python3 - "${command_json}" <<'PYOUTER'
import base64, json, sys
values=json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode())
values[0]='/usr/local/bin/urprotect-packed'
print(base64.urlsafe_b64encode(json.dumps(values).encode()).decode())
PYOUTER
      )"
      outer_command_json="${outer_command}"
      outer_pack_status=0
      record_pack_cli_status "${sample_root}" 0 'profile-matched outer pack report is missing or malformed'
      printf '%s\n' 0 > "${sample_root}/logs/outer-pack.status"
      run_isolated_command "${runtime_root}" "${sample_root}" outer "${outer_command}" "/${artifact_path#/}" || true
      if outer_protocol="$(read_isolation_result "${sample_root}/logs/outer.helper.json")"; then
        IFS='|' read -r outer_attempted outer_helper_status outer_target_status <<< "${outer_protocol}"
      else
        outer_attempted=false
        outer_helper_status=125
        outer_target_status=""
      fi
      outer_status="${outer_target_status}"
      if [[ -n "${outer_target_status}" ]]; then
        printf '%s\n' "${outer_target_status}" > "${sample_root}/logs/outer.status"
      else
        rm -f -- "${sample_root}/logs/outer.status"
      fi
      if [[ -n "${outer_helper_status}" ]]; then
        printf '%s\n' "${outer_helper_status}" > "${sample_root}/logs/outer.helper-status"
      else
        rm -f -- "${sample_root}/logs/outer.helper-status"
      fi
      actual_outer="$(classify_isolation_result "${outer_attempted}" "${outer_helper_status}" "${outer_target_status}" "${baseline_expected_status}")"
      if [[ "${outer_helper_status}" == 125 ]]; then
        reason_outer='bubblewrap isolation capability is unavailable'
      elif [[ "${outer_helper_status}" == 124 ]]; then
        reason_outer='outer helper exceeded its bounded execution limit'
      elif [[ "${actual_outer}" == accepted-and-runs && "${outer_target_status}" == "${baseline_target_status}" ]]; then
        reason_outer="outer target status=${outer_target_status}"
      elif [[ -n "${outer_target_status}" ]]; then
        reason_outer="outer target exited with status=${outer_target_status}"
      else
        actual_outer=runtime-failure
        reason_outer='outer isolation result protocol was incomplete'
      fi
      if [[ "${actual_outer}" == accepted-and-runs ]] \
          && { ! cmp -- "${sample_root}/logs/baseline.stdout" "${sample_root}/logs/outer.stdout" \
            || ! cmp -- "${sample_root}/logs/baseline.stderr" "${sample_root}/logs/outer.stderr" \
            || [[ "${outer_target_status}" != "${baseline_target_status}" ]]; }; then
        actual_outer=runtime-failure
        reason_outer='outer behavior differs from the original baseline'
      fi
    else
      local pack_status=$?
      if [[ "${expected_outer}" == expected-rejected ]]; then
        actual_outer=expected-rejected
      else
        actual_outer=unexpected-rejection
      fi
      reason_outer='profile-matched outer pack rejected the runtime artifact'
      outer_preflight_outcome=preflight-product-failure
      outer_preflight_reason="${reason_outer}"
      outer_pack_status="${pack_status}"
      printf '%s\n' "${pack_status}" > "${sample_root}/logs/outer-pack.status"
      record_pack_cli_status "${sample_root}" "${pack_status}" "${reason_outer}"
    fi
  elif [[ "${expected_outer}" != not-applicable && "${runtime}" != bionic ]]; then
    actual_outer=runtime-failure
    reason_outer='baseline did not reach the outer-wrapper oracle'
    outer_status=""
    outer_attempted=false
    outer_helper_status=""
    outer_preflight_outcome=preflight-product-failure
    outer_preflight_reason="${reason_outer}"
    write_outer_pack_boundary "${sample_root}" "${reason_outer}" true
  fi
  write_execution_evidence "${sample_root}" "${id}" "${artifact_path}" "${baseline_applicable}" "${expected_baseline}" "${baseline_expected_status}" "${invocation_source}" "${command_json}" "${baseline_status}" "${actual_baseline}" "${baseline_attempted}" "${baseline_helper_status}" "${outer_applicable}" "${expected_outer}" "${outer_mode}" "${outer_command_json}" "${outer_status}" "${actual_outer}" "${outer_attempted}" "${outer_helper_status}" "${outer_pack_status}" \
    "${baseline_preflight_outcome}" "${outer_preflight_outcome}" "${baseline_preflight_reason}" "${outer_preflight_reason}" "${bionic_lock_sha}" "${bionic_timeout_seconds}" "${bionic_output_limit}" "${bionic_memory_bytes}" "${bionic_process_limit}" "${bionic_outer_mode}" "${bionic_path_policy}" "${bionic_runpath}"
  local first_failure=""
  if [[ "${fingerprint_status}" -ne 0 ]]; then
    first_failure=fingerprint
  elif [[ "${actual_static}" != "${expected_static}" ]]; then
    first_failure="static-validation"
  elif [[ "${actual_baseline}" != "${expected_baseline}" ]]; then
    first_failure=environment
  elif [[ "${actual_outer}" != "${expected_outer}" ]]; then
    first_failure=outer
  fi
  FIRST_FAILURE_LAYER="${first_failure}" CLI_SUCCESS="$([[ "${validator_status}" -eq 0 ]] && echo true || echo false)" SOURCE_ARTIFACT_SHA="${artifact_sha}" RUNTIME_ARTIFACT_SHA="${runtime_artifact_sha}" write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable \
    "${actual_static}" "${actual_baseline}" "${actual_outer}" "${actual_host}" "${artifact_sha}" \
    "validation-only; fingerprintStatus=${fingerprint_status}; validatorStatus=${validator_status}" "${reason_baseline}" "${reason_outer}"
  printf 'raw-inputs-removed=true\n' > "${sample_root}/raw-inputs-removed.txt"
  rm -rf -- "${sample_tmp}"
  local result_status=0
  [[ "${actual_static}" == "${expected_static}" ]] || result_status=1
  [[ "${actual_baseline}" == "${expected_baseline}" ]] || result_status=1
  [[ "${actual_outer}" == "${expected_outer}" ]] || result_status=1
  return "${result_status}"
}

# Export the worker function graph into a fresh bash session.  The dotnet CLI
# command is reconstructed in that session because bash does not export arrays.
export repo_root manifest candidates runtime_closures artifact_root requested_tier \
  runner_temp package_cache_root package_archive_cache package_index_cache temp_root \
  isolation_lock isolation_dropper_dir isolation_dropper parallelism manifest_sha \
  max_archive_bytes cli_dll bionic_lock bionic_image bionic_lock_sha \
  bionic_timeout_seconds bionic_output_limit bionic_memory_bytes bionic_process_limit \
  bionic_outer_mode bionic_path_policy bionic_runpath bionic_image bionic_image_id bionic_loader
export -f project_fields write_result write_runtime_closure_record \
  record_pack_cli_status write_outer_pack_boundary remove_unreferenced_preflight_markers write_execution_evidence \
  write_failure_evidence classify_isolation_result read_isolation_result \
  run_isolated_command run_isolated_baseline prepare_runtime_root resolve_artifact \
  process_project

project_batch=()
worker_registry_index=0
while IFS= read -r project_json; do
  [[ -z "${project_json}" ]] && continue
  worker_registry_index=$((worker_registry_index + 1))
  pid_registry="${worker_registry_dir}/worker-${worker_registry_index}.pids"
  container_registry="${worker_registry_dir}/worker-${worker_registry_index}.containers"
  : > "${pid_registry}"
  : > "${container_registry}"
  chmod 600 "${pid_registry}" "${container_registry}"
  URP_WORKER_CONTAINER_REGISTRY="${container_registry}" setsid --wait \
    python3 "${repo_root}/scripts/real_sample_worker_supervisor.py" \
      --pid-registry "${pid_registry}" --container-registry "${container_registry}" -- \
      bash -c 'set -euo pipefail; dotnet_cli=(dotnet "${cli_dll}"); process_project "$1"' \
      _ "${project_json}" &
  project_pid="$!"
  self_pgid="$(urp_worker_pgid "$$" || true)"
  project_pgid=""
  for _ in {1..20}; do
    candidate_pgid="$(urp_worker_pgid "${project_pid}" || true)"
    if [[ "${candidate_pgid}" =~ ^[0-9]+$ && "${candidate_pgid}" != "${self_pgid}" ]]; then
      project_pgid="${candidate_pgid}"
      break
    fi
    sleep 0.01
  done
  project_batch+=("${project_pid}")
  active_pids+=("${project_pid}")
  active_pgids+=("${project_pgid}")
  active_pid_registries+=("${pid_registry}")
  active_container_registries+=("${container_registry}")
  if [[ "${#project_batch[@]}" -ge "${parallelism}" ]]; then
    for index in "${!project_batch[@]}"; do
      pid="${project_batch[${index}]}"
      if wait "${pid}"; then :; else overall_status=1; fi
      if ! urp_stop_worker_group "${pid}" "${active_pgids[${index}]}" 1 \
        "${active_pid_registries[${index}]}" "${active_container_registries[${index}]}"; then
        printf 'worker descendants or named containers remain after project %s\n' "${pid}" >&2
        exit 1
      fi
    done
    project_batch=()
    active_pids=()
    active_pgids=()
    active_pid_registries=()
    active_container_registries=()
  fi
done < <(python3 "${repo_root}/scripts/validate-real-samples.py" "${manifest}" --candidates "${candidates}" --tier "${requested_tier}" --emit | tail -n +2)
for index in "${!project_batch[@]}"; do
  pid="${project_batch[${index}]}"
  if wait "${pid}"; then :; else overall_status=1; fi
  if ! urp_stop_worker_group "${pid}" "${active_pgids[${index}]}" 1 \
    "${active_pid_registries[${index}]}" "${active_container_registries[${index}]}"; then
    printf 'worker descendants or named containers remain after project %s\n' "${pid}" >&2
    exit 1
  fi
done
active_pids=()
active_pgids=()
active_pid_registries=()
active_container_registries=()

if ! sanitize_evidence; then
  overall_status=1
fi
python3 "${repo_root}/scripts/render-real-sample-report.py" "${manifest}" --tier "${requested_tier}" \
  --runtime-closures "${runtime_closures}" --artifact-root "${artifact_root}" --output-json "${artifact_root}/aggregate.json" \
  --output-markdown "${artifact_root}/aggregate.md" --require-evidence || overall_status=1
python3 "${repo_root}/scripts/check-real-sample-evidence.py" "${manifest}" --candidates "${candidates}" \
  --runtime-closures "${runtime_closures}" \
  --tier "${requested_tier}" --artifact-root "${artifact_root}" || overall_status=1
printf 'real-sample tier %s completed with status %s; raw inputs were under %s and removed on exit\n' "${requested_tier}" "${overall_status}" "${temp_root}"
exit "${overall_status}"
