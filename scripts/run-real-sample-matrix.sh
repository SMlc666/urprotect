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
manifest="${repo_root}/fixtures/real-samples/manifest.json"
candidates="${repo_root}/fixtures/real-samples/candidates.json"
runtime_closures="${repo_root}/fixtures/real-samples/runtime-closures.json"
artifact_root="${REAL_SAMPLE_ARTIFACT_ROOT:-${repo_root}/.artifacts/real-samples/${requested_tier}}"
mkdir -p "${artifact_root}"
artifact_root="$(cd "${artifact_root}" && pwd)"

for command in curl sha256sum python3 readelf timeout dotnet; do
  command -v "${command}" >/dev/null 2>&1 || { echo "${command} is required" >&2; exit 127; }
done

python3 "${repo_root}/scripts/validate-real-samples.py" "${manifest}" \
  --candidates "${candidates}" --tier "${requested_tier}" >/dev/null
python3 "${repo_root}/scripts/validate-runtime-closures.py" \
  "${runtime_closures}" "${manifest}" >/dev/null

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
temp_root="$(mktemp -d "${runner_temp%/}/urprotect-real-samples-${requested_tier}.XXXXXX")"
chmod 700 "${temp_root}"
sanitize_evidence() {
  [[ -d "${artifact_root}" ]] || return 0
  python3 - "${artifact_root}" "${temp_root}" <<'PYSANITIZE'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = sys.argv[2].encode("utf-8")
replacement = b"<runner-temp>"
for path in root.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    try:
        data = path.read_bytes()
    except OSError:
        continue
    if b"\0" in data[:4096] or temporary not in data:
        continue
    path.write_bytes(data.replace(temporary, replacement))
PYSANITIZE
}
cleanup() {
  sanitize_evidence || true
  rm -rf -- "${temp_root}"
}
trap cleanup EXIT HUP INT TERM

manifest_sha="$(sha256sum "${manifest}" | awk '{print $1}')"
overall_status=0
max_archive_bytes="$(PYTHONPATH="${repo_root}/scripts${PYTHONPATH:+:${PYTHONPATH}}" \
  python3 -c 'from real_sample_schema import MAX_REAL_SAMPLE_ARCHIVE_BYTES; print(MAX_REAL_SAMPLE_ARCHIVE_BYTES)')"

dotnet_cli=(dotnet run --project "${repo_root}/src/UrProtect.Cli" --configuration Release --no-restore --)

project_fields() {
  python3 - "$1" <<'PY'
import base64, json, sys
p=json.loads(sys.argv[1]); prov=p['provenance']; target=p['target']; policy=p['executionPolicy']
apk_metadata={
 'package': prov.get('packageName',''),
 'version': prov.get('version',''),
 'architecture': target.get('architecture',''),
 'origin': prov.get('origin',''),
 'license': prov.get('license',''),
}
values=[
 p['projectId'], prov['archiveUrl'], prov['version'], prov['archivePath'], prov['archiveSha256'],
 prov['archiveFormat'], prov['artifactPath'], p['featureFingerprint']['producer'],
 policy['static']['expectedResult'], str(policy['baseline']['applicable']).lower(),
 policy['baseline']['expectedResult'], policy['baseline'].get('mode','-'), base64.urlsafe_b64encode(json.dumps(policy['baseline'].get('command', [])).encode()).decode(), target['runtime'], target['loader'],
 base64.urlsafe_b64encode(json.dumps(apk_metadata).encode()).decode(),
 prov.get('sourceKind',''),
]
print('\t'.join(values))
PY
}

write_result() {
  local sample_root="$1" id="$2" expected_static="$3" expected_baseline="$4" expected_outer="$5" expected_host="$6"
  local actual_static="$7" actual_baseline="$8" actual_outer="$9" actual_host="${10}" artifact_sha="${11}" reason_static="${12}" reason_baseline="${13}" reason_outer="${14}"
  SAMPLE_ROOT="${sample_root}" SAMPLE_ID="${id}" SAMPLE_TIER="${requested_tier}" \
  REPO_ROOT="${repo_root}" \
  EXPECTED_STATIC="${expected_static}" EXPECTED_BASELINE="${expected_baseline}" EXPECTED_OUTER="${expected_outer}" EXPECTED_HOST="${expected_host}" \
  ACTUAL_STATIC="${actual_static}" ACTUAL_BASELINE="${actual_baseline}" ACTUAL_OUTER="${actual_outer}" ACTUAL_HOST="${actual_host}" \
  ARTIFACT_SHA="${artifact_sha}" REASON_STATIC="${reason_static}" REASON_BASELINE="${reason_baseline}" REASON_OUTER="${reason_outer}" \
  FIRST_FAILURE_LAYER="${FIRST_FAILURE_LAYER:-}" \
  python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ['REPO_ROOT'], 'scripts'))
from real_sample_schema import first_failure_layer

root=os.environ['SAMPLE_ROOT']
expected={'static':os.environ['EXPECTED_STATIC'],'baseline':os.environ['EXPECTED_BASELINE'],'outerWrapper':os.environ['EXPECTED_OUTER'],'hostContext':os.environ['EXPECTED_HOST']}
actual={'static':os.environ['ACTUAL_STATIC'],'baseline':os.environ['ACTUAL_BASELINE'],'outerWrapper':os.environ['ACTUAL_OUTER'],'hostContext':os.environ['ACTUAL_HOST']}
reasons={'static':os.environ.get('REASON_STATIC',''),'baseline':os.environ.get('REASON_BASELINE',''),'outerWrapper':os.environ.get('REASON_OUTER',''),'hostContext':'Ordinary public executable has no HostContext entry contract.'}
result={'schemaVersion':2,'tier':os.environ['SAMPLE_TIER'],'projectId':os.environ['SAMPLE_ID'],'artifactSha256':os.environ.get('ARTIFACT_SHA',''),'layers':{}}
for layer in ('static','baseline','outerWrapper','hostContext'):
 result['layers'][layer]={'expected':expected[layer],'actual':actual[layer],'status':'passed' if expected[layer]==actual[layer] else 'failed','reason':reasons[layer]}
explicit=os.environ.get('FIRST_FAILURE_LAYER','')
result['firstFailureLayer']=first_failure_layer(result['layers'], explicit or None)
json.dump(result,open(os.path.join(root,'result.json'),'w'),indent=2,sort_keys=True); open(os.path.join(root,'result.json'),'a').write('\n')
PY
}

write_failure_evidence() {
  local sample_root="$1" id="$2" expected_static="$3" expected_baseline="$4"
  local expected_outer="$5" expected_host="$6" reason="$7" first_failure="${8:-acquisition}"
  printf 'evidence unavailable: %s\n' "${reason}" > "${sample_root}/readelf.txt"
  printf '{"schemaVersion":2,"projectId":"%s","error":%s,"unknownFields":["all"]}\n' "${id}" "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${reason}")" > "${sample_root}/elf-fingerprint.json"
  printf '{"schemaVersion":2,"projectId":"%s","status":"not-applicable","reason":%s}\n' "${id}" "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${reason}")" > "${sample_root}/fingerprint-comparison.json"
  printf '{"schemaVersion":2,"status":"environment-unavailable","reason":%s,"unknownFields":["all"]}\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${reason}")" > "${sample_root}/urprotect-report.json"
  printf 'failure=%s\n' "${reason}" > "${sample_root}/hashes.txt"
  FIRST_FAILURE_LAYER="${first_failure}" write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" "${expected_host}" \
    environment-unavailable environment-unavailable environment-unavailable environment-unavailable '' "${reason}" "${reason}" "${reason}"
  rm -rf -- "${temp_root}/${id}"
  printf 'raw-inputs-removed=true\n' > "${sample_root}/raw-inputs-removed.txt"
}

run_isolated_command() {
  local extract_root="$1" sample_root="$2" label="$3" command_b64="$4"
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
  python3 "${repo_root}/scripts/run-isolated-real-sample.py" \
    --rootfs "${extract_root}" --stdout "${sample_root}/logs/${label}.stdout" \
    --stderr "${sample_root}/logs/${label}.stderr" --timeout 30 --memory-bytes 536870912 \
    --process-limit 32 --output-limit 1048576 -- "${command_parts[@]}"
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
  run_isolated_command "${extract_root}" "${sample_root}" baseline "${command_b64}"
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
  local id archive_url version archive_path archive_sha archive_format artifact_path producer expected_static baseline_applicable expected_baseline baseline_mode baseline_command_b64 runtime loader apk_metadata_b64 source_kind
  IFS=$'\t' read -r id archive_url version archive_path archive_sha archive_format artifact_path producer expected_static baseline_applicable expected_baseline baseline_mode baseline_command_b64 runtime loader apk_metadata_b64 source_kind < <(project_fields "${json_record}")
  expected_baseline=accepted-and-runs
  local expected_outer=accepted-and-runs
  local sample_root="${artifact_root}/${id}" sample_tmp archive extract_root
  sample_tmp="${temp_root}/${id}"
  archive="${sample_tmp}/source.archive"
  extract_root="${sample_tmp}/extract"
  rm -rf -- "${sample_root}" "${sample_tmp}"; mkdir -p "${sample_root}/logs" "${sample_tmp}"
  {
    printf 'projectId=%s\nversion=%s\narchiveUrl=%s\narchivePath=%s\narchiveSha256=%s\nartifactPath=%s\narchiveFormat=%s\n' \
      "${id}" "${version}" "${archive_url}" "${archive_path}" "${archive_sha}" "${artifact_path}" "${archive_format}"
    printf 'manifestSha256=%s\ntier=%s\nrawArtifactsUploaded=false\n' "${manifest_sha}" "${requested_tier}"
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
  printf 'artifactSha256=%s\n' "${artifact_sha}" >> "${sample_root}/hashes.txt"
  local inspect_status=0
  if python3 "${repo_root}/scripts/inspect-real-sample.py" --input "${artifact}" --output "${sample_root}/elf-fingerprint.json" \
      --readelf-output "${sample_root}/readelf.txt" --project-id "${id}" --producer "${producer}" --runtime "${runtime}" > "${sample_root}/logs/inspect.log" 2>&1; then :; else inspect_status=$?; fi
  if [[ "${inspect_status}" -ne 0 ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable "ELF fingerprint inspection failed" fingerprint
    return 1
  fi
  printf '%s\n' "${json_record}" > "${sample_tmp}/project.json"
  local runtime_root="${sample_tmp}/runtime-root"
  local closure_failed=false closure_reason=''
  if [[ "${source_kind}" == "alpine-minirootfs" ]]; then
    runtime_root="${extract_root}"
    printf 'resolver=provenance-archive\n' > "${sample_root}/runtime-closure.txt"
  elif [[ "${runtime}" == "glibc" || "${runtime}" == "musl" ]]; then
    if python3 "${repo_root}/scripts/build-runtime-closure.py" \
        --runtime "${runtime}" --runtime-closures "${runtime_closures}" \
        --project "${sample_tmp}/project.json" --rootfs "${runtime_root}" \
        --work-root "${sample_tmp}/closure-work" --index-dir "${temp_root}/indexes" \
        --lock-output "${sample_root}/runtime-closure.json" \
        > "${sample_root}/logs/closure.log" 2>&1; then
      :
    else
      closure_failed=true
      closure_reason='runtime dependency closure failed'
    fi
    printf 'resolver=%s\n' "${runtime}" > "${sample_root}/runtime-closure.txt"
  else
    printf 'resolver=termux-container\n' > "${sample_root}/runtime-closure.txt"
  fi
  if [[ "${closure_failed}" == false && "${runtime}" != bionic ]] \
      && ! resolve_artifact "${runtime_root}" "${artifact_path}" > "${sample_tmp}/runtime-artifact"; then
    closure_failed=true
    closure_reason='runtime closure does not contain the declared artifact'
  fi
  local command_json
  if [[ "${baseline_mode}" == "bubblewrap-rootfs" && -n "${baseline_command_b64}" ]]; then
    command_json="${baseline_command_b64}"
  else
    command_json="$(python3 - "${artifact_path}" <<'PYCOMMAND'
import base64, json, sys
print(base64.urlsafe_b64encode(json.dumps(["/" + sys.argv[1].lstrip("/"), "--version"]).encode()).decode())
PYCOMMAND
    )"
  fi
  local fingerprint_status=0
  if python3 "${repo_root}/scripts/compare-real-sample-fingerprint.py" --manifest "${manifest}" --project-id "${id}" \
      --fingerprint "${sample_root}/elf-fingerprint.json" --output "${sample_root}/fingerprint-comparison.json" > "${sample_root}/logs/fingerprint-compare.log" 2>&1; then :; else fingerprint_status=$?; fi
  local validator_status=0
  if "${dotnet_cli[@]}" validate "${artifact}" --no-analysis --json "${sample_root}/urprotect-report.json" > "${sample_root}/logs/urprotect.log" 2>&1; then :; else validator_status=$?; fi
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
    FIRST_FAILURE_LAYER=environment write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable \
      "${actual_static}" environment-unavailable environment-unavailable not-applicable "${artifact_sha}" \
      "validation-only; fingerprintStatus=${fingerprint_status}; validatorStatus=${validator_status}" \
      "${closure_baseline_reason}" "${closure_outer_reason}"
    printf 'raw-inputs-removed=true\n' > "${sample_root}/raw-inputs-removed.txt"
    rm -rf -- "${sample_tmp}"
    return 1
  fi
  local run_status=0
  local actual_baseline=accepted-and-runs reason_baseline="baseline status=0"
  local actual_outer=accepted-and-runs reason_outer='outer behavior matched baseline' actual_host=not-applicable
  local wrapper_status=0
  if [[ "${runtime}" == bionic ]]; then
    local bionic_root="${sample_root}/bionic-evidence"
    local bionic_input="${sample_root}/bionic-input"
    cp --preserve=mode "${artifact}" "${bionic_input}"
    chmod 0755 "${bionic_input}"
    local bionic_image
    bionic_image="$(python3 - "${repo_root}/fixtures/manifest.json" <<'PYBIONIC'
import json, sys
manifest=json.load(open(sys.argv[1]))
case=next(item for item in manifest['cases'] if item.get('id') == 'c-termux-bionic-pie')
print(case['host']['image'])
PYBIONIC
    )"
    if ! "${repo_root}/scripts/run-bionic-node-sample.sh" \
        --input "${bionic_input}" --artifact-root "${bionic_root}" --image "${bionic_image}" \
        --version "${version}" --sha256 "${artifact_sha}" --archive-sha256 "${archive_sha}" \
        --launcher "${launcher_path}" \
        > "${sample_root}/logs/bionic-node.log" 2>&1; then
      actual_baseline=runtime-failure
      actual_outer=runtime-failure
        reason_baseline='locked bionic Node.js baseline failed'
      reason_outer='locked bionic Node.js outer wrapper failed'
    else
      cp "${bionic_root}/node-baseline.stdout" "${sample_root}/logs/baseline.stdout"
      cp "${bionic_root}/node-baseline.stderr" "${sample_root}/logs/baseline.stderr"
      cp "${bionic_root}/node-outer.stdout" "${sample_root}/logs/outer.stdout"
      cp "${bionic_root}/node-outer.stderr" "${sample_root}/logs/outer.stderr"
      cp "${bionic_root}/node-pack.json" "${sample_root}/outer-pack.json"
      printf '0\n' > "${sample_root}/logs/baseline.status"
      cp "${bionic_root}/node-outer.status" "${sample_root}/logs/outer.status"
    fi
    rm -f -- "${bionic_input}"
  else
    if run_isolated_command "${runtime_root}" "${sample_root}" baseline "${command_json}"; then :; else run_status=$?; fi
    actual_baseline=accepted-and-runs
    reason_baseline="baseline status=${run_status}"
    if [[ "${run_status}" -eq 125 ]]; then
      actual_baseline=environment-unavailable
      reason_baseline='bubblewrap isolation capability is unavailable'
    elif [[ "${run_status}" -eq 124 ]]; then
      actual_baseline=runtime-failure
      reason_baseline='baseline exceeded its bounded execution limit'
    fi
  fi

  local wrapper="${sample_tmp}/outer-wrapper"
  if [[ "${runtime}" != bionic && "${actual_baseline}" == accepted-and-runs ]]; then
    if "${dotnet_cli[@]}" pack "${artifact}" --output "${wrapper}" --launcher "${launcher_path}" \
        --profile outer-execveat --path-preserving --json "${sample_root}/outer-pack.json" \
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
      if run_isolated_command "${runtime_root}" "${sample_root}" outer "${outer_command}"; then :; else wrapper_status=$?; fi
      if [[ "${wrapper_status}" -eq 125 ]]; then actual_outer=environment-unavailable; reason_outer='bubblewrap isolation capability is unavailable'
      elif [[ "${wrapper_status}" -eq 124 ]]; then actual_outer=runtime-failure; reason_outer='outer wrapper exceeded its bounded execution limit'
      else actual_outer=accepted-and-runs; reason_outer="outer status=${wrapper_status}"; fi
      if [[ "${actual_outer}" == accepted-and-runs ]] \
          && { ! cmp -- "${sample_root}/logs/baseline.stdout" "${sample_root}/logs/outer.stdout" \
            || ! cmp -- "${sample_root}/logs/baseline.stderr" "${sample_root}/logs/outer.stderr" \
            || [[ "${wrapper_status}" -ne "${run_status}" ]]; }; then
        actual_outer=runtime-failure
        reason_outer='outer behavior differs from the original baseline'
      fi
    else
      actual_outer=unexpected-rejection
      reason_outer='profile-matched outer pack rejected the runtime artifact'
    fi
  elif [[ "${runtime}" != bionic ]]; then
    actual_outer=environment-unavailable
    reason_outer='baseline did not reach the outer-wrapper oracle'
  fi
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
  FIRST_FAILURE_LAYER="${first_failure}" write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" not-applicable \
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

while IFS= read -r project_json; do
  [[ -z "${project_json}" ]] && continue
  if process_project "${project_json}"; then :; else overall_status=1; fi
done < <(python3 "${repo_root}/scripts/validate-real-samples.py" "${manifest}" --candidates "${candidates}" --tier "${requested_tier}" --emit | tail -n +2)

sanitize_evidence
python3 "${repo_root}/scripts/render-real-sample-report.py" "${manifest}" --tier "${requested_tier}" \
  --runtime-closures "${runtime_closures}" --artifact-root "${artifact_root}" --output-json "${artifact_root}/aggregate.json" \
  --output-markdown "${artifact_root}/aggregate.md" --require-evidence || overall_status=1
python3 "${repo_root}/scripts/check-real-sample-evidence.py" "${manifest}" --candidates "${candidates}" \
  --runtime-closures "${runtime_closures}" \
  --tier "${requested_tier}" --artifact-root "${artifact_root}" || overall_status=1
printf 'real-sample tier %s completed with status %s; raw inputs were under %s and removed on exit\n' "${requested_tier}" "${overall_status}" "${temp_root}"
exit "${overall_status}"
