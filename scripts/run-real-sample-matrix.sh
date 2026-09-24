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
artifact_root="${REAL_SAMPLE_ARTIFACT_ROOT:-${repo_root}/.artifacts/real-samples/${requested_tier}}"
mkdir -p "${artifact_root}"
artifact_root="$(cd "${artifact_root}" && pwd)"

for command in curl sha256sum python3 readelf timeout dotnet; do
  command -v "${command}" >/dev/null 2>&1 || { echo "${command} is required" >&2; exit 127; }
done

python3 "${repo_root}/scripts/validate-real-samples.py" "${manifest}" \
  --candidates "${candidates}" --tier "${requested_tier}" >/dev/null

runner_temp="${RUNNER_TEMP:-}"
if [[ -z "${runner_temp}" || "${runner_temp}" != /* ]]; then
  echo 'RUNNER_TEMP must be an absolute CI temporary directory' >&2
  exit 2
fi
mkdir -p "${runner_temp}"
temp_root="$(mktemp -d "${runner_temp%/}/urprotect-real-samples-${requested_tier}.XXXXXX")"
chmod 700 "${temp_root}"
cleanup() { rm -rf -- "${temp_root}"; }
trap cleanup EXIT HUP INT TERM

manifest_sha="$(sha256sum "${manifest}" | awk '{print $1}')"
overall_status=0

dotnet_cli=(dotnet run --project "${repo_root}/src/UrProtect.Cli" --configuration Release --no-restore --)

project_fields() {
  python3 - "$1" <<'PY'
import base64, json, sys
p=json.loads(sys.argv[1]); prov=p['provenance']; target=p['target']; policy=p['executionPolicy']
values=[
 p['projectId'], prov['archiveUrl'], prov['version'], prov['archivePath'], prov['archiveSha256'],
 prov['archiveFormat'], prov['artifactPath'], p['featureFingerprint']['producer'],
 policy['static']['expectedResult'], str(policy['baseline']['applicable']).lower(),
 policy['baseline']['expectedResult'], policy['baseline'].get('mode',''), base64.urlsafe_b64encode(json.dumps(policy['baseline'].get('command', [])).encode()).decode(), target['runtime'], target['loader'],
]
print('\t'.join(values))
PY
}

write_result() {
  local sample_root="$1" id="$2" expected_static="$3" expected_baseline="$4" expected_outer="$5" expected_host="$6"
  local actual_static="$7" actual_baseline="$8" actual_outer="$9" actual_host="${10}" artifact_sha="${11}" reason_static="${12}" reason_baseline="${13}"
  SAMPLE_ROOT="${sample_root}" SAMPLE_ID="${id}" SAMPLE_TIER="${requested_tier}" \
  EXPECTED_STATIC="${expected_static}" EXPECTED_BASELINE="${expected_baseline}" EXPECTED_OUTER="${expected_outer}" EXPECTED_HOST="${expected_host}" \
  ACTUAL_STATIC="${actual_static}" ACTUAL_BASELINE="${actual_baseline}" ACTUAL_OUTER="${actual_outer}" ACTUAL_HOST="${actual_host}" \
  ARTIFACT_SHA="${artifact_sha}" REASON_STATIC="${reason_static}" REASON_BASELINE="${reason_baseline}" \
  python3 - <<'PY'
import json, os
root=os.environ['SAMPLE_ROOT']
expected={'static':os.environ['EXPECTED_STATIC'],'baseline':os.environ['EXPECTED_BASELINE'],'outerWrapper':os.environ['EXPECTED_OUTER'],'hostContext':os.environ['EXPECTED_HOST']}
actual={'static':os.environ['ACTUAL_STATIC'],'baseline':os.environ['ACTUAL_BASELINE'],'outerWrapper':os.environ['ACTUAL_OUTER'],'hostContext':os.environ['ACTUAL_HOST']}
reasons={'static':os.environ.get('REASON_STATIC',''),'baseline':os.environ.get('REASON_BASELINE',''),'outerWrapper':'Policy did not apply an outer-wrapper oracle.','hostContext':'Policy did not apply a HostContext oracle.'}
result={'schemaVersion':1,'tier':os.environ['SAMPLE_TIER'],'projectId':os.environ['SAMPLE_ID'],'artifactSha256':os.environ.get('ARTIFACT_SHA',''),'layers':{}}
for layer in ('static','baseline','outerWrapper','hostContext'):
 result['layers'][layer]={'expected':expected[layer],'actual':actual[layer],'status':'passed' if expected[layer]==actual[layer] else 'failed','reason':reasons[layer]}
json.dump(result,open(os.path.join(root,'result.json'),'w'),indent=2,sort_keys=True); open(os.path.join(root,'result.json'),'a').write('\n')
PY
}

write_failure_evidence() {
  local sample_root="$1" id="$2" expected_static="$3" expected_baseline="$4"
  local expected_outer="$5" expected_host="$6" reason="$7"
  printf 'evidence unavailable: %s\n' "${reason}" > "${sample_root}/readelf.txt"
  printf '{"schemaVersion":1,"projectId":"%s","error":%s}\n' "${id}" "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${reason}")" > "${sample_root}/elf-fingerprint.json"
  printf '{"schemaVersion":1,"status":"environment-unavailable","reason":%s}\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${reason}")" > "${sample_root}/urprotect-report.json"
  printf 'failure=%s\n' "${reason}" > "${sample_root}/hashes.txt"
  write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" "${expected_outer}" "${expected_host}" \
    environment-unavailable environment-unavailable environment-unavailable environment-unavailable '' "${reason}" "${reason}"
}

run_isolated_baseline() {
  local extract_root="$1" sample_root="$2" artifact_path="$3" command_b64="$4"
  local declared_path="/${artifact_path#/}"
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
  if [[ "${#command_parts[@]}" -eq 0 || "${command_parts[0]}" != "${declared_path}" ]]; then
    echo "baseline policy command does not launch declared artifact ${declared_path}" >&2
    return 125
  fi
  python3 "${repo_root}/scripts/run-isolated-real-sample.py" \
    --rootfs "${extract_root}" --stdout "${sample_root}/logs/baseline.stdout" \
    --stderr "${sample_root}/logs/baseline.stderr" --timeout 30 --memory-bytes 536870912 \
    --process-limit 32 --output-limit 1048576 -- "${command_parts[@]}"
}

process_project() {
  local json_record="$1"
  local id archive_url version archive_path archive_sha archive_format artifact_path producer expected_static baseline_applicable expected_baseline baseline_mode baseline_command_b64 runtime loader
  IFS=$'\t' read -r id archive_url version archive_path archive_sha archive_format artifact_path producer expected_static baseline_applicable expected_baseline baseline_mode baseline_command_b64 runtime loader < <(project_fields "${json_record}")
  local sample_root="${artifact_root}/${id}" sample_tmp="${temp_root}/${id}" archive="${sample_tmp}/source.archive" extract_root="${sample_tmp}/extract"
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
      --connect-timeout 20 --max-time 180 --output "${archive}" "${archive_url}" \
      >"${sample_root}/logs/acquisition.log" 2>&1; then archive_status=0; else archive_status=$?; fi
  if [[ "${archive_status}" -ne 0 || ! -s "${archive}" ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" not-applicable not-applicable "archive download failed"
    return 1
  fi
  if [[ "$(stat -c '%s' "${archive}")" -gt 67108864 ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" not-applicable not-applicable "archive exceeds 64 MiB acquisition limit"
    return 1
  fi
  if printf '%s  %s\n' "${archive_sha}" "${archive}" | sha256sum -c - > "${sample_root}/logs/archive-sha256.log" 2>&1; then :; else
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" not-applicable not-applicable "archive SHA-256 mismatch"
    return 1
  fi
  printf 'archiveSha256=%s\n' "${archive_sha}" > "${sample_root}/hashes.txt"
  if python3 "${repo_root}/scripts/extract-real-sample.py" --archive "${archive}" --format "${archive_format}" --destination "${extract_root}" > "${sample_root}/logs/extraction.log" 2>&1; then :; else
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" not-applicable not-applicable "archive extraction failed"
    return 1
  fi
  local artifact="${extract_root}/${artifact_path}"
  if [[ -L "${artifact}" || ! -f "${artifact}" ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" not-applicable not-applicable "declared artifact path is missing or a symlink"
    return 1
  fi
  local artifact_sha; artifact_sha="$(sha256sum "${artifact}" | awk '{print $1}')"
  printf 'artifactSha256=%s\n' "${artifact_sha}" >> "${sample_root}/hashes.txt"
  local inspect_status=0
  if python3 "${repo_root}/scripts/inspect-real-sample.py" --input "${artifact}" --output "${sample_root}/elf-fingerprint.json" \
      --readelf-output "${sample_root}/readelf.txt" --project-id "${id}" --producer "${producer}" > "${sample_root}/logs/inspect.log" 2>&1; then :; else inspect_status=$?; fi
  if [[ "${inspect_status}" -ne 0 ]]; then
    write_failure_evidence "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" not-applicable not-applicable "ELF fingerprint inspection failed"
    return 1
  fi
  local fingerprint_status=0
  if python3 "${repo_root}/scripts/compare-real-sample-fingerprint.py" --manifest "${manifest}" --project-id "${id}" \
      --fingerprint "${sample_root}/elf-fingerprint.json" --output "${sample_root}/fingerprint-comparison.json" > "${sample_root}/logs/fingerprint-compare.log" 2>&1; then :; else fingerprint_status=$?; fi
  local validator_status=0
  if "${dotnet_cli[@]}" validate "${artifact}" --no-analysis --json "${sample_root}/urprotect-report.json" > "${sample_root}/logs/urprotect.log" 2>&1; then :; else validator_status=$?; fi
  local actual_static
  if [[ "${fingerprint_status}" -ne 0 ]]; then actual_static=unexpected-rejection
  elif [[ "${validator_status}" -eq 0 ]]; then actual_static=accepted-and-runs
  elif [[ "${expected_static}" == expected-rejected ]]; then actual_static=expected-rejected
  else actual_static=unexpected-rejection
  fi
  local actual_baseline=not-applicable reason_baseline='policy declares no dynamic baseline oracle for this package closure'
  if [[ "${baseline_applicable}" == true ]]; then
    if [[ "${baseline_mode}" == bubblewrap-rootfs ]]; then
      local run_status=0
      if run_isolated_baseline "${extract_root}" "${sample_root}" "${artifact_path}" "${baseline_command_b64}"; then :; else run_status=$?; fi
      if [[ "${run_status}" -eq 0 ]]; then actual_baseline=accepted-and-runs
      elif [[ "${run_status}" -eq 125 ]]; then actual_baseline=environment-unavailable; reason_baseline='bubblewrap isolation capability is unavailable'
      else actual_baseline=runtime-failure; reason_baseline="isolated baseline exited with status ${run_status}"; fi
    else actual_baseline=environment-unavailable; reason_baseline='unknown isolation policy mode'; fi
  fi
  local actual_outer=not-applicable actual_host=not-applicable
  write_result "${sample_root}" "${id}" "${expected_static}" "${expected_baseline}" not-applicable not-applicable \
    "${actual_static}" "${actual_baseline}" "${actual_outer}" "${actual_host}" "${artifact_sha}" \
    "fingerprintStatus=${fingerprint_status}; validatorStatus=${validator_status}" "${reason_baseline}"
  local result_status=0
  [[ "${actual_static}" == "${expected_static}" ]] || result_status=1
  [[ "${actual_baseline}" == "${expected_baseline}" ]] || result_status=1
  return "${result_status}"
}

while IFS= read -r project_json; do
  [[ -z "${project_json}" ]] && continue
  if process_project "${project_json}"; then :; else overall_status=1; fi
done < <(python3 "${repo_root}/scripts/validate-real-samples.py" "${manifest}" --candidates "${candidates}" --tier "${requested_tier}" --emit | tail -n +2)

python3 "${repo_root}/scripts/render-real-sample-report.py" "${manifest}" --tier "${requested_tier}" \
  --artifact-root "${artifact_root}" --output-json "${artifact_root}/aggregate.json" \
  --output-markdown "${artifact_root}/aggregate.md" || overall_status=1
python3 "${repo_root}/scripts/check-real-sample-evidence.py" "${manifest}" --candidates "${candidates}" \
  --tier "${requested_tier}" --artifact-root "${artifact_root}" || overall_status=1
printf 'real-sample tier %s completed with status %s; raw inputs were under %s and removed on exit\n' "${requested_tier}" "${overall_status}" "${temp_root}"
exit "${overall_status}"
