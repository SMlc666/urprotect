#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.1.0}"
output_root="${2:-${repo_root}/.artifacts/release}"
source_date_epoch="${SOURCE_DATE_EPOCH:-0}"

if [[ ! "${source_date_epoch}" =~ ^[0-9]+$ ]]; then
  echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
  exit 2
fi

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version: ${version}" >&2
  exit 2
fi

for required_command in dotnet file git python3 readelf sha256sum tar; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "${required_command} is required to package UrProtect Validator" >&2
    exit 127
  fi
done

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "release packaging requires an ARM64 host; got $(uname -m)" >&2
  exit 2
fi

mkdir -p "${output_root}"
work_root="$(mktemp -d "${output_root}/.package.XXXXXX")"
cleanup() {
  rm -rf -- "${work_root}"
}
trap cleanup EXIT

dotnet restore "${repo_root}/UrProtect.sln" --locked-mode

asmstone_commit="$(tr -d '[:space:]' < "${repo_root}/third_party/AsmStone/COMMIT")"
sdk_version="$(dotnet --version)"
manifest_sha256="$(sha256sum "${repo_root}/fixtures/manifest.json" | awk '{print $1}')"
git_sha="$(git -C "${repo_root}" rev-parse HEAD)"
checksums_file="${output_root}/SHA256SUMS"
manifest_file="${output_root}/release-manifest.txt"
: > "${checksums_file}"

export GZIP=-n
for profile in glibc musl; do
  if [[ "${profile}" == glibc ]]; then
    rid="linux-arm64"
    expected_loader="ld-linux-aarch64.so.1"
  else
    rid="linux-musl-arm64"
    expected_loader="ld-musl-aarch64.so.1"
  fi

  package_name="urprotect-linux-arm64-${profile}-${version}"
  publish_directory="${work_root}/${package_name}/publish"
  package_directory="${work_root}/${package_name}"
  archive="${output_root}/${package_name}.tar.gz"
  mkdir -p "${publish_directory}"

  dotnet publish "${repo_root}/src/UrProtect.Cli" \
    --configuration Release \
    --output "${publish_directory}" \
    --no-restore \
    --nologo \
    -p:RuntimeIdentifier="${rid}" \
    -p:SelfContained=true \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -p:DebugType=None \
    -p:StripSymbols=true \
    -p:Version="${version}" \
    -p:InformationalVersion="${version}"

  binary="${publish_directory}/urprotect"
  if [[ ! -x "${binary}" ]]; then
    echo "publish did not produce executable ${binary}" >&2
    exit 1
  fi
  file "${binary}" > "${package_directory}/file.txt"
  readelf -hW -lW -dW "${binary}" > "${package_directory}/readelf.txt"
  python3 - "${package_directory}/readelf.txt" "${expected_loader}" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
loader = sys.argv[2]
fields = {}
for line in report.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        fields[name.strip()] = value.strip()
if (
    fields.get("Class") != "ELF64"
    or fields.get("Data") != "2's complement, little endian"
    or fields.get("Machine") != "AArch64"
    or not fields.get("Type", "").startswith("DYN")
    or loader not in report
):
    raise SystemExit(f"published binary is not the expected AArch64 {loader} PIE")
PY

  mv -- "${binary}" "${package_directory}/urprotect"
  rm -rf -- "${publish_directory}"
  cat > "${package_directory}/README.md" <<EOF
UrProtect Validator ${version} (${profile})

This package validates ELF64 little-endian AArch64 ET_DYN PIE executables and
dynamically linked shared objects. It can emit a byte-identical no-op copy and
a schema-versioned JSON report.

Usage:
  ./urprotect validate ./program
  ./urprotect validate ./program --copy ./program.checked --json ./report.json

This release does not rewrite code, encrypt code, inject runtime behavior, or
claim physical Android-device compatibility. The ${profile} package must run
on a native ARM64 ${profile} environment.
EOF
  mkdir -p "${package_directory}/THIRD_PARTY_NOTICES"
  cp "${repo_root}/third_party/AsmStone/LICENSE" "${package_directory}/THIRD_PARTY_NOTICES/AsmStone-LICENSE"
  cp "${repo_root}/third_party/AsmStone/COMMIT" "${package_directory}/THIRD_PARTY_NOTICES/AsmStone-COMMIT"
  cp "${repo_root}/third_party/AsmStone/docs/THIRD_PARTY.md" "${package_directory}/THIRD_PARTY_NOTICES/AsmStone-THIRD_PARTY.md"
  python3 - "${package_directory}/sbom.json" "${version}" "${rid}" "${sdk_version}" "${asmstone_commit}" "${manifest_sha256}" <<'PY'
import json
import pathlib
import sys

path, version, rid, sdk, asmstone, manifest = sys.argv[1:]
document = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:urprotect:validator:{version}:{rid}",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "UrProtect Validator",
            "version": version,
        }
    },
    "components": [
        {"type": "framework", "name": ".NET SDK", "version": sdk},
        {"type": "library", "name": "AsmStone", "version": f"commit:{asmstone}"},
        {"type": "data", "name": "fixture-manifest", "version": manifest},
    ],
}
pathlib.Path(path).write_text(json.dumps(document, indent=2) + "\n")
PY
  cat > "${package_directory}/provenance.txt" <<EOF
product=UrProtect Validator
version=${version}
runtime_identifier=${rid}
sdk_version=${sdk_version}
asmstone_commit=${asmstone_commit}
fixture_manifest_sha256=${manifest_sha256}
source_git_sha=${git_sha}
source_date_epoch=${source_date_epoch}
EOF

  tar --sort=name --mtime="@${source_date_epoch}" --owner=0 --group=0 --numeric-owner \
    --create --gzip --file "${archive}" --directory "${work_root}" "${package_name}"
  (cd "${output_root}" && sha256sum "$(basename "${archive}")") >> "${checksums_file}"
  printf '%s runtime_identifier=%s archive=%s\n' "${package_name}" "${rid}" "$(basename "${archive}")" >> "${manifest_file}"
done

{
  echo "product=UrProtect Validator"
  echo "version=${version}"
  echo "source_git_sha=${git_sha}"
  echo "sdk_version=${sdk_version}"
  echo "asmstone_commit=${asmstone_commit}"
  echo "fixture_manifest_sha256=${manifest_sha256}"
  echo "source_date_epoch=${source_date_epoch}"
} | cat - "${manifest_file}" > "${manifest_file}.tmp"
mv -- "${manifest_file}.tmp" "${manifest_file}"
printf 'release packages written to %s\n' "${output_root}"
