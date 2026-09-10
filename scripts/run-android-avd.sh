#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/fixtures/manifest.json"
artifact_root="${ANDROID_ARTIFACT_ROOT:-${repo_root}/.artifacts/android-arm64-tcg-on-x64}"
mkdir -p "${artifact_root}"
report="${artifact_root}/environment.txt"
exec > >(tee "${artifact_root}/run.log") 2>&1

{
  echo "host=$(uname -a)"
  echo "machine=$(uname -m)"
  echo "page_size=$(getconf PAGESIZE 2>/dev/null || echo unknown)"
  echo "kvm=$(test -e /dev/kvm && echo present || echo absent)"
  echo "expected_host=x86_64"
  echo "expected_guest=arm64-v8a"
  echo "mode=android-arm64-tcg-on-x64"
} > "${report}"

android_value() {
  python3 - "${manifest}" "$1" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1]).read())
print(data["android"][sys.argv[2]])
PY
}

api_level="$(android_value apiLevel)"
system_image="$(android_value systemImage)"
if [[ "${system_image}" != *";arm64-v8a" ]]; then
  echo "Android manifest must select an arm64-v8a system image: ${system_image}" >&2
  exit 1
fi
ndk_version="$(android_value ndkVersion)"
cmake_version="$(android_value cmakeVersion)"
avd_name="$(android_value avdName)"
package_name="$(android_value packageName)"

find_command() {
  local name="$1"
  if command -v "${name}" >/dev/null 2>&1; then
    command -v "${name}"
    return 0
  fi
  local sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [[ -n "${sdk_root}" ]]; then
    for candidate in \
      "${sdk_root}/cmdline-tools/latest/bin/${name}" \
      "${sdk_root}/cmdline-tools/bin/${name}" \
      "${sdk_root}/tools/bin/${name}" \
      "${sdk_root}/emulator/${name}" \
      "${sdk_root}/platform-tools/${name}"; do
      if [[ -x "${candidate}" ]]; then
        echo "${candidate}"
        return 0
      fi
    done
  fi
  return 1
}

sdkmanager="$(find_command sdkmanager || true)"
avdmanager="$(find_command avdmanager || true)"
emulator="$(find_command emulator || true)"
adb="$(find_command adb || true)"
gradle="$(find_command gradle || true)"

missing=()
for pair in \
  "sdkmanager:${sdkmanager}" \
  "avdmanager:${avdmanager}" \
  "gradle:${gradle}"; do
  name="${pair%%:*}"
  value="${pair#*:}"
  if [[ -z "${value}" ]]; then
    missing+=("${name}")
  else
    echo "${name}=${value}" | tee -a "${report}"
  fi
done

report_unavailable() {
  local reason="$1"
  echo "ANDROID_AVD_UNAVAILABLE ${reason}"
  echo "Mode: android-arm64-tcg-on-x64 (x86_64 host, arm64-v8a guest, TCG/software CPU emulation)."
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## Android ARM64 TCG E2E unavailable"
      echo
      echo "${reason}"
      echo
      echo 'Mode: `android-arm64-tcg-on-x64` (x86_64 host, `arm64-v8a` guest, TCG/software CPU emulation).'
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
  return 0
}

if [[ "$(uname -m)" != "x86_64" ]]; then
  report_unavailable "unsupported host architecture: $(uname -m); expected x86_64"
  exit 0
fi

if (( ${#missing[@]} > 0 )); then
  report_unavailable "missing tools: ${missing[*]}"
  exit 0
fi

sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "${sdk_root}" ]]; then
  sdk_root="$(cd "$(dirname "${sdkmanager}")/../../.." && pwd)"
fi
echo "android_sdk=${sdk_root}" | tee -a "${report}"
echo "system_image=${system_image}" | tee -a "${report}"
echo "ndk_version=${ndk_version}" | tee -a "${report}"
echo "cmake_version=${cmake_version}" | tee -a "${report}"
echo "mode=android-arm64-tcg-on-x64" | tee -a "${report}"

if ! timeout 15 "${sdkmanager}" --version > "${artifact_root}/sdkmanager-version.txt" 2>&1; then
  report_unavailable "sdkmanager version probe failed"
  exit 0
fi
set +e
timeout 15 "${avdmanager}" --help > "${artifact_root}/avdmanager-help.txt" 2>&1
avdmanager_help_status=$?
set -e
if ! grep -qE 'Usage:|Valid actions' "${artifact_root}/avdmanager-help.txt"; then
  report_unavailable "avdmanager help probe failed (status ${avdmanager_help_status})"
  exit 0
fi
if ! timeout 15 "${gradle}" --version > "${artifact_root}/gradle-version.txt" 2>&1; then
  report_unavailable "Gradle version probe failed"
  exit 0
fi

yes | timeout 180 "${sdkmanager}" --sdk_root="${sdk_root}" --licenses > "${artifact_root}/licenses.log" 2>&1 || true
timeout 300 "${sdkmanager}" --sdk_root="${sdk_root}" \
  "platform-tools" "emulator" "platforms;android-${api_level}" \
  "build-tools;35.0.0" "cmake;${cmake_version}" "ndk;${ndk_version}" \
  "${system_image}"

# setup-android provides sdkmanager/avdmanager, while emulator and adb are
# installed by the pinned SDK package set above.
emulator="$(find_command emulator || true)"
adb="$(find_command adb || true)"
missing=()
for pair in "emulator:${emulator}" "adb:${adb}"; do
  name="${pair%%:*}"
  value="${pair#*:}"
  if [[ -z "${value}" ]]; then
    missing+=("${name}")
  else
    echo "${name}=${value}" | tee -a "${report}"
  fi
done
if (( ${#missing[@]} > 0 )); then
  report_unavailable "SDK installation did not provide required tools: ${missing[*]}"
  exit 0
fi
if ! timeout 15 "${emulator}" -version > "${artifact_root}/emulator-version.txt" 2>&1; then
  report_unavailable "emulator version probe failed"
  exit 0
fi
if ! timeout 15 "${adb}" version > "${artifact_root}/adb-version.txt" 2>&1; then
  report_unavailable "adb version probe failed"
  exit 0
fi
timeout 15 "${emulator}" -accel-check > "${artifact_root}/accel-check.txt" 2>&1 || true

echo "no" | timeout 60 "${avdmanager}" create avd --force --name "${avd_name}" \
  --package "${system_image}" --device "pixel_2" > "${artifact_root}/avd-create.log" 2>&1

timeout 300 "${gradle}" --no-daemon --console=plain \
  -p "${repo_root}/fixtures/samples/android-jni" :app:assembleDebug
apk="$(find "${repo_root}/fixtures/samples/android-jni/app/build/outputs/apk" -name '*.apk' -type f | head -1)"
if [[ -z "${apk}" ]]; then
  echo "Android build produced no APK" >&2
  exit 1
fi
cp -- "${apk}" "${artifact_root}/fixture.apk"
python3 - "${artifact_root}/fixture.apk" <<'PY_APK_CHECK'
from pathlib import Path
import sys
import zipfile

apk = Path(sys.argv[1])
with zipfile.ZipFile(apk) as archive:
    names = set(archive.namelist())
arm64 = "lib/arm64-v8a/libfixture.so"
abis = sorted(name for name in names if name.startswith("lib/") and name.endswith(".so"))
if arm64 not in names:
    raise SystemExit(f"APK is missing required {arm64}; native entries={abis}")
wrong_abis = [name for name in abis if not name.startswith("lib/arm64-v8a/")]
if wrong_abis:
    raise SystemExit(f"APK contains unexpected native ABIs: {wrong_abis}")
print(f"APK native ABI check passed: {arm64}")
PY_APK_CHECK

emulator_log="${artifact_root}/emulator.log"
"${emulator}" -avd "${avd_name}" -no-window -no-audio -no-boot-anim \
  -no-snapshot -accel off -gpu swiftshader_indirect > "${emulator_log}" 2>&1 &
emulator_pid=$!
cleanup() {
  "${adb}" emu kill >/dev/null 2>&1 || true
  kill "${emulator_pid}" >/dev/null 2>&1 || true
  wait "${emulator_pid}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

timeout 300 "${adb}" wait-for-device
boot_deadline=$((SECONDS + 300))
until [[ "$("${adb}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do
  if (( SECONDS >= boot_deadline )); then
    echo "Android AVD did not boot in software-emulation mode" >&2
    exit 1
  fi
  sleep 3
done

"${adb}" shell getprop > "${artifact_root}/device-properties.txt"
guest_abis="$("${adb}" shell getprop ro.product.cpu.abilist 2>/dev/null | tr -d '\r')"
echo "guest_abis=${guest_abis}" | tee -a "${report}"
if [[ ",${guest_abis}," != *,arm64-v8a,* ]]; then
  echo "Android AVD guest ABI mismatch: expected arm64-v8a, got ${guest_abis}" >&2
  exit 1
fi

"${adb}" install -r --abi arm64-v8a "${artifact_root}/fixture.apk"
"${adb}" logcat -c
"${adb}" shell am start -n "${package_name}/.MainActivity"
result_deadline=$((SECONDS + 120))
while :; do
  "${adb}" logcat -d > "${artifact_root}/logcat.txt"
  if grep -q 'URPROTECT_FIXTURE_RESULT=urprotect-fixture:android-ndk' "${artifact_root}/logcat.txt"; then
    break
  fi
  if (( SECONDS >= result_deadline )); then
    echo "Android JNI result was not observed through System.loadLibrary" >&2
    exit 1
  fi
  sleep 3
done

echo "PASS android-arm64-tcg-on-x64: APK installed, bionic loaded libfixture.so, Android linker resolved the AArch64 library, and JNI returned the expected value"
