#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/fixtures/manifest.json"
artifact_root="${ANDROID_ARTIFACT_ROOT:-${repo_root}/.artifacts/android-avd-tcg}"
mkdir -p "${artifact_root}"
report="${artifact_root}/environment.txt"
exec > >(tee "${artifact_root}/run.log") 2>&1

{
  echo "host=$(uname -a)"
  echo "machine=$(uname -m)"
  echo "page_size=$(getconf PAGESIZE 2>/dev/null || echo unknown)"
  echo "kvm=$(test -e /dev/kvm && echo present || echo absent)"
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
  "emulator:${emulator}" \
  "adb:${adb}" \
  "gradle:${gradle}"; do
  name="${pair%%:*}"
  value="${pair#*:}"
  if [[ -z "${value}" ]]; then
    missing+=("${name}")
  else
    echo "${name}=${value}" | tee -a "${report}"
  fi
done

if (( ${#missing[@]} > 0 )); then
  echo "ANDROID_AVD_UNAVAILABLE missing=${missing[*]}"
  echo "The ARM64 runner cannot execute the AVD software-emulation path without these tools."
  exit 0
fi

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "ANDROID_AVD_UNAVAILABLE host is not aarch64"
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
echo "mode=arm64-avd-tcg-software" | tee -a "${report}"

if ! timeout 15 "${emulator}" -version > "${artifact_root}/emulator-version.txt" 2>&1; then
  echo "ANDROID_AVD_UNAVAILABLE emulator version probe failed"
  exit 0
fi
if ! timeout 15 "${adb}" version > "${artifact_root}/adb-version.txt" 2>&1; then
  echo "ANDROID_AVD_UNAVAILABLE adb version probe failed"
  exit 0
fi

yes | timeout 180 "${sdkmanager}" --sdk_root="${sdk_root}" --licenses > "${artifact_root}/licenses.log" 2>&1 || true
timeout 300 "${sdkmanager}" --sdk_root="${sdk_root}" \
  "platform-tools" "emulator" "platforms;android-${api_level}" \
  "build-tools;35.0.0" "cmake;${cmake_version}" "ndk;${ndk_version}" \
  "${system_image}"

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

emulator_log="${artifact_root}/emulator.log"
"${emulator}" -avd "${avd_name}" -no-window -no-audio -no-boot-anim \
  -no-snapshot -no-accel -gpu swiftshader_indirect > "${emulator_log}" 2>&1 &
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

"${adb}" install -r --abi arm64-v8a "${artifact_root}/fixture.apk"
"${adb}" logcat -c
"${adb}" shell am start -n "${package_name}/.MainActivity"
sleep 5
"${adb}" logcat -d > "${artifact_root}/logcat.txt"
if ! grep -q 'URPROTECT_FIXTURE_RESULT=urprotect-fixture:android-ndk' "${artifact_root}/logcat.txt"; then
  echo "Android JNI result was not observed through System.loadLibrary" >&2
  exit 1
fi

echo "PASS android-ndk-jni: APK installed, bionic loaded libfixture.so, and JNI returned the expected value"
