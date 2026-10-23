#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s PINNED-OCI-IMAGE INPUT-ELF ENTRY-SYMBOL RECORD [IDENTITY-DIR IDENTITY-RELATIVE-DIR ROLE]\n' "$0" >&2
  exit 2
}
[[ $# -eq 4 || $# -eq 7 ]] || usage

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container_runtime="${BIONIC_CONTAINER_RUNTIME:-docker}"
expected_image="${BIONIC_TERMUX_IMAGE:-}"
oci_image="$1"
input_elf="$2"
entry_symbol="$3"
record_arg="$4"
build_root_arg="${BIONIC_INDIRECT_CONTROL_BUILD_ROOT:-}"
[[ "$expected_image" =~ ^[A-Za-z0-9._/:+-]+@sha256:[0-9a-f]{64}$ ]] || { echo "Bionic pinned OCI selection is not an exact digest reference" >&2; exit 2; }
[[ "$oci_image" == "$expected_image" ]] || { echo "Bionic handoff OCI reference differs from the pinned runtime selection" >&2; exit 2; }
[[ -n "$build_root_arg" ]] || { echo "Bionic handoff build root is not configured" >&2; exit 2; }
command -v "$container_runtime" >/dev/null 2>&1 || { echo "$container_runtime is required for the Bionic HostContext handoff" >&2; exit 127; }
[[ "$(uname -m)" == aarch64 ]] || { echo "Bionic HostContext handoff requires native AArch64" >&2; exit 2; }
server_platform="$("$container_runtime" version --format '{{.Server.Os}}/{{.Server.Arch}}')"
[[ "$server_platform" == linux/arm64 ]] || { echo "Bionic handoff requires a native Linux/arm64 container engine; got $server_platform" >&2; exit 2; }

unit_root_arg="$(dirname -- "$record_arg")"
unit_root="$(realpath -e -- "$unit_root_arg" 2>/dev/null || true)"
artifact_base="$(realpath -e -- "$repo_root/.artifacts/indirect-control" 2>/dev/null || true)"
[[ -n "$unit_root" && -n "$artifact_base" && -d "$unit_root" && ! -L "$unit_root_arg" ]] || {
  echo "Bionic handoff evidence unit root is not a real directory" >&2
  exit 2
}
case "$unit_root/" in "$artifact_base/"*) ;; *) echo "Bionic handoff evidence root escaped .artifacts/indirect-control" >&2; exit 2 ;; esac
build_root="$(realpath -e -- "$build_root_arg" 2>/dev/null || true)"
expected_build_root="$(realpath -m -- "$repo_root/.artifacts/bionic/c-termux-bionic-pie/host-context/indirect-control-build")"
[[ -n "$build_root" && "$build_root" == "$expected_build_root" && -d "$build_root" && ! -L "$build_root_arg" ]] || {
  echo "Bionic handoff build root does not match the pinned fixture output root" >&2
  exit 2
}
helper="$build_root/host-context-image-handoff"
[[ -f "$helper" && -x "$helper" && ! -L "$helper" ]] || { echo "Bionic HostContext helper is missing or not executable" >&2; exit 2; }

map_into_container() {
  local path="$1" resolved relative
  [[ -f "$path" && ! -L "$path" ]] || { echo "Bionic handoff input is not a regular non-symlink file: $path" >&2; return 1; }
  resolved="$(realpath -e -- "$path" 2>/dev/null || true)"
  [[ -n "$resolved" ]] || { echo "Bionic handoff input cannot be resolved: $path" >&2; return 1; }
  case "$resolved" in
    "$unit_root"/*)
      relative="${resolved#"$unit_root"/}"
      printf '/evidence/%s' "$relative"
      ;;
    "$build_root"/*)
      relative="${resolved#"$build_root"/}"
      printf '/bionic-build/%s' "$relative"
      ;;
    *) echo "Bionic handoff input escaped its isolated evidence/build roots: $path" >&2; return 1 ;;
  esac
}
input_in_container="$(map_into_container "$input_elf")" || exit 2
record_parent="$(realpath -e -- "$(dirname -- "$record_arg")" 2>/dev/null || true)"
record_name="$(basename -- "$record_arg")"
[[ -n "$record_parent" && "$record_parent" == "$unit_root" && "$record_name" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "Bionic handoff record must remain directly inside its evidence unit" >&2
  exit 2
}
record_in_container="/evidence/$record_name"
[[ ! -e "$record_arg" && ! -L "$record_arg" ]] || { echo "Bionic handoff record path already exists" >&2; exit 2; }
[[ "$entry_symbol" =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]] || { echo "Bionic handoff entry symbol is malformed" >&2; exit 2; }
args=("$input_in_container" "$entry_symbol" "$record_in_container")
identity_in_container=
if [[ $# -eq 7 ]]; then
  identity_directory="$(realpath -e -- "$5" 2>/dev/null || true)"
  [[ -n "$identity_directory" && -d "$identity_directory" && ! -L "$5" ]] || { echo "Bionic runtime identity output directory is not a real directory" >&2; exit 2; }
  case "$identity_directory/" in "$unit_root/"*) ;; *) echo "Bionic runtime identity output escaped its evidence unit" >&2; exit 2 ;; esac
  identity_relative_directory="$6"
  role="$7"
  [[ "$identity_relative_directory" =~ ^runtime-identity/[A-Za-z0-9._-]+$ ]] || { echo "Bionic runtime identity relative path is malformed" >&2; exit 2; }
  [[ "$role" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Bionic runtime identity role is malformed" >&2; exit 2; }
  identity_in_container="/evidence/${identity_directory#"$unit_root"/}"
  args+=("$identity_in_container" "$identity_relative_directory" "$role")
  chmod a+rwx "$unit_root" "$identity_directory" || exit 1
fi

resolved_image="$("$container_runtime" image inspect "$oci_image" --format '{{.Id}}|{{join .RepoDigests ","}}')"
resolved_digests="${resolved_image#*|}"
case ",$resolved_digests," in
  *",$oci_image,"*) ;;
  *) echo "Bionic handoff image inspect did not return the exact pinned repository digest" >&2; exit 2 ;;
esac

container_shell='/data/data/com.termux/files/usr/bin/sh'
"$container_runtime" run --rm --platform linux/arm64 --user 1000:1000 \
  --env PREFIX=/data/data/com.termux/files/usr \
  --env HOME=/tmp \
  --env "IDENTITY_DIR=$identity_in_container" \
  --mount "type=bind,src=$unit_root,dst=/evidence" \
  --mount "type=bind,src=$build_root,dst=/bionic-build,readonly" \
  "$oci_image" "$container_shell" -c '
set -u
helper=/bionic-build/host-context-image-handoff
set +e
"$helper" "$@"
status=$?
if [ -n "$IDENTITY_DIR" ]; then
  for retained in "$IDENTITY_DIR"/*; do
    [ -f "$retained" ] && chmod 0644 "$retained" || :
  done
  chmod 0755 "$IDENTITY_DIR" || :
fi
exit "$status"
' bionic-handoff "${args[@]}"
