#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --input NODE --artifact-root DIR --image IMAGE --version VERSION --sha256 SHA256 --archive-sha256 SHA256 --launcher LAUNCHER" >&2
}

input=''
artifact_root=''
image=''
version=''
sha256=''
archive_sha256=''
launcher=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) input="$2"; shift 2 ;;
    --artifact-root) artifact_root="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --sha256) sha256="$2"; shift 2 ;;
    --archive-sha256) archive_sha256="$2"; shift 2 ;;
    --launcher) launcher="$2"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
if [[ -z "$input" || -z "$artifact_root" || -z "$image" || -z "$version" || -z "$sha256" || -z "$archive_sha256" || -z "$launcher" ]]; then
  usage
  exit 2
fi

echo 'environment-unavailable: bionic Node.js dependency closure is not locked; refusing live apt acquisition as compatibility evidence' >&2
exit 125
