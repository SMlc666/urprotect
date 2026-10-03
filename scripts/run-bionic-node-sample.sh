#!/usr/bin/env bash
set -euo pipefail

# The Python owner implements the bounded Docker watchdog, host-side stream
# capture, inspected container-status protocol, and interruption cleanup.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${repo_root}/scripts/bionic_node_runner.py" "$@"
