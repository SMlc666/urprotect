#!/usr/bin/env bash
set -euo pipefail

helper="${1:-native/urprotect-runtime/build/native-image-handoff}"
if [[ ! -x "$helper" ]]; then
  echo "native handoff helper is missing or not executable: $helper" >&2
  exit 2
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/urprotect-native-handoff.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

cat >"$work/target.c" <<'C'
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 9;
    }
    (void)puts(argv[1]);
    return 0;
}
C
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror "$work/target.c" -o "$work/target"
image="$work/target"
image_hash="$(sha256sum "$image" | cut -d' ' -f1)"
rehydration_hash="$(printf 'synthetic rehydration record\n' | sha256sum | cut -d' ' -f1)"
"$helper" "$image" "$image_hash" "$rehydration_hash" "$work/handoff.json" "$work/target.stdout" "$work/target.stderr" 4096 -- "$work/target" native-handoff-ok
python3 - "$work" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
record = json.loads((root / "handoff.json").read_text(encoding="utf-8"))
assert record["schemaVersion"] == 1
assert record["stage"] == "native-handoff"
assert record["status"] == "passed"
assert record["helperStatus"] == "passed"
assert record["helperExitCode"] == 0
assert record["rehydrationRecordSha256"] == hashlib.sha256(b"synthetic rehydration record\n").hexdigest()
assert record["memfdCreated"] is True
assert record["fchmodStatus"] == "passed"
assert record["fsyncStatus"] == "passed"
assert record["sealsSupported"] is True and record["sealsApplied"] is True
assert record["execveatInvoked"] is True and record["execveatStatus"] == "passed"
assert record["targetStatus"] == 0 and record["targetSignal"] is None
assert (root / "target.stdout").read_bytes() == b"native-handoff-ok\n"
assert (root / "target.stderr").read_bytes() == b""
assert record["stdoutBytes"] == len(b"native-handoff-ok\n")
assert record["stderrBytes"] == 0
assert record["stdoutTruncated"] is False and record["stderrTruncated"] is False
PY

set +e
"$helper" "$image" "$(printf '%064d' 0)" "$rehydration_hash" "$work/tamper.json" "$work/tamper.stdout" "$work/tamper.stderr" 4096 -- "$work/target" should-not-run
status=$?
set -e
if [[ "$status" -ne 65 ]]; then
  echo "digest mismatch returned unexpected helper status: $status" >&2
  exit 1
fi
python3 - "$work" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
record = json.loads((root / "tamper.json").read_text(encoding="utf-8"))
assert record["status"] == "failed"
assert record["helperStatus"] == "failed"
assert record["diagnostic"] == "NativeImageDigestMismatch"
assert record["memfdCreated"] is False
assert record["execveatInvoked"] is False
assert (root / "tamper.stdout").read_bytes() == b""
assert (root / "tamper.stderr").read_bytes() == b""
PY

echo "PASS native memfd/execveat handoff helper"
