#!/usr/bin/env python3
"""Validate the reviewed metadata-only Termux/bionic Node.js runtime lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from bionic_node_lock import lock_file_sha256, validate_lock_document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path("fixtures/real-samples/manifest.json"))
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        lock = json.loads(args.lock.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"FAIL bionic Node.js runtime lock: {error}", file=sys.stderr)
        return 1

    errors = validate_lock_document(
        lock,
        manifest=manifest,
        expected_lock_sha256=args.expected_sha256,
    )
    if args.expected_sha256 is not None:
        try:
            actual = lock_file_sha256(args.lock)
        except OSError as error:
            errors.append(f"could not hash lock: {error}")
        else:
            if actual != args.expected_sha256:
                errors.append(f"lock SHA-256 mismatch: expected {args.expected_sha256}, got {actual}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"PASS bionic Node.js runtime lock: {args.lock}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
