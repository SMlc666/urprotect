#!/usr/bin/env python3
"""Validate the append-only independent-evaluator manifests and immutable baseline."""

from __future__ import annotations

import argparse
import sys
sys.dont_write_bytecode = True
from pathlib import Path

from evaluator_lib import EvaluatorError, validate_all_manifests


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest_root", nargs="?", type=Path, help="optional fixtures/evaluator directory")
    parser.add_argument("--protocol", type=Path, default=None)
    parser.add_argument("--corpus", type=Path, default=None)
    parser.add_argument("--scheme-a", type=Path, default=None)
    parser.add_argument("--oracles", type=Path, default=None)
    parser.add_argument("--baseline-reference", type=Path, default=None)
    arguments = parser.parse_args()
    manifest_root = (arguments.manifest_root or root / "fixtures/evaluator").resolve()
    arguments.protocol = arguments.protocol or manifest_root / "evaluator-protocol.json"
    arguments.corpus = arguments.corpus or manifest_root / "compatibility-corpus.json"
    arguments.scheme_a = arguments.scheme_a or manifest_root / "scheme-a-manifest.json"
    arguments.oracles = arguments.oracles or manifest_root / "oracles.json"
    arguments.baseline_reference = arguments.baseline_reference or manifest_root / "baseline-reference.json"
    return arguments


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    try:
        validated = validate_all_manifests(
            repo_root,
            protocol_path=args.protocol.resolve(),
            corpus_path=args.corpus.resolve(),
            scheme_path=args.scheme_a.resolve(),
            oracle_path=args.oracles.resolve(),
            baseline_reference_path=args.baseline_reference.resolve(),
        )
    except EvaluatorError as error:
        print(f"FAIL evaluator manifests: {error}", file=sys.stderr)
        return 1
    corpus = validated["corpus"]
    scheme = validated["scheme"]
    reference = validated["baselineReference"]
    print(
        "PASS evaluator manifests: "
        f"corpus={corpus['corpusVersion']} rows={len(validated['rows'])} "
        f"families={len(validated['families'])} "
        f"baseline={reference['baselineArtifactId']} "
        f"baselineStatus={validated['baseline']['baselineStatus']} "
        f"strengthStatus={validated['baseline']['strengthStatus']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
