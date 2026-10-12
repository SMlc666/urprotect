#!/usr/bin/env python3
"""Reject final AArch64 instruction-word writers outside the project adapter."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ADAPTER = Path("src/UrProtect.Core/Aarch64Semantics/Aarch64InstructionEncoder.cs")
SCAN_DIRECTORIES = (
    Path("src/UrProtect.Core/Application/Protection"),
    Path("src/UrProtect.Core/ElfLayout"),
    Path("src/UrProtect.Core/SemanticPlanning"),
    Path("src/UrProtect.Cli"),
)
LEGACY_WRITER_TOKENS = (
    "EncodeMovW",
    "EncodeMovX",
    "EncodeCmpW",
    "TryEncodeBranch26",
    "ElfLayoutPlannerTryEncode",
    "EncodePageImmediate",
)
FINAL_WORD_PATTERNS = (
    (
        "source/output bitfield merge",
        re.compile(
            r"\b(?:fixedEncoding|encoded[A-Za-z0-9_]*|outputEncoding|"
            r"word|words\s*\[[^\]]+\])\s*=\s*[^;\n]*"
            r"&\s*~[^;\n]*\|\s*[^;\n]*&"
        ),
    ),
    (
        "opcode/immediate assembly",
        re.compile(
            r"(?:\b(?:fixedEncoding|encoded[A-Za-z0-9_]*|outputEncoding|"
            r"word|words\s*\[[^\]]+\])\s*=\s*|\breturn\s+|=>\s*)"
            r"[^;\n]*0x[0-9A-Fa-f_]+u?\s*\|\s*[^;\n]*(?:<<|>>)"
        ),
    ),
)


def _blank_comments(source: str) -> str:
    result = list(source)
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end == -1 else end
            for position in range(index, end):
                result[position] = " "
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = len(source) if end == -1 else end + 2
            for position in range(index, end):
                if result[position] not in "\r\n":
                    result[position] = " "
            index = end
            continue
        index += 1
    return "".join(result)


def production_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for directory in SCAN_DIRECTORIES:
        base = root / directory
        if base.exists():
            paths.extend(
                path
                for path in base.rglob("*.cs")
                if "obj" not in path.parts and "bin" not in path.parts
            )
    return paths


def check_sources(root: Path, paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in sorted(paths):
        relative = path.resolve().relative_to(root.resolve())
        if relative == ADAPTER:
            continue
        source = _blank_comments(path.read_text(encoding="utf-8"))
        for line_number, line in enumerate(source.splitlines(), 1):
            for token in LEGACY_WRITER_TOKENS:
                if re.search(rf"\b{re.escape(token)}\b", line):
                    failures.append(
                        f"{path}:{line_number}: manual AArch64 final-word writer token {token}"
                    )
        for description, pattern in FINAL_WORD_PATTERNS:
            match = pattern.search(source)
            if match:
                line_number = source.count("\n", 0, match.start()) + 1
                failures.append(
                    f"{path}:{line_number}: manual AArch64 final-word writer ({description})"
                )
    return failures


def run(root: Path, fixture: Path | None, self_test: bool) -> int:
    failures = check_sources(root, production_paths(root))
    if failures:
        print("AArch64 encoding boundary check: production tree failed", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("AArch64 encoding boundary check: production tree passed")
    if fixture is None:
        return 0

    fixture_failures = check_sources(
        root,
        [fixture if fixture.is_absolute() else root / fixture],
    )
    if not fixture_failures:
        print(
            f"AArch64 encoding boundary check: expected fixture violation absent: {fixture}",
            file=sys.stderr,
        )
        return 1
    print(
        f"AArch64 encoding boundary check: forbidden fixture detected "
        f"({len(fixture_failures)} violation(s))"
    )
    for failure in fixture_failures:
        print(f"  {failure}")
    return 0 if self_test else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return run(args.root.resolve(), args.fixture, args.self_test)


if __name__ == "__main__":
    raise SystemExit(main())
