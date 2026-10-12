#!/usr/bin/env python3
"""Deterministic namespace and dependency checks for the managed ownership map.

The checker intentionally works on source text instead of build output.  That
keeps the rule stable across SDKs and lets the self-test exercise a forbidden
reference without placing invalid code in a production project.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class OwnershipRule:
    name: str
    namespace: str
    directory: Path
    allowed_namespaces: tuple[str, ...]
    forbidden_namespaces: tuple[str, ...]
    forbidden_tokens: tuple[str, ...] = ()
    check_side_effects: bool = True


RULES = (
    OwnershipRule(
        "StructuralElf",
        "UrProtect.Core.StructuralElf",
        Path("src/UrProtect.Core/StructuralElf"),
        ("UrProtect.Core.Binary", "UrProtect.Core.Diagnostics"),
        (
            "UrProtect.Core.Aarch64Semantics",
            "UrProtect.Core.SemanticPlanning",
            "UrProtect.Core.ElfLayout",
            "UrProtect.Core.ArtifactProtocol",
            "UrProtect.Core.Application",
            "UrProtect.Core.Infrastructure",
            "UrProtect.Cli",
        ),
        (
            "System.IO",
            "System.Diagnostics",
            "System.Runtime.InteropServices",
            "DllImport",
            "LibraryImport",
            "NativeLibrary",
            "SafeFileHandle",
            "Marshal",
            "Process",
        ),
    ),
    OwnershipRule(
        "Aarch64Semantics",
        "UrProtect.Core.Aarch64Semantics",
        Path("src/UrProtect.Core/Aarch64Semantics"),
        ("UrProtect.Core.StructuralElf", "UrProtect.Core.Binary", "UrProtect.Core.Diagnostics"),
        (
            "UrProtect.Core.SemanticPlanning",
            "UrProtect.Core.ElfLayout",
            "UrProtect.Core.ArtifactProtocol",
            "UrProtect.Core.Application",
            "UrProtect.Core.Infrastructure",
            "UrProtect.Cli",
        ),
        (
            "System.IO",
            "System.Diagnostics",
            "System.Runtime.InteropServices",
            "DllImport",
            "LibraryImport",
            "NativeLibrary",
            "SafeFileHandle",
            "Marshal",
            "Process",
        ),
    ),
    OwnershipRule(
        "SemanticPlanning",
        "UrProtect.Core.SemanticPlanning",
        Path("src/UrProtect.Core/SemanticPlanning"),
        (
            "UrProtect.Core.StructuralElf",
            "UrProtect.Core.Aarch64Semantics",
            "UrProtect.Core.Binary",
            "UrProtect.Core.Diagnostics",
        ),
        (
            "UrProtect.Core.ElfLayout",
            "UrProtect.Core.ArtifactProtocol",
            "UrProtect.Core.Application",
            "UrProtect.Core.Infrastructure",
            "UrProtect.Cli",
        ),
        (
            "System.IO",
            "System.Diagnostics",
            "System.Runtime.InteropServices",
            "DllImport",
            "LibraryImport",
            "NativeLibrary",
            "SafeFileHandle",
            "Marshal",
            "Process",
        ),
    ),
    OwnershipRule(
        "ElfLayout",
        "UrProtect.Core.ElfLayout",
        Path("src/UrProtect.Core/ElfLayout"),
        (
            "UrProtect.Core.StructuralElf",
            "UrProtect.Core.SemanticPlanning",
            "UrProtect.Core.Aarch64Semantics",
            "UrProtect.Core.Binary",
            "UrProtect.Core.Diagnostics",
        ),
        (
            "UrProtect.Core.ArtifactProtocol",
            "UrProtect.Core.Application",
            "UrProtect.Core.Infrastructure",
            "UrProtect.Cli",
        ),
        (
            "System.IO",
            "System.Diagnostics",
            "System.Runtime.InteropServices",
            "DllImport",
            "LibraryImport",
            "NativeLibrary",
            "SafeFileHandle",
            "Marshal",
            "Process",
        ),
    ),
    OwnershipRule(
        "Application",
        "UrProtect.Core.Application",
        Path("src/UrProtect.Core/Application"),
        (
            "UrProtect.Core.StructuralElf",
            "UrProtect.Core.Aarch64Semantics",
            "UrProtect.Core.SemanticPlanning",
            "UrProtect.Core.ElfLayout",
            "UrProtect.Core.ArtifactProtocol",
            "UrProtect.Core.Binary",
            "UrProtect.Core.Diagnostics",
            "UrProtect.Core.Infrastructure",
        ),
        (
            "UrProtect.Cli",
        ),
        (
            "System.IO",
            "System.Runtime.InteropServices",
            "DllImport",
            "LibraryImport",
            "NativeLibrary",
            "SafeFileHandle",
            "Marshal",
            "Process",
        ),
    ),
    OwnershipRule(
        "Infrastructure",
        "UrProtect.Core.Infrastructure",
        Path("src/UrProtect.Core/Infrastructure"),
        (
            "UrProtect.Core.Application",
            "UrProtect.Core.StructuralElf",
            "UrProtect.Core.Aarch64Semantics",
            "UrProtect.Core.SemanticPlanning",
            "UrProtect.Core.ElfLayout",
            "UrProtect.Core.ArtifactProtocol",
            "UrProtect.Core.Binary",
            "UrProtect.Core.Diagnostics",
        ),
        (
            "UrProtect.Cli",
        ),
        check_side_effects=False,
    ),
    OwnershipRule(
        "Cli",
        "UrProtect.Cli",
        Path("src/UrProtect.Cli"),
        (
            "UrProtect.Cli",
            "UrProtect.Core.Application",
            "UrProtect.Core.ArtifactProtocol",
            "UrProtect.Core.Diagnostics",
            "UrProtect.Core.StructuralElf",
            "UrProtect.Core.Aarch64Semantics",
            "UrProtect.Core.SemanticPlanning",
            "UrProtect.Core.Infrastructure",
        ),
        (),
        (
            "System.IO",
            "System.Diagnostics",
            "System.Runtime.InteropServices",
            "DllImport",
            "LibraryImport",
            "NativeLibrary",
            "SafeFileHandle",
            "Marshal",
            "Process",
        ),
    ),
)

NAMESPACE_PATTERN = re.compile(
    r"^\s*namespace\s+([A-Za-z_][\w.]*)\s*(?:;|\{)",
    re.MULTILINE,
)
USING_PATTERN = re.compile(
    r"^\s*(?:global\s+)?using\s+(?:static\s+)?(?:[A-Za-z_]\w*\s*=\s*)?"
    r"(?:global::)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;"
)
QUALIFIED_NAMESPACE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:global::)?"
    r"((?:UrProtect\.Core|UrProtect\.Cli)(?:\.[A-Za-z_]\w*)*)"
)
FORBIDDEN_SIDE_EFFECT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.])(?:File|Directory|Path|Process|Console)\s*\.\s*[A-Za-z_]"
    r"|\bEnvironment\s*\.\s*(?!NewLine\b)[A-Za-z_]"
    r"|\b(?:FileStream|FileInfo|DirectoryInfo|FileOptions|FileMode|FileAccess|FileShare"
    r"|StreamReader|StreamWriter)\b"
)


def _blank_comments_and_literals(source: str) -> str:
    """Replace comments and literals with spaces while preserving newlines."""
    result = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if result[position] not in "\r\n":
                result[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            blank(index, end)
            index = end
            continue
        if source[index] == '"':
            # C# verbatim strings double an embedded quote; ordinary strings
            # use backslash escapes. The preceding @ also covers $@ strings.
            verbatim = index > 0 and source[index - 1] == "@"
            if source.startswith('"""', index):
                delimiter = '"' * 3
                end = source.find(delimiter, index + 3)
                end = length if end == -1 else end + 3
                blank(index, end)
                index = end
                continue
            end = index + 1
            while end < length:
                if verbatim:
                    if source.startswith('""', end):
                        end += 2
                        continue
                    if source[end] == '"':
                        end += 1
                        break
                else:
                    if source[end] == '"' and source[end - 1] != "\\":
                        end += 1
                        break
                    if source[end] == "\\":
                        end += 1
                end += 1
            blank(index, end)
            index = end
            continue
        if source[index] == "'":
            end = index + 1
            while end < length:
                if source[end] == "'" and source[end - 1] != "\\":
                    end += 1
                    break
                if source[end] == "\\":
                    end += 1
                end += 1
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(result)


def _owner_for_namespace(namespace: str) -> OwnershipRule | None:
    for rule in RULES:
        if namespace == rule.namespace or namespace.startswith(rule.namespace + "."):
            return rule
    return None


def _namespace_for_source(source: str) -> str | None:
    match = NAMESPACE_PATTERN.search(source)
    return match.group(1) if match else None


def _is_namespace_reference(value: str, prefix: str) -> bool:
    return value == prefix or value.startswith(prefix + ".")


def check_sources(root: Path, paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in sorted(paths):
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            failures.append(f"{path}: source is not UTF-8 ({error})")
            continue

        analysis_source = _blank_comments_and_literals(source)
        namespace = _namespace_for_source(analysis_source)
        if namespace is None:
            # The executable entry point is intentionally a top-level CLI
            # adapter; all library source still requires an explicit namespace.
            if path.resolve() == (root / "src/UrProtect.Cli/Program.cs").resolve():
                continue
            failures.append(f"{path}: missing file-scoped or block namespace")
            continue
        absolute_path = path.resolve()
        relative = absolute_path.relative_to(root)
        path_rule = next(
            (
                candidate
                for candidate in RULES
                if (root / candidate.directory).resolve() == absolute_path.parent
                or (root / candidate.directory).resolve() in absolute_path.parents
            ),
            None,
        )
        rule = path_rule or _owner_for_namespace(namespace)
        if rule is None:
            continue

        expected_directory = (root / rule.directory).relative_to(root)
        if not (relative.parent == expected_directory or expected_directory in relative.parents):
            failures.append(
                f"{path}: namespace {namespace} must live below {rule.directory}"
            )
        elif not _is_namespace_reference(namespace, rule.namespace):
            failures.append(
                f"{path}: directory {rule.directory} requires namespace {rule.namespace}, got {namespace}"
            )
            # Keep scanning dependencies under the directory rule so the
            # report remains deterministic and complete.

        for line_number, line in enumerate(analysis_source.splitlines(), 1):
            using = USING_PATTERN.match(line)
            references = [using.group(1)] if using else [
                match.group(1) for match in QUALIFIED_NAMESPACE_PATTERN.finditer(line)
            ]
            for referenced in references:
                if referenced.startswith(("UrProtect.Core.", "UrProtect.Cli")):
                    same_owner = _is_namespace_reference(referenced, rule.namespace)
                    allowed = any(_is_namespace_reference(referenced, prefix) for prefix in rule.allowed_namespaces)
                    if not same_owner and not allowed:
                        failures.append(
                            f"{path}:{line_number}: {rule.name} cannot depend on {referenced}"
                        )

            for token in rule.forbidden_tokens:
                if re.search(rf"\b{re.escape(token)}\b", line):
                    failures.append(
                        f"{path}:{line_number}: {rule.name} contains forbidden token {token}"
                    )
            if rule.check_side_effects and FORBIDDEN_SIDE_EFFECT_PATTERN.search(line):
                failures.append(
                    f"{path}:{line_number}: {rule.name} contains a forbidden filesystem/process reference"
                )
    return failures


def production_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for base in (root / "src/UrProtect.Core", root / "src/UrProtect.Cli"):
        if base.exists():
            paths.extend(
                path
                for path in base.rglob("*.cs")
                if "obj" not in path.parts and "bin" not in path.parts
            )
    return paths


def fixture_paths(root: Path, fixture: Path) -> list[Path]:
    return [fixture if fixture.is_absolute() else root / fixture]


def run(root: Path, fixture: Path | None, self_test: bool) -> int:
    failures = check_sources(root, production_paths(root))
    if failures:
        print("architecture check: production tree failed", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("architecture check: production tree passed")

    if fixture is not None:
        fixture_failures = check_sources(root, fixture_paths(root, fixture))
        if not fixture_failures:
            print(f"architecture check: expected forbidden fixture violation in {fixture} was absent", file=sys.stderr)
            return 1
        print(f"architecture check: forbidden fixture detected ({len(fixture_failures)} violation(s))")
        for failure in fixture_failures:
            print(f"  {failure}")
        return 1 if not self_test else 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--fixture",
        type=Path,
        help="Check one non-production source fixture; it is expected to fail.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Require --fixture to fail and report the expected violation as a pass.",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    fixture = args.fixture
    if args.self_test and fixture is None:
        fixture = Path("tests/ArchitectureFixtures/ForbiddenStructuralDependency.cs")
    return run(root, fixture, args.self_test)


if __name__ == "__main__":
    raise SystemExit(main())
