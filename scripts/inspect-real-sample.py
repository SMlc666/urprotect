#!/usr/bin/env python3
"""Emit a bounded, normalized ELF fingerprint for one acquired CI sample.

The orchestrator invokes this after archive and extracted-file hash checks.  It
only reads the declared file and runs the platform readelf tool; it never
executes the target ELF.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

MAX_INPUT_BYTES = 512 * 1024 * 1024
# Do not request the full dynamic symbol table here: large real-world
# runtimes can make `readelf -sW` unbounded for evidence purposes. Version
# records are collected with `-V`; 16 MiB is still a hard evidence bound.
MAX_READELF_BYTES = 16 * 1024 * 1024


class InspectionError(Exception):
    pass


def parse_integer(value: str) -> int | None:
    try:
        return int(value, 0)
    except ValueError:
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def readelf_report(path: Path, executable: str) -> str:
    try:
        completed = subprocess.run(
            [
                executable,
                "-hW",
                "-lW",
                "-dW",
                "-rW",
                "-nW",
                "-VW",
                str(path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InspectionError(f"readelf could not inspect the sample: {error}") from error
    if len(completed.stdout) > MAX_READELF_BYTES:
        raise InspectionError("readelf output exceeded the bounded report size")
    report = completed.stdout.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        raise InspectionError(f"readelf failed with status {completed.returncode}: {report[-1000:]}")
    return report


def parse_loads(report: str) -> list[dict[str, Any]]:
    loads: list[dict[str, Any]] = []
    in_program_headers = False
    for line in report.splitlines():
        if line.startswith("Program Headers:"):
            in_program_headers = True
            continue
        if in_program_headers and line.startswith(" Section to Segment mapping"):
            break
        if not in_program_headers or not line.strip().startswith("LOAD"):
            continue
        fields = line.split()
        if len(fields) < 8:
            continue
        numbers = [parse_integer(fields[index]) for index in range(1, 6)]
        alignment = parse_integer(fields[-1])
        if any(value is None for value in numbers) or alignment is None:
            continue
        flags = "".join(field for field in fields[6:-1] if field in {"R", "W", "E"})
        loads.append(
            {
                "offset": numbers[0],
                "virtualAddress": numbers[1],
                "physicalAddress": numbers[2],
                "fileSize": numbers[3],
                "memorySize": numbers[4],
                "flags": flags,
                "alignment": alignment,
                "congruent": alignment <= 1
                or (numbers[0] % alignment) == (numbers[1] % alignment),
            }
        )
    return loads


def parse_fingerprint(path: Path, report: str, producer: str) -> dict[str, Any]:
    def field(name: str) -> str:
        match = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", report, re.MULTILINE)
        return match.group(1) if match else "unknown"

    elf_class = field("Class")
    data = field("Data")
    machine = field("Machine")
    type_value = field("Type")
    if type_value != "unknown":
        type_value = type_value.split(" ", 1)[0]
    interpreter_match = re.search(r"Requesting program interpreter:\s*([^\]\n]+)", report)
    interpreter = interpreter_match.group(1).strip() if interpreter_match else None
    loads = parse_loads(report)

    needed = sorted(
        set(re.findall(r"Shared library:\s*\[([^\]]+)\]", report))
    )
    dynamic_tags = sorted(
        set(
            match.group(1)
            for line in report.splitlines()
            if "(" in line and ")" in line and not line.lstrip().startswith(("Hex dump", "Version"))
            for match in [re.search(r"\((DT_[A-Z0-9_]+)\)", line)]
            if match
        )
    )
    has_rela = bool(re.search(r"\bRELA\b|\.rela", report, re.IGNORECASE))
    has_relr = bool(re.search(r"\bRELR\b|\.relr", report, re.IGNORECASE))
    has_plt = bool(re.search(r"JUMP_SLOT|\.rela\.plt|\.rel\.plt|JMPREL", report))
    symbol_versions = bool(
        re.search(r"\.gnu\.version|VERSYM|VERDEF|VERNEED", report, re.IGNORECASE)
    )
    tls = bool(re.search(r"^\s*TLS\s", report, re.MULTILINE))
    gnu_property = "GNU_PROPERTY" in report or ".note.gnu.property" in report
    gnu_relro = bool(re.search(r"^\s*GNU_RELRO\s", report, re.MULTILINE))
    stack_match = re.search(r"^\s*GNU_STACK\s+.*?\s([RWE ]{1,4})\s+0x", report, re.MULTILINE)
    stack_flags = "".join(stack_match.group(1).split()) if stack_match else "unknown"
    stripped = "Symbol table '.symtab'" not in report and ".symtab" not in report
    build_id_match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", report)
    page_size_match = re.search(r"Page size:\s*(\d+)", report)
    program_headers_match = re.search(r"There are\s+(\d+)\s+program headers", report)
    dynamic_symbols_match = re.search(r"\.dynsym\s+\w+\s+\w+\s+(\d+)", report)
    file_size = path.stat().st_size

    feature_tags: list[str] = []
    if has_rela:
        feature_tags.append("rela")
    if has_relr:
        feature_tags.append("relr")
    if has_plt:
        feature_tags.append("plt-relocations")
    if symbol_versions:
        feature_tags.append("symbol-versions")
    if tls:
        feature_tags.append("pt-tls")
    if gnu_property:
        feature_tags.append("gnu-property")
    if gnu_relro:
        feature_tags.append("gnu-relro")
    if stack_flags != "unknown":
        feature_tags.append("gnu-stack-exec" if "E" in stack_flags else "gnu-stack-noexec")
    if stripped:
        feature_tags.append("stripped")
    if not loads:
        feature_tags.append("missing-load-layout")
    else:
        feature_tags.append("load-layout-congruent" if all(load["congruent"] for load in loads) else "load-layout-noncongruent")

    return {
        "schemaVersion": 1,
        "producer": producer,
        "fileSha256": sha256_file(path),
        "fileSizeBytes": file_size,
        "elfClass": elf_class,
        "data": data,
        "machine": machine,
        "type": type_value,
        "interpreter": interpreter,
        "programHeaderCount": int(program_headers_match.group(1)) if program_headers_match else None,
        "pageSize": int(page_size_match.group(1)) if page_size_match else None,
        "ptLoadLayout": loads,
        "dynamicNeeded": needed,
        "dynamicTags": dynamic_tags,
        "relocations": {
            "rela": has_rela,
            "relr": has_relr,
            "plt": has_plt,
        },
        "symbolVersions": symbol_versions,
        "tls": tls,
        "gnuProperty": gnu_property,
        "relro": gnu_relro,
        "gnuStack": {
            "flags": stack_flags,
            "executable": "E" in stack_flags if stack_flags != "unknown" else None,
        },
        "stripped": stripped,
        "dynamicSymbolCount": int(dynamic_symbols_match.group(1)) if dynamic_symbols_match else None,
        "buildId": build_id_match.group(1).lower() if build_id_match else None,
        "featureTags": feature_tags,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--readelf-output", required=True, type=Path)
    parser.add_argument("--project-id", default="unknown-project")
    parser.add_argument("--producer", default="unknown")
    parser.add_argument("--readelf", default="readelf")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        path = arguments.input.resolve(strict=True)
        if path.is_symlink() or not path.is_file():
            raise InspectionError("input must be a regular non-symlink file")
        if path.stat().st_size <= 0 or path.stat().st_size > MAX_INPUT_BYTES:
            raise InspectionError("input size is outside the bounded inspection range")
        report = readelf_report(path, arguments.readelf)
        fingerprint = parse_fingerprint(path, report, arguments.producer)
        fingerprint["projectId"] = arguments.project_id
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.readelf_output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(fingerprint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        arguments.readelf_output.write_text(report, encoding="utf-8")
    except (InspectionError, OSError, ValueError) as error:
        print(f"FAIL real-sample inspection: {error}", file=sys.stderr)
        return 1
    print(f"PASS real-sample inspection: {arguments.project_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
