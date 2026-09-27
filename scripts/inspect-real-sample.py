#!/usr/bin/env python3
"""Emit a bounded, normalized ELF fingerprint for one acquired CI sample.

The orchestrator invokes this after archive and extracted-file hash checks.  It
only reads the declared file and runs the platform readelf tool; it never
executes the target ELF.  The report is intentionally a normalized summary:
large relocation/symbol tables are represented by bounded counts and names,
not copied into retained evidence.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
from typing import Any, Iterable

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_READELF_BYTES = 16 * 1024 * 1024
MAX_LIST_ITEMS = 128
MAX_RELOCATION_ROWS = 200_000
MAX_DYNAMIC_NEEDED = 256


class InspectionError(Exception):
    """A bounded inspection or normalization failure."""


def parse_integer(value: str) -> int | None:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        try:
            return int(value, 16)
        except (TypeError, ValueError):
            return None


def bounded_strings(values: Iterable[str], limit: int = MAX_LIST_ITEMS) -> list[str]:
    """Return deterministic unique strings without retaining an unbounded list."""
    unique = sorted({value for value in values if isinstance(value, str) and value})
    return unique[:limit]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def readelf_report(path: Path, executable: str) -> str:
    command = [
        executable,
        "-hW",
        "-lW",
        "-SW",
        "-dW",
        "-rW",
        "-nW",
        "-VW",
        str(path),
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as error:
        raise InspectionError(f"readelf could not inspect the sample: {error}") from error

    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + 45
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise InspectionError("readelf exceeded the bounded inspection time")
            events = selector.select(remaining)
            if not events:
                process.kill()
                process.wait()
                raise InspectionError("readelf exceeded the bounded inspection time")
            chunk = process.stdout.read1(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_READELF_BYTES:
                process.kill()
                process.wait()
                raise InspectionError("readelf output exceeded the bounded report size")
            chunks.append(chunk)
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired) as error:
        process.kill()
        process.wait()
        raise InspectionError(f"readelf could not finish inspection: {error}") from error
    finally:
        selector.close()
        process.stdout.close()

    report = b"".join(chunks).decode("utf-8", errors="replace")
    if return_code != 0:
        raise InspectionError(f"readelf failed with status {return_code}: {report[-1000:]}")
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
        assert all(value is not None for value in numbers)
        flags = "".join(dict.fromkeys(char for field in fields[6:-1] for char in field if char in "RWE"))
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
        if len(loads) >= MAX_LIST_ITEMS:
            break
    return loads


def parse_program_headers(report: str) -> dict[str, Any]:
    """Capture bounded facts for TLS, RELRO, stack, and interpreter segments."""
    segments: dict[str, list[dict[str, Any]]] = {
        "TLS": [],
        "GNU_RELRO": [],
        "GNU_STACK": [],
    }
    in_program_headers = False
    for line in report.splitlines():
        if line.startswith("Program Headers:"):
            in_program_headers = True
            continue
        if in_program_headers and line.startswith(" Section to Segment mapping"):
            break
        if not in_program_headers:
            continue
        fields = line.split()
        if not fields or fields[0] not in segments or len(fields) < 8:
            continue
        numbers = [parse_integer(fields[index]) for index in range(1, 6)]
        alignment = parse_integer(fields[-1])
        if any(value is None for value in numbers) or alignment is None:
            continue
        segments[fields[0]].append(
            {
                "offset": numbers[0],
                "virtualAddress": numbers[1],
                "fileSize": numbers[3],
                "memorySize": numbers[4],
                "flags": "".join(dict.fromkeys(char for field in fields[6:-1] for char in field if char in "RWE")),
                "alignment": alignment,
            }
        )
    return segments


def parse_dynamic(report: str) -> dict[str, Any]:
    needed = re.findall(r"Shared library:\s*\[([^\]]+)\]", report)
    needed = bounded_strings(needed, MAX_DYNAMIC_NEEDED)
    tags: set[str] = set()
    flags: set[str] = set()
    rpaths: list[str] = []
    runpaths: list[str] = []
    for line in report.splitlines():
        # GNU readelf omits the DT_ prefix in the human-readable Name column;
        # synthetic fixtures sometimes retain it. Normalize both spellings.
        for match in re.finditer(r"\((?:DT_)?([A-Z0-9_]+)\)", line):
            tags.add(f"DT_{match.group(1)}")
        if "Flags:" in line:
            flags.update(value for value in line.split("Flags:", 1)[1].split() if value.isupper())
        rpath_match = re.search(r"Library rpath:\s*\[([^\]]*)\]", line)
        runpath_match = re.search(r"Library runpath:\s*\[([^\]]*)\]", line)
        if rpath_match:
            rpaths.append(rpath_match.group(1))
        if runpath_match:
            runpaths.append(runpath_match.group(1))
    if "BIND_NOW" in report:
        flags.add("BIND_NOW")
    if "NOW" in report and "FLAGS_1" in report:
        flags.add("NOW")
    return {
        "needed": needed,
        "count": len(needed),
        "rpath": bounded_strings(rpaths),
        "runpath": bounded_strings(runpaths),
        "searchPathTags": bounded_strings(
            (["DT_RPATH"] if rpaths else []) + (["DT_RUNPATH"] if runpaths else [])
        ),
        "tags": bounded_strings(tags),
        "flags": bounded_strings(flags),
        "graph": {
            "status": "observed",
            "rootCount": len(needed),
            "edges": len(needed),
            "bounded": True,
        },
    }


def parse_relocations(report: str) -> dict[str, Any]:
    types: Counter[str] = Counter()
    families: Counter[str] = Counter()
    sections: Counter[str] = Counter()
    symbol_min: int | None = None
    symbol_max: int | None = None
    declared_rows = 0
    observed_rows = 0
    current_section: str | None = None
    truncated = False
    type_overflow = False
    section_overflow = False
    has_plt_section = False
    has_got_section = False

    for line in report.splitlines():
        section_match = re.match(
            r"^Relocation section '([^']+)'(?: at .*?)? contains (\d+) entries:", line
        )
        if section_match:
            current_section = section_match.group(1)
            declared_rows += int(section_match.group(2))
            if ".plt" in current_section.lower():
                has_plt_section = True
            if ".got" in current_section.lower():
                has_got_section = True
            if current_section not in sections:
                if len(sections) < MAX_LIST_ITEMS:
                    sections[current_section] = 0
                else:
                    section_overflow = True
            if ".relr" in current_section.lower():
                families["relr"] += int(section_match.group(2))
            elif ".rela" in current_section.lower() or ".rel" in current_section.lower():
                families["rela"] += int(section_match.group(2))
            continue
        if current_section is None or observed_rows >= MAX_RELOCATION_ROWS:
            if observed_rows >= MAX_RELOCATION_ROWS:
                truncated = True
            continue
        fields = line.split()
        if len(fields) < 3 or parse_integer(fields[0]) is None:
            continue
        relocation_type = next(
            (field for field in fields[2:] if re.fullmatch(r"R_[A-Z0-9_]+", field)),
            None,
        )
        if relocation_type is None:
            continue
        observed_rows += 1
        if relocation_type in types:
            types[relocation_type] += 1
        elif len(types) < MAX_LIST_ITEMS:
            types[relocation_type] = 1
        else:
            type_overflow = True
        if current_section in sections:
            sections[current_section] += 1
        upper = relocation_type.upper()
        if "RELATIVE" in upper:
            families["relative"] += 1
        elif "JUMP_SLOT" in upper or "PLT" in upper:
            families["plt"] += 1
        elif "GLOB_DAT" in upper or "GOT" in upper:
            families["got"] += 1
        elif "TLS" in upper:
            families["tls"] += 1
        elif "IRELATIVE" in upper:
            families["ifunc"] += 1
        else:
            families["other"] += 1
        info = parse_integer(fields[1])
        if info is not None and info >= 0:
            symbol_index = info >> 32
            symbol_min = symbol_index if symbol_min is None else min(symbol_min, symbol_index)
            symbol_max = symbol_index if symbol_max is None else max(symbol_max, symbol_index)

    dynamic = parse_dynamic(report)
    dynamic_tags = set(dynamic["tags"])
    has_rela = bool(families.get("rela")) or "DT_RELA" in dynamic_tags
    has_relr = bool(families.get("relr")) or "DT_RELR" in dynamic_tags
    has_plt = bool(families.get("plt")) or "DT_JMPREL" in dynamic_tags or any(
        ".plt" in name.lower() for name in sections
    )
    has_plt = has_plt or has_plt_section
    has_got = bool(families.get("got")) or "DT_PLTGOT" in dynamic_tags or any(
        ".got" in name.lower() for name in sections
    )
    has_got = has_got or has_got_section
    android_tags = {
        "DT_ANDROID_REL",
        "DT_ANDROID_RELSZ",
        "DT_ANDROID_RELA",
        "DT_ANDROID_RELASZ",
        "DT_ANDROID_RELR",
        "DT_ANDROID_RELRSZ",
        "DT_ANDROID_RELRENT",
        "DT_ANDROID_RELRCOUNT",
    }
    unknown = []
    if declared_rows and observed_rows == 0:
        unknown.append("relocation-rows-not-readable")
    if truncated:
        unknown.append("relocation-row-limit")
    if type_overflow:
        unknown.append("relocation-type-limit")
    if section_overflow:
        unknown.append("relocation-section-limit")
    return {
        # Keep the original booleans as compatibility projections.
        "rela": has_rela,
        "relr": has_relr,
        "plt": has_plt,
        "got": has_got,
        "androidPacked": bool(dynamic_tags.intersection(android_tags)),
        "families": dict(sorted(families.items())),
        "types": bounded_strings(types.keys()),
        "counts": dict(sorted(types.items())) if not truncated else dict(sorted(types.items())),
        "sections": dict(sorted(sections.items())),
        "declaredCount": declared_rows,
        "observedCount": observed_rows,
        "symbolIndexRange": (
            {"min": symbol_min, "max": symbol_max}
            if symbol_min is not None and symbol_max is not None
            else None
        ),
        "bounded": not (truncated or type_overflow or section_overflow),
        "unknown": bounded_strings(unknown),
    }


def parse_symbol_versions(report: str) -> dict[str, Any]:
    versym = bool(re.search(r"Version symbols section|\.gnu\.version(?:\s|')", report))
    definitions = bool(re.search(r"Version definition section|\.gnu\.version_d", report))
    needs = bool(re.search(r"Version needs section|\.gnu\.version_r", report))
    names = bounded_strings(re.findall(r"\bName:\s*([A-Za-z0-9_.+-]+)", report))
    present = versym or definitions or needs or bool(
        re.search(r"\b(?:DT_VERSYM|DT_VERDEF|DT_VERNEED)\b", report)
    )
    return {
        "present": present,
        "versym": versym,
        "definitions": definitions,
        "needs": needs,
        "names": names,
        "count": len(names),
        "status": "observed",
        "unknown": [],
    }


def parse_tls(report: str, headers: dict[str, Any], relocations: dict[str, Any]) -> dict[str, Any]:
    segments = headers.get("TLS", [])
    relocation_types = [value for value in relocations.get("types", []) if "TLS" in value]
    models: set[str] = set()
    for relocation_type in relocation_types:
        upper = relocation_type.upper()
        if "TLSDESC" in upper:
            models.add("tlsdesc")
        elif "TPREL" in upper:
            models.add("initial-exec-or-local-exec")
        elif "DTPREL" in upper or "DTPMOD" in upper:
            models.add("dynamic")
        else:
            models.add("unknown")
    if segments and not models:
        models.add("segment-only")
    return {
        "present": bool(segments) or bool(relocation_types),
        "segments": segments[:MAX_LIST_ITEMS],
        "models": sorted(models),
        "relocations": bounded_strings(relocation_types),
        "status": "observed",
        "unknown": [],
    }


def parse_gnu_property(report: str) -> dict[str, Any]:
    present = bool(
        re.search(r"GNU_PROPERTY|\.note\.gnu\.property|AArch64 feature:", report, re.IGNORECASE)
    )
    features: list[str] = []
    for line in report.splitlines():
        match = re.search(r"AArch64 feature:\s*(.+)$", line, re.IGNORECASE)
        if match:
            features.extend(value.strip().lower() for value in match.group(1).split(","))
    return {
        "present": present,
        "features": bounded_strings(features),
        "notes": bounded_strings(
            re.findall(r"Displaying notes found in:\s*([^\n]+)", report)
        ),
        "status": "observed",
        "unknown": [],
    }


def parse_section_facts(report: str) -> dict[str, Any]:
    section_names = bounded_strings(
        re.findall(r"^\s*\[\s*\d+\]\s+([^\s]+)", report, re.MULTILINE)
    )
    dynamic_symbol_count: int | None = None
    for line in report.splitlines():
        if ".dynsym" not in line or not re.match(r"^\s*\[\s*\d+\]", line):
            continue
        match = re.match(
            r"^\s*\[\s*\d+\]\s+\.dynsym\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)",
            line,
        )
        if match:
            size = parse_integer(match.group(1))
            entry_size = parse_integer(match.group(2))
            if size is not None and entry_size is not None and entry_size > 0:
                dynamic_symbol_count = size // entry_size
        break
    section_header_count_match = re.search(r"(?:There are|Number of)\s+(\d+)\s+section headers?", report)
    if section_header_count_match is None:
        section_header_count_match = re.search(r"Number of section headers:\s*(\d+)", report)
    section_count = int(section_header_count_match.group(1)) if section_header_count_match else None
    return {
        "names": section_names,
        "count": section_count,
        "sectionless": section_count == 0,
        "symtab": ".symtab" in section_names,
        "dynsym": ".dynsym" in section_names,
        "dynamicSymbolCount": dynamic_symbol_count,
    }


def parse_fingerprint(path: Path, report: str, producer: str, runtime: str = "unknown") -> dict[str, Any]:
    def field(name: str) -> str:
        match = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", report, re.MULTILINE)
        return match.group(1) if match else "unknown"

    elf_class = field("Class")
    data = field("Data")
    if "little" in data.lower():
        data = "little-endian"
    elif "big" in data.lower():
        data = "big-endian"
    machine = field("Machine")
    type_value = field("Type")
    if type_value != "unknown":
        type_value = type_value.split(" ", 1)[0]
    interpreter_match = re.search(r"Requesting program interpreter:\s*([^\]\n]+)", report)
    interpreter = interpreter_match.group(1).strip() if interpreter_match else None
    loads = parse_loads(report)
    headers = parse_program_headers(report)
    dynamic = parse_dynamic(report)
    relocations = parse_relocations(report)
    symbol_versions = parse_symbol_versions(report)
    tls = parse_tls(report, headers, relocations)
    gnu_property = parse_gnu_property(report)
    sections = parse_section_facts(report)

    dynamic_tags = set(dynamic["tags"])
    gnu_relro = bool(headers.get("GNU_RELRO"))
    stack_segments = headers.get("GNU_STACK", [])
    stack_flags = stack_segments[0].get("flags", "unknown") if stack_segments else "unknown"
    bind_now = "BIND_NOW" in set(dynamic.get("flags", [])) or "DT_BIND_NOW" in dynamic_tags
    textrel = "DT_TEXTREL" in dynamic_tags or bool(re.search(r"\bTEXTREL\b", report))
    build_id_match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", report)
    program_headers_match = re.search(r"There are\s+(\d+)\s+program headers", report)
    page_size_match = re.search(r"Page size:\s*(\d+)", report)
    if page_size_match:
        page_size: int | None = int(page_size_match.group(1))
        page_size_source = "readelf"
    else:
        try:
            page_size = int(os.sysconf("SC_PAGESIZE"))
            page_size_source = "host-getconf"
        except (AttributeError, OSError, ValueError):
            page_size = None
            page_size_source = "unknown"
    file_size = path.stat().st_size
    stripped = not sections["symtab"] and not sections["sectionless"]
    relro_kind = "full" if gnu_relro and bind_now else "partial" if gnu_relro else "none"
    is_dyn = type_value in {"ET_DYN", "DYN"}

    feature_tags: list[str] = []
    if relocations["rela"]:
        feature_tags.append("rela")
    if relocations["relr"]:
        feature_tags.append("relr")
    if relocations["plt"]:
        feature_tags.append("plt-relocations")
    if relocations["got"]:
        feature_tags.append("got")
    if relocations["androidPacked"]:
        feature_tags.append("android-packed-relocations")
    if symbol_versions["present"]:
        feature_tags.append("symbol-versions")
    if tls["present"]:
        feature_tags.append("pt-tls")
    if gnu_property["present"]:
        feature_tags.append("gnu-property")
    if gnu_relro:
        feature_tags.append("gnu-relro")
    if bind_now:
        feature_tags.append("bind-now")
    if textrel:
        feature_tags.append("textrel")
    if stack_flags != "unknown":
        feature_tags.append("gnu-stack-exec" if "E" in stack_flags else "gnu-stack-noexec")
    feature_tags.append("stripped" if stripped else "has-symbol-table")
    if sections["sectionless"]:
        feature_tags.append("sectionless")
    if dynamic["needed"]:
        feature_tags.append("dynamic-needed")
    if dynamic["rpath"]:
        feature_tags.append("rpath")
    if dynamic["runpath"]:
        feature_tags.append("runpath")
    if not loads:
        feature_tags.append("missing-load-layout")
    else:
        feature_tags.append(
            "load-layout-congruent"
            if all(load["congruent"] for load in loads)
            else "load-layout-noncongruent"
        )
    if type_value == "ET_EXEC":
        feature_tags.append("et-exec")
    elif is_dyn:
        feature_tags.append("et-dyn")

    unknown_fields: list[str] = []
    for key, value in (
        ("elfClass", elf_class),
        ("data", data),
        ("machine", machine),
        ("type", type_value),
        ("pageSize", page_size),
    ):
        if value in {None, "unknown"}:
            unknown_fields.append(key)
    if not loads:
        unknown_fields.append("ptLoadLayout")
    if not stack_segments:
        unknown_fields.append("gnuStack")

    return {
        "schemaVersion": 2,
        "featureSchemaVersion": 2,
        "producer": producer or "unknown",
        "runtime": runtime or "unknown",
        "loader": interpreter,
        "fileSha256": sha256_file(path),
        "fileSizeBytes": file_size,
        "elfClass": elf_class,
        "data": data,
        "machine": machine,
        "type": type_value,
        "interpreter": interpreter,
        "programHeaderCount": int(program_headers_match.group(1)) if program_headers_match else None,
        "pageSize": page_size,
        "pageSizeSource": page_size_source,
        "ptLoadLayout": loads,
        "dynamicNeeded": dynamic["needed"],
        "dynamicTags": bounded_strings(dynamic_tags),
        "dynamic": dynamic,
        "dependencies": {
            "needed": dynamic["needed"],
            "count": dynamic["count"],
            "rpath": dynamic["rpath"],
            "runpath": dynamic["runpath"],
            "searchPathTags": dynamic["searchPathTags"],
            "graph": dynamic["graph"],
        },
        "relocations": relocations,
        "symbolVersions": symbol_versions,
        "tls": tls,
        "gnuProperty": gnu_property,
        "relro": {
            "present": gnu_relro,
            "kind": relro_kind,
            "bindNow": bind_now,
            "segments": headers.get("GNU_RELRO", [])[:MAX_LIST_ITEMS],
        },
        "gnuStack": {
            "flags": stack_flags,
            "executable": "E" in stack_flags if stack_flags != "unknown" else None,
            "present": bool(stack_segments),
        },
        "hardening": {
            "relro": relro_kind,
            "bindNow": bind_now,
            "gnuStack": stack_flags,
            "textrel": textrel,
            "pie": is_dyn and interpreter is not None,
            "stripped": stripped,
        },
        "sections": sections,
        "stripped": stripped,
        "dynamicSymbolCount": sections.get("dynamicSymbolCount"),
        "buildId": build_id_match.group(1).lower() if build_id_match else None,
        "featureTags": bounded_strings(feature_tags),
        "unknownFields": bounded_strings(unknown_fields),
        "inspection": {
            "status": "observed",
            "bounded": True,
            "readelfBytes": len(report.encode("utf-8", errors="replace")),
            "unknownFields": bounded_strings(unknown_fields),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--readelf-output", required=True, type=Path)
    parser.add_argument("--project-id", default="unknown-project")
    parser.add_argument("--producer", default="unknown")
    parser.add_argument("--runtime", default="unknown")
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
        fingerprint = parse_fingerprint(path, report, arguments.producer, arguments.runtime)
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
