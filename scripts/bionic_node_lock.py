#!/usr/bin/env python3
"""Shared validation for the reviewed Termux/bionic Node.js runtime lock.

The checked-in lock is metadata only.  This module deliberately keeps the
manual candidate provenance separate from the runtime evidence produced by the
native container runner, and it resolves only the small Debian relation syntax
used by the reviewed package rows.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

LOCK_SCHEMA_VERSION = 1
RUNTIME = "bionic"
LOADER = "/system/bin/linker64"
PACKAGE_REPOSITORY = "https://packages-cf.termux.dev/apt/termux-main"
IMAGE_REF = "termux/termux-docker@sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4"
IMAGE_ID = "sha256:4afeef45d346a5e377724efede889c9ccad1046a71e097037494d16f15467c2e"
CANDIDATE_ARTIFACT_SHA256 = "ccd8022aef3671e4d0f33d9756adfbabd12bb057b1735732246887a155562f53"
CANDIDATE_WORKFLOW_RUN_ID = 37105636258
BASE_INVENTORY_COUNT = 86
BASE_INVENTORY_SHA256 = "a1023a8f537845b556776b67790c4bc8f8c49a56efbe1d248565b5f970b0327f"
NODE_ARCHIVE_PATH = "pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb"
NODE_VERSION = "26.4.0-1"
NODE_ARCHIVE_SHA256 = "eaf3ed8a6e4b72ebaa8c2cb3bad778c577cdf9ea87ca91761213d8a3940fc090"
NODE_ARCHIVE_SIZE_BYTES = 10349280
TERMUX_PREFIX = "/data/data/com.termux/files/usr"
TERMUX_SHELL = TERMUX_PREFIX + "/bin/sh"
NODE_SOURCE_URL = "https://packages.termux.dev/apt/termux-main/" + NODE_ARCHIVE_PATH
NODE_LOCK_URL = PACKAGE_REPOSITORY + "/" + NODE_ARCHIVE_PATH
ARTIFACT_PATH = TERMUX_PREFIX + "/bin/node"
LD_LIBRARY_PATH = TERMUX_PREFIX + "/lib"
NODE_RUNPATH = TERMUX_PREFIX + "/lib"
EXECUTION_ENVIRONMENT = {
    "PATH": TERMUX_PREFIX + "/bin:/system/bin:/usr/bin",
    "HOME": "/tmp",
    "LD_LIBRARY_PATH": LD_LIBRARY_PATH,
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::(?:any|native))?$")
RELATION_TERM_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9+.-]*(?::(?:any|native))?)"
    r"(?:\s*\(\s*(?P<operator><<|<=|=|>=|>>)\s+(?P<version>[^()\s]+)\s*\))?$"
)

# These rows are the reviewed, exact package inputs.  Keeping the immutable
# values here gives the validator an independent anchor in addition to the
# cross-file lock digest in runtime-closures.json.
EXPECTED_PACKAGES: dict[str, dict[str, Any]] = {
    "c-ares": {
        "version": "1.34.8",
        "architecture": "aarch64",
        "filename": "pool/main/c/c-ares/c-ares_1.34.8_aarch64.deb",
        "localFilename": "c-ares_1.34.8_aarch64.deb",
        "url": PACKAGE_REPOSITORY + "/pool/main/c/c-ares/c-ares_1.34.8_aarch64.deb",
        "sizeBytes": 194924,
        "sha256": "7681fc23e822d7988ba8b2adf3468f93ae68f724dda365cff1385096a9fa87e6",
        "dependencies": {
            "Breaks": "c-ares-dev",
            "Depends": "resolv-conf",
            "Replaces": "c-ares-dev",
        },
    },
    "libicu": {
        "version": "78.3",
        "architecture": "aarch64",
        "filename": "pool/main/libi/libicu/libicu_78.3_aarch64.deb",
        "localFilename": "libicu_78.3_aarch64.deb",
        "url": PACKAGE_REPOSITORY + "/pool/main/libi/libicu/libicu_78.3_aarch64.deb",
        "sizeBytes": 10210396,
        "sha256": "f536403f65a08fe0df6e7304184e902d54def77d5c3bd5edfd9109d57601d276",
        "dependencies": {
            "Breaks": "libicu-dev",
            "Depends": "libc++",
            "Replaces": "libicu-dev",
        },
    },
    "libsqlite": {
        "version": "3.53.4",
        "architecture": "aarch64",
        "filename": "pool/main/libs/libsqlite/libsqlite_3.53.4_aarch64.deb",
        "localFilename": "libsqlite_3.53.4_aarch64.deb",
        "url": PACKAGE_REPOSITORY + "/pool/main/libs/libsqlite/libsqlite_3.53.4_aarch64.deb",
        "sizeBytes": 759764,
        "sha256": "0e909ce0d50fe123305446cd22e0c5edf535d40344b9b065fbdcdee52f53198d",
        "dependencies": {
            "Breaks": "libsqlite-dev",
            "Depends": "zlib",
            "Replaces": "libsqlite-dev",
        },
    },
    "nodejs": {
        "version": NODE_VERSION,
        "architecture": "aarch64",
        "filename": NODE_ARCHIVE_PATH,
        "localFilename": "nodejs_26.4.0-1_aarch64.deb",
        "url": NODE_LOCK_URL,
        "sizeBytes": NODE_ARCHIVE_SIZE_BYTES,
        "sha256": NODE_ARCHIVE_SHA256,
        "dependencies": {
            "Breaks": "nodejs-dev",
            "Conflicts": "nodejs-lts, nodejs-current",
            "Depends": "libc++, openssl, c-ares, libicu, libsqlite, zlib, libffi",
            "Recommends": "npm",
            "Replaces": "nodejs-current, nodejs-dev",
            "Suggests": "clang, make, pkg-config, python",
        },
    },
    "npm": {
        "version": "11.20.0",
        "architecture": "all",
        "filename": "pool/main/n/npm/npm_11.20.0_all.deb",
        "localFilename": "npm_11.20.0_all.deb",
        "url": PACKAGE_REPOSITORY + "/pool/main/n/npm/npm_11.20.0_all.deb",
        "sizeBytes": 2025572,
        "sha256": "a2775653a0626749138ccd6e37a7b63239f36a9e3c62a9e6740818ca4b2d088b",
        "dependencies": {
            "Conflicts": "nodejs (<= 25.3.0), nodejs-lts (<= 24.13.0)",
            "Depends": "nodejs | nodejs-lts",
        },
    },
}


class LockValidationError(ValueError):
    """Raised by helpers that need a validated lock rather than an error list."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def lock_file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def canonical_inventory_bytes(packages: Sequence[Mapping[str, Any]]) -> bytes:
    rows: list[str] = []
    for package in sorted(
        packages,
        key=lambda item: (
            str(item.get("name", "")),
            str(item.get("version", "")),
            str(item.get("architecture", "")),
            str(item.get("status", "")),
        ),
    ):
        rows.append(
            "\t".join(
                (
                    str(package.get("name", "")),
                    str(package.get("version", "")),
                    str(package.get("architecture", "")),
                    str(package.get("status", "")),
                )
            )
            + "\n"
        )
    return "".join(rows).encode("utf-8")


def inventory_sha256(packages: Sequence[Mapping[str, Any]]) -> str:
    return _sha256(canonical_inventory_bytes(packages))


def _is_clean_https_url(value: Any) -> bool:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        return False
    parsed = urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.query and not parsed.fragment


def _safe_relative_filename(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and not value.endswith("/")


def parse_relation_expression(value: Any, label: str) -> tuple[list[list[dict[str, str]]], list[str]]:
    """Parse the bounded Debian relation subset without choosing providers.

    Supported syntax is package names, ``|`` alternatives, comma-separated
    clauses, and an optional version comparison.  Architecture restrictions,
    profile restrictions, substitutions, and other forms are rejected rather
    than interpreted heuristically.
    """

    if not isinstance(value, str) or not value.strip():
        return [], [f"{label} must be a non-empty dependency expression"]
    if any(ord(character) < 32 for character in value):
        return [], [f"{label} contains a control character"]
    clauses: list[list[dict[str, str]]] = []
    errors: list[str] = []
    for clause_index, raw_clause in enumerate(value.split(",")):
        clause = raw_clause.strip()
        if not clause:
            errors.append(f"{label} contains an empty clause at index {clause_index}")
            continue
        alternatives: list[dict[str, str]] = []
        for alternative_index, raw_alternative in enumerate(clause.split("|")):
            token = raw_alternative.strip()
            match = RELATION_TERM_RE.fullmatch(token)
            if match is None:
                errors.append(
                    f"{label} contains unsupported dependency syntax at clause "
                    f"{clause_index}, alternative {alternative_index}: {token!r}"
                )
                continue
            name = match.group("name")
            alternatives.append(
                {
                    "name": name.split(":", 1)[0],
                    "qualifier": name.split(":", 1)[1] if ":" in name else "",
                    "operator": match.group("operator") or "",
                    "version": match.group("version") or "",
                }
            )
        if alternatives:
            clauses.append(alternatives)
    return clauses, errors


def _relation_names(value: Any, label: str) -> tuple[list[list[str]], list[str]]:
    clauses, errors = parse_relation_expression(value, label)
    return [[term["name"] for term in clause] for clause in clauses], errors


def _error_if(condition: bool, errors: list[str], message: str) -> None:
    if condition:
        errors.append(message)


def _manifest_project(manifest: Mapping[str, Any] | None, project_id: str) -> Mapping[str, Any] | None:
    if not isinstance(manifest, Mapping):
        return None
    projects = manifest.get("corpus", {}).get("projects") if isinstance(manifest.get("corpus"), Mapping) else None
    if not isinstance(projects, list):
        return None
    for project in projects:
        if isinstance(project, Mapping) and project.get("projectId") == project_id:
            return project
    return None


def validate_lock_document(
    document: Any,
    *,
    manifest: Mapping[str, Any] | None = None,
    expected_lock_sha256: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, Mapping):
        return ["bionic Node.js runtime lock must be a JSON object"]

    _error_if(document.get("schemaVersion") != LOCK_SCHEMA_VERSION, errors, "bionic Node.js runtime lock schemaVersion must be 1")
    _error_if(document.get("status") != "reviewed-runtime-lock", errors, "bionic Node.js runtime lock status must be reviewed-runtime-lock")
    _error_if(document.get("evidenceClass") != "runtime-lock-metadata-only", errors, "bionic Node.js runtime lock evidenceClass must remain metadata-only")
    _error_if(document.get("runtime") != RUNTIME, errors, "bionic Node.js runtime lock runtime must be bionic")
    _error_if(document.get("runtimeEvidence") is not False, errors, "bionic Node.js runtime lock must not claim runtime evidence")
    _error_if(document.get("compatibilityStatus") != "not-established", errors, "bionic Node.js runtime lock compatibilityStatus must remain not-established")

    candidate = document.get("candidateProvenance")
    if not isinstance(candidate, Mapping):
        errors.append("bionic Node.js runtime lock candidateProvenance is required")
    else:
        expected_candidate = {
            "artifactSha256": CANDIDATE_ARTIFACT_SHA256,
            "workflowRunId": CANDIDATE_WORKFLOW_RUN_ID,
            "status": "candidate-lock",
            "evidenceClass": "candidate-lock-only",
            "runtimeEvidence": False,
            "compatibilityStatus": "not-established",
            "packageIndex": "live-capture-only",
            "resolver": "apt-get-update-download-only",
        }
        for field, expected in expected_candidate.items():
            if candidate.get(field) != expected:
                errors.append(f"candidateProvenance {field} does not preserve the verified candidate provenance")
        if not isinstance(candidate.get("artifactSha256"), str) or not SHA256_RE.fullmatch(str(candidate.get("artifactSha256"))):
            errors.append("candidateProvenance artifactSha256 must be a SHA-256 digest")
        if not isinstance(candidate.get("capturedAtUtc"), str) or not candidate.get("capturedAtUtc"):
            errors.append("candidateProvenance capturedAtUtc is required")
        if not isinstance(candidate.get("trigger"), str) or candidate.get("trigger") != "workflow_dispatch:capture_bionic_node_closure":
            errors.append("candidateProvenance trigger must identify the manual capture workflow")

    image = document.get("baseImage")
    if not isinstance(image, Mapping):
        errors.append("bionic Node.js runtime lock baseImage is required")
    else:
        for field, expected in (
            ("requestedRef", IMAGE_REF),
            ("id", IMAGE_ID),
            ("os", "linux"),
        ):
            if image.get(field) != expected:
                errors.append(f"baseImage {field} does not match the reviewed Termux image")
        if image.get("architecture") not in {"arm64", "aarch64"}:
            errors.append("baseImage architecture must be ARM64")
        repo_digests = image.get("repoDigests")
        if not isinstance(repo_digests, list) or IMAGE_REF not in repo_digests:
            errors.append("baseImage repoDigests must retain the reviewed immutable image reference")

    host = document.get("host")
    if not isinstance(host, Mapping):
        errors.append("bionic Node.js runtime lock host metadata is required")
    else:
        for field, expected in (
            ("architecture", "aarch64"),
            ("dockerServerPlatform", "linux/arm64"),
            ("containerPlatform", "linux/arm64"),
            ("loader", LOADER),
        ):
            if host.get(field) != expected:
                errors.append(f"host {field} does not match the locked native ARM64 bionic contract")

    for field, expected in (("loader", LOADER), ("packageRepository", PACKAGE_REPOSITORY)):
        if document.get(field) != expected:
            errors.append(f"bionic Node.js runtime lock {field} does not match the reviewed value")
    if expected_lock_sha256 is not None and expected_lock_sha256 != "":
        if not SHA256_RE.fullmatch(expected_lock_sha256) or expected_lock_sha256 == "0" * 64:
            errors.append("runtime closure bionic Node.js lock digest is malformed")

    source = document.get("sourceArchiveLock")
    if not isinstance(source, Mapping):
        errors.append("bionic Node.js runtime lock sourceArchiveLock is required")
    else:
        expected_source = {
            "projectId": "nodejs",
            "version": NODE_VERSION,
            "filename": NODE_ARCHIVE_PATH,
            "url": NODE_SOURCE_URL,
            "sizeBytes": NODE_ARCHIVE_SIZE_BYTES,
            "sha256": NODE_ARCHIVE_SHA256,
        }
        for field, expected in expected_source.items():
            if source.get(field) != expected:
                errors.append(f"sourceArchiveLock {field} does not match the locked Node.js source archive")
        if not _is_clean_https_url(source.get("url")):
            errors.append("sourceArchiveLock url must be a clean HTTPS URL")
        if not _safe_relative_filename(source.get("filename")):
            errors.append("sourceArchiveLock filename is unsafe")

    inventory = document.get("basePackageInventory")
    inventory_packages: list[Mapping[str, Any]] = []
    if not isinstance(inventory, Mapping):
        errors.append("bionic Node.js runtime lock basePackageInventory is required")
    else:
        raw_packages = inventory.get("packages")
        if not isinstance(raw_packages, list):
            errors.append("basePackageInventory packages must be an array")
        else:
            inventory_packages = [item for item in raw_packages if isinstance(item, Mapping)]
            if len(inventory_packages) != len(raw_packages):
                errors.append("basePackageInventory packages must contain only objects")
        if inventory.get("count") != BASE_INVENTORY_COUNT or inventory.get("count") != len(raw_packages or []):
            errors.append("basePackageInventory count does not match the reviewed 86-package inventory")
        if inventory.get("sha256") != BASE_INVENTORY_SHA256:
            errors.append("basePackageInventory sha256 does not match the reviewed base inventory")
        elif inventory_packages and inventory_sha256(inventory_packages) != inventory.get("sha256"):
            errors.append("basePackageInventory sha256 does not match its canonical records")
        if inventory.get("unchangedAfterDownloadOnly") is not True:
            errors.append("basePackageInventory must record an unchanged starting inventory")
        names: set[str] = set()
        for index, package in enumerate(inventory_packages):
            name = package.get("name")
            if not isinstance(name, str) or not PACKAGE_NAME_RE.fullmatch(name):
                errors.append(f"basePackageInventory package {index} has an invalid name")
            elif name in names:
                errors.append(f"basePackageInventory contains duplicate package {name}")
            names.add(str(name))
            if package.get("architecture") not in {"aarch64", "all"}:
                errors.append(f"basePackageInventory package {name} has an unsupported architecture")
            if package.get("status") != "install ok installed":
                errors.append(f"basePackageInventory package {name} is not installed")
            for field in ("version", "status"):
                if not isinstance(package.get(field), str) or not package.get(field):
                    errors.append(f"basePackageInventory package {name} is missing {field}")

    raw_records = document.get("packages")
    records: list[Mapping[str, Any]] = []
    if not isinstance(raw_records, list):
        errors.append("bionic Node.js runtime lock packages must be an array")
    else:
        records = [item for item in raw_records if isinstance(item, Mapping)]
        if len(records) != len(raw_records):
            errors.append("bionic Node.js runtime lock packages must contain only objects")
        if len(records) != len(EXPECTED_PACKAGES):
            errors.append("bionic Node.js runtime lock must contain exactly the five reviewed archive rows")

    record_by_name: dict[str, Mapping[str, Any]] = {}
    for index, record in enumerate(records):
        name = record.get("name")
        label = f"package {index}"
        if not isinstance(name, str) or not PACKAGE_NAME_RE.fullmatch(name):
            errors.append(f"{label} has an invalid package name")
            continue
        if name in record_by_name:
            errors.append(f"package identity is duplicated: {name}")
        record_by_name[name] = record
        expected = EXPECTED_PACKAGES.get(name)
        if expected is None:
            errors.append(f"package {name} is not one of the reviewed Node.js closure rows")
            continue
        for field, expected_value in expected.items():
            if record.get(field) != expected_value:
                errors.append(f"package {name} {field} does not match the reviewed archive row")
        for field in ("version", "architecture", "filename", "localFilename", "url"):
            if not isinstance(record.get(field), str) or not record.get(field):
                errors.append(f"package {name} is missing {field}")
        if record.get("architecture") not in {"aarch64", "all"}:
            errors.append(f"package {name} has an unsupported architecture")
        if not isinstance(record.get("sizeBytes"), int) or isinstance(record.get("sizeBytes"), bool) or record.get("sizeBytes", 0) <= 0:
            errors.append(f"package {name} sizeBytes must be a positive integer")
        if not isinstance(record.get("sha256"), str) or not SHA256_RE.fullmatch(str(record.get("sha256"))):
            errors.append(f"package {name} sha256 must be a lowercase SHA-256 digest")
        if not _safe_relative_filename(record.get("filename")) or not _safe_relative_filename(record.get("localFilename")):
            errors.append(f"package {name} filename metadata is unsafe")
        if not _is_clean_https_url(record.get("url")):
            errors.append(f"package {name} url must be a clean HTTPS URL")
        elif not str(record.get("url")).endswith("/" + str(record.get("filename"))):
            errors.append(f"package {name} url must end with its locked filename")
        dependencies = record.get("dependencies")
        if not isinstance(dependencies, Mapping):
            errors.append(f"package {name} dependencies metadata is required")
        else:
            for relation_name, relation_value in dependencies.items():
                if relation_name not in {"Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances", "Breaks", "Conflicts", "Replaces", "Provides"}:
                    errors.append(f"package {name} has unsupported relationship field {relation_name!r}")
                    continue
                _, relation_errors = _relation_names(relation_value, f"package {name} {relation_name}")
                errors.extend(relation_errors)

    if set(record_by_name) != set(EXPECTED_PACKAGES):
        errors.append("bionic Node.js runtime lock package names do not match the reviewed five-package set")

    # Resolve only Depends/Pre-Depends.  Versioned dependency clauses are
    # intentionally a hard boundary because this lock does not embed a Debian
    # version-order implementation; the reviewed closure uses none.
    providers = {str(package.get("name")) for package in inventory_packages}
    providers.update(record_by_name)
    for name, record in record_by_name.items():
        dependencies = record.get("dependencies", {})
        if not isinstance(dependencies, Mapping):
            continue
        for relation_name in ("Pre-Depends", "Depends"):
            if relation_name not in dependencies:
                continue
            clauses, relation_errors = parse_relation_expression(
                dependencies[relation_name], f"package {name} {relation_name}"
            )
            errors.extend(relation_errors)
            if relation_errors:
                continue
            for clause in clauses:
                if any(term["operator"] or term["version"] for term in clause):
                    errors.append(
                        f"package {name} {relation_name} uses versioned dependency syntax; "
                        "the locked resolver rejects it rather than guessing"
                    )
                if not any(term["name"] in providers for term in clause):
                    alternatives = " | ".join(term["name"] for term in clause)
                    errors.append(f"package {name} {relation_name} has no locked provider for {alternatives}")

    resolution = document.get("dependencyResolution")
    if not isinstance(resolution, Mapping):
        errors.append("dependencyResolution metadata is required")
    else:
        if resolution.get("fields") != ["Pre-Depends", "Depends"]:
            errors.append("dependencyResolution must lock the Pre-Depends/Depends fields")
        if resolution.get("unsupportedSyntax") != "reject":
            errors.append("dependencyResolution must reject unsupported dependency syntax")
        expected_names = list(EXPECTED_PACKAGES)
        for field in ("rootPackages", "extractedPackages"):
            values = resolution.get(field)
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                errors.append(f"dependencyResolution {field} must be a string array")
        if resolution.get("rootPackages") != ["nodejs", "npm"]:
            errors.append("dependencyResolution rootPackages must retain nodejs and npm")
        if set(resolution.get("extractedPackages", [])) != set(expected_names):
            errors.append("dependencyResolution extractedPackages must cover every locked archive row")

    execution = document.get("execution")
    if not isinstance(execution, Mapping):
        errors.append("bionic Node.js runtime lock execution metadata is required")
    else:
        expected_execution = {
            "artifactPath": ARTIFACT_PATH,
            "argv": [ARTIFACT_PATH, "--version"],
            "loader": LOADER,
            "shell": TERMUX_SHELL,
            "ldLibraryPath": LD_LIBRARY_PATH,
            "environment": EXECUTION_ENVIRONMENT,
            "outerMode": "outer-path-preserving",
            "pathPolicy": "absolute-dt-runpath-preserved",
            "runpath": NODE_RUNPATH,
            "network": "none",
            "filesystem": "fresh-container-ephemeral-prefix",
            "packageExtraction": "dpkg-deb-extract-only-no-maintainer-scripts",
            "expectedStatus": 0,
            "timeoutSeconds": 30,
            "memoryBytes": 536870912,
            "processLimit": 32,
            "outputBytes": 1048576,
        }
        for field, expected in expected_execution.items():
            if execution.get(field) != expected:
                errors.append(f"execution {field} does not match the locked bionic Node.js policy")

    project = _manifest_project(manifest, "nodejs")
    if project is not None:
        target = project.get("target") if isinstance(project.get("target"), Mapping) else {}
        provenance = project.get("provenance") if isinstance(project.get("provenance"), Mapping) else {}
        host_case = _manifest_bionic_host(manifest)
        comparisons = (
            (target.get("runtime"), RUNTIME, "manifest Node.js runtime"),
            (target.get("loader"), LOADER, "manifest Node.js loader"),
            (provenance.get("version"), NODE_VERSION, "manifest Node.js version"),
            (provenance.get("archivePath"), NODE_ARCHIVE_PATH, "manifest Node.js archivePath"),
            (provenance.get("archiveUrl"), NODE_SOURCE_URL, "manifest Node.js archiveUrl"),
            (provenance.get("artifactPath"), ARTIFACT_PATH.lstrip("/"), "manifest Node.js artifactPath"),
            (provenance.get("archiveSha256"), NODE_ARCHIVE_SHA256, "manifest Node.js archiveSha256"),
            (provenance.get("archiveSizeBytes"), NODE_ARCHIVE_SIZE_BYTES, "manifest Node.js archiveSizeBytes"),
        )
        for actual, expected, label in comparisons:
            if actual != expected:
                errors.append(f"{label} does not match the bionic Node.js runtime lock")
        if isinstance(host_case, Mapping) and host_case.get("image") != IMAGE_REF:
            errors.append("fixture bionic image does not match the Node.js runtime lock")
        if isinstance(host_case, Mapping) and host_case.get("packageRepository") != PACKAGE_REPOSITORY:
            errors.append("fixture bionic package repository does not match the Node.js runtime lock")
        execution_policy = project.get("executionPolicy") if isinstance(project.get("executionPolicy"), Mapping) else {}
        isolation_policy = execution_policy.get("isolation") if isinstance(execution_policy.get("isolation"), Mapping) else {}
        expected_status = execution.get("expectedStatus") if isinstance(execution, Mapping) else None
        for layer in ("baseline", "outerWrapper"):
            layer_policy = execution_policy.get(layer) if isinstance(execution_policy.get(layer), Mapping) else {}
            if layer_policy.get("expectedStatus") != expected_status:
                errors.append(f"manifest Node.js {layer} expectedStatus does not match the runtime lock")
        expected_limits = {
            "timeoutSeconds": execution.get("timeoutSeconds") if isinstance(execution, Mapping) else None,
            "memoryBytes": execution.get("memoryBytes") if isinstance(execution, Mapping) else None,
            "processLimit": execution.get("processLimit") if isinstance(execution, Mapping) else None,
            "outputBytes": execution.get("outputBytes") if isinstance(execution, Mapping) else None,
        }
        for field, expected in expected_limits.items():
            if isolation_policy.get(field) != expected:
                errors.append(f"manifest Node.js isolation {field} does not match the runtime lock")
        outer_policy = execution_policy.get("outerWrapper") if isinstance(execution_policy.get("outerWrapper"), Mapping) else {}
        locked_outer_mode = execution.get("outerMode") if isinstance(execution, Mapping) else None
        if outer_policy.get("mode") != locked_outer_mode:
            errors.append("manifest Node.js outerWrapper mode does not match the runtime lock")

    return errors


def _manifest_bionic_host(manifest: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if not isinstance(manifest, Mapping):
        return None
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        return None
    for case in cases:
        if isinstance(case, Mapping) and case.get("id") == "c-termux-bionic-pie":
            value = case.get("host")
            return value if isinstance(value, Mapping) else None
    return None


def load_lock(path: Path, *, manifest: Mapping[str, Any] | None = None, expected_lock_sha256: str | None = None) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LockValidationError(f"could not read bionic Node.js runtime lock: {error}") from error
    errors = validate_lock_document(document, manifest=manifest, expected_lock_sha256=expected_lock_sha256)
    if errors:
        raise LockValidationError("; ".join(errors))
    return dict(document)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    manifest_value: Mapping[str, Any] | None = None
    if args.manifest is not None:
        manifest_value = json.loads(args.manifest.read_text(encoding="utf-8"))
    lock_value = json.loads(args.lock.read_text(encoding="utf-8"))
    validation_errors = validate_lock_document(
        lock_value,
        manifest=manifest_value,
        expected_lock_sha256=args.expected_sha256,
    )
    if validation_errors:
        raise SystemExit("\n".join(validation_errors))
    print(f"PASS bionic Node.js runtime lock: {args.lock}")
