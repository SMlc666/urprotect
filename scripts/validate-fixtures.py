#!/usr/bin/env python3
"""Validate and select the feature-covering AArch64 fixture matrix."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


TIERS = {"pr": 0, "nightly": 1, "release": 2}
STATUSES = {"proven", "validated", "rejected", "unknown"}
CASE_FIELDS = {
    "id",
    "features",
    "language",
    "toolchain",
    "builder",
    "runtime",
    "target",
    "artifact",
    "source",
    "tier",
    "required",
    "execution",
    "oracle",
    "evidence",
}
FEATURE_FIELDS = {"id", "status", "obligation", "witness", "oracle", "evidence"}
EXECUTIONS = {
    "native-linux",
    "android-arm64-native-bridge-on-x64",
    "native-arm64-bionic-container",
}
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> "None":
    raise SystemExit(message)


def parse_options(argv: list[str]) -> tuple[Path, str, bool]:
    if len(argv) < 2:
        fail("usage: validate-fixtures.py MANIFEST --tier <pr|nightly|release> [--emit]")

    manifest_path = Path(argv[1])
    requested = "pr"
    emit = False
    index = 2
    while index < len(argv):
        argument = argv[index]
        if argument == "--emit":
            emit = True
        elif argument == "--tier":
            index += 1
            if index >= len(argv):
                fail("--tier requires a value")
            requested = argv[index]
        elif argument.startswith("--tier="):
            requested = argument.split("=", 1)[1]
        else:
            fail(f"unsupported argument: {argument}")
        index += 1

    if requested not in TIERS:
        fail(f"unsupported fixture tier: {requested}")
    return manifest_path, requested, emit


def require_text(record: dict[str, object], field: str, label: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        fail(f"{label}.{field} must be a non-empty string")
    return value


def require_text_list(record: dict[str, object], field: str, label: str) -> list[str]:
    value = record.get(field)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        fail(f"{label}.{field} must be a non-empty string array")
    return value


def validate_id(value: object, label: str, ids: set[str]) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value) or value in ids:
        fail(f"{label} must be a unique non-empty identifier: {value!r}")
    ids.add(value)
    return value


def validate_reference(value: object, label: str, repo_root: Path, case_ids: set[str]) -> None:
    reference = require_text({"value": value}, "value", label)
    if reference in case_ids:
        return
    path = (repo_root / Path(reference)).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError:
        fail(f"{label} must remain inside the repository: {reference}")
    if not path.exists():
        fail(f"{label} does not exist and is not a matrix case: {reference}")


def validate_evidence_reference(value: object, label: str, repo_root: Path) -> None:
    reference = require_text({"value": value}, "value", label)
    path = (repo_root / Path(reference)).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError:
        fail(f"{label} must remain inside the repository: {reference}")
    # CI artifacts are created by the selected runner after manifest validation.
    if path.exists() or Path(reference).parts[:1] == (".artifacts",):
        return
    fail(f"{label} does not exist or is not a generated artifact path: {reference}")


def validate_android(android: object) -> None:
    if not isinstance(android, dict):
        fail("fixture manifest must contain an android object")
    container = android.get("container")
    if not isinstance(container, dict):
        fail("fixture manifest android.container must be an object")
    for field in (
        "environment",
        "systemImageUrl",
        "systemImageSha256",
        "vendorImageUrl",
        "vendorImageSha256",
    ):
        require_text(container, field, "fixture manifest android.container")
    for field in ("systemImageSha256", "vendorImageSha256"):
        value = container[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            fail(f"fixture manifest android.container.{field} must be a lowercase SHA-256")


def validate_features(data: dict[str, object]) -> dict[str, str]:
    features = data.get("features")
    if not isinstance(features, list) or not features:
        fail("fixture manifest must contain a non-empty features array")

    statuses: dict[str, str] = {}
    ids: set[str] = set()
    for feature in features:
        if not isinstance(feature, dict):
            fail("each matrix feature must be an object")
        feature_id = validate_id(feature.get("id"), "feature id", ids)
        missing = FEATURE_FIELDS - feature.keys()
        if missing:
            fail(f"{feature_id} missing fields: {sorted(missing)}")
        status = require_text(feature, "status", feature_id)
        if status not in STATUSES:
            fail(f"{feature_id} has unsupported status {status!r}")
        require_text(feature, "obligation", feature_id)
        require_text(feature, "witness", feature_id)
        require_text(feature, "oracle", feature_id)
        require_text_list(feature, "evidence", feature_id)
        if status == "unknown":
            require_text(feature, "nextEvidence", feature_id)
        if status == "rejected":
            require_text(feature, "reason", feature_id)
            require_text(feature, "negativeWitness", feature_id)
            require_text(feature, "negativeOracle", feature_id)
        statuses[feature_id] = status
    return statuses


def validate_case(
    case: object,
    feature_statuses: dict[str, str],
    repo_root: Path,
    ids: set[str],
    requested: str,
) -> dict[str, object]:
    if not isinstance(case, dict):
        fail("each matrix case must be an object")
    case_id = validate_id(case.get("id"), "case id", ids)
    missing = CASE_FIELDS - case.keys()
    if missing:
        fail(f"{case_id} missing fields: {sorted(missing)}")

    features = case["features"]
    if (
        not isinstance(features, list)
        or not features
        or any(not isinstance(feature, str) for feature in features)
    ):
        fail(f"{case_id}.features must be a non-empty string array")
    if len(set(features)) != len(features):
        fail(f"{case_id}.features must not contain duplicate feature identifiers")
    missing_features = set(features) - feature_statuses.keys()
    if missing_features:
        fail(f"{case_id} references unknown features: {sorted(missing_features)}")

    tier = require_text(case, "tier", case_id)
    if tier not in TIERS:
        fail(f"{case_id} has unsupported tier {tier!r}")
    variant = case.get("variant")
    if variant is not None and variant != "release-hardened":
        fail(f"{case_id}.variant is unsupported: {variant!r}")
    if tier == "release" and variant != "release-hardened":
        fail(f"{case_id} release cases must declare the release-hardened variant")
    if tier != "release" and variant is not None:
        fail(f"{case_id}.variant is reserved for release cases")
    if not isinstance(case["required"], bool):
        fail(f"{case_id}.required must be boolean")
    if case["required"]:
        unsupported_features = {
            feature: feature_statuses[feature]
            for feature in features
            if feature_statuses[feature] in {"rejected", "unknown"}
        }
        if unsupported_features:
            fail(
                f"{case_id} is required but references non-supporting features: "
                f"{unsupported_features}"
            )
    execution = require_text(case, "execution", case_id)
    if execution not in EXECUTIONS:
        fail(f"{case_id} has unsupported execution {execution!r}")
    require_text(case, "runtime", case_id)
    require_text(case, "builder", case_id)
    require_text(case, "source", case_id)
    require_text(case, "oracle", case_id)
    require_text(case, "evidence", case_id)
    host = case.get("host")
    if not isinstance(host, dict):
        fail(f"{case_id}.host must be an object")
    source = (repo_root / Path(case["source"])).resolve()
    try:
        source.relative_to(repo_root)
    except ValueError:
        fail(f"{case_id}.source must remain inside the repository")
    if not source.exists():
        fail(f"{case_id}.source does not exist: {source}")

    if execution == "native-arm64-bionic-container":
        image = host.get("image")
        source_commit = host.get("sourceCommit")
        compiler_package = host.get("compilerPackage")
        linker = host.get("linker")
        if not isinstance(image, str) or not SHA256_PATTERN.fullmatch(image.split("@")[-1]):
            fail(f"{case_id}.host.image must contain a pinned sha256 digest")
        if not isinstance(source_commit, str) or not COMMIT_PATTERN.fullmatch(source_commit):
            fail(f"{case_id}.host.sourceCommit must be a 40-character lowercase commit")
        if compiler_package != "clang=21.1.8-3":
            fail(f"{case_id}.host.compilerPackage must pin clang=21.1.8-3")
        package_repository = host.get("packageRepository")
        if package_repository != "https://packages-cf.termux.dev/apt/termux-main":
            fail(f"{case_id}.host.packageRepository must identify the pinned Termux package source")
        compiler_packages = host.get("compilerPackages")
        if not isinstance(compiler_packages, list) or not compiler_packages:
            fail(f"{case_id}.host.compilerPackages must be a non-empty locked package array")
        locked_versions: dict[str, str] = {}
        locked_filenames: set[str] = set()
        for package_index, package in enumerate(compiler_packages):
            package_label = f"{case_id}.host.compilerPackages[{package_index}]"
            if not isinstance(package, dict):
                fail(f"{package_label} must be an object")
            name = package.get("name")
            version = package.get("version")
            filename = package.get("filename")
            digest = package.get("sha256")
            licenses = package.get("licenses")
            license_source = package.get("licenseSource")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+.-]*", name):
                fail(f"{package_label}.name must be a valid package name")
            if name in locked_versions:
                fail(f"{case_id}.host.compilerPackages contains duplicate package {name!r}")
            if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9.+:~_-]+", version):
                fail(f"{package_label}.version must be an exact package version")
            if not isinstance(filename, str) or not filename.startswith("pool/") or ".." in filename.split("/"):
                fail(f"{package_label}.filename must be a repository-relative pool path")
            if not filename.endswith("_aarch64.deb") or filename in locked_filenames:
                fail(f"{package_label}.filename must be a unique AArch64 Debian package")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                fail(f"{package_label}.sha256 must be a lowercase SHA-256 digest")
            if not isinstance(licenses, list) or not licenses or any(
                not isinstance(license_id, str) or not license_id.strip()
                for license_id in licenses
            ):
                fail(f"{package_label}.licenses must be a non-empty license identifier array")
            if not isinstance(license_source, str) or not license_source.strip():
                fail(f"{package_label}.licenseSource must identify its license record source")
            locked_versions[name] = version
            locked_filenames.add(filename)
        expected_compiler_packages = {
            "clang",
            "libcompiler-rt",
            "libllvm",
            "libxml2",
            "lld",
            "llvm",
            "ndk-sysroot",
        }
        if set(locked_versions) != expected_compiler_packages:
            fail(f"{case_id}.host.compilerPackages must lock the exact compiler dependency set")
        if locked_versions.get("clang") != compiler_package.split("=", 1)[1]:
            fail(f"{case_id}.host.compilerPackages clang version must match compilerPackage")
        if linker != "/system/bin/linker64":
            fail(f"{case_id}.host.linker must be /system/bin/linker64")
        if host.get("environment") != "termux-userspace" or host.get("androidRuntime") is not False:
            fail(f"{case_id}.host must identify a non-Android Termux userspace")
        if host.get("pageSize") != "recorded":
            fail(f"{case_id}.host.pageSize must be recorded")
        if host.get("architecture") != "aarch64":
            fail(f"{case_id}.host.architecture must be aarch64")
        if host.get("kernel") != "recorded":
            fail(f"{case_id}.host.kernel must be recorded")
        if host.get("packageIndex") != "live":
            fail(f"{case_id}.host.packageIndex must identify the package index used for lookup")
        if host.get("packageInputsReproducible") is not True:
            fail(f"{case_id}.host.packageInputsReproducible must be true for the exact version/SHA-256 package lock")
        if host.get("packageProvenance") != "version-and-sha256-locked-package-set":
            fail(f"{case_id}.host.packageProvenance must identify the exact package lock contract")
    elif execution == "native-linux":
        if host.get("environment") != "native-arm64-linux":
            fail(f"{case_id}.host.environment must identify native ARM64 Linux")

    if TIERS[tier] <= TIERS[requested]:
        return case
    return {}


def main() -> int:
    manifest_path, requested, emit = parse_options(sys.argv)
    try:
        data = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"could not read fixture manifest: {error}")
    if not isinstance(data, dict):
        fail("fixture manifest root must be an object")
    if data.get("schemaVersion") != 3:
        fail("fixture manifest schemaVersion must be 3")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("strategy") != "feature-covering":
        fail("fixture manifest coverage.strategy must be feature-covering")
    rules = coverage.get("rules")
    if not isinstance(rules, list) or not rules or any(
        not isinstance(rule, str) or not rule for rule in rules
    ):
        fail("fixture manifest coverage.rules must be a non-empty string array")
    host_contract = data.get("hostContract")
    if not isinstance(host_contract, dict) or host_contract.get("id") != "urp-host-v1":
        fail("fixture manifest hostContract must identify urp-host-v1")
    if host_contract.get("version") != 1:
        fail("fixture manifest hostContract version must be 1")
    validate_android(data.get("android"))
    feature_statuses = validate_features(data)
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        fail("fixture manifest must contain a non-empty cases array")

    repo_root = manifest_path.parent.parent.resolve()
    ids: set[str] = set()
    selected: list[dict[str, object]] = []
    for case in cases:
        selected_case = validate_case(
            case,
            feature_statuses,
            repo_root,
            ids,
            requested,
        )
        if selected_case:
            selected.append(selected_case)

    case_ids = ids
    for feature in data["features"]:
        feature_id = str(feature["id"])
        validate_reference(feature["witness"], f"{feature_id}.witness", repo_root, case_ids)
        validate_reference(feature["oracle"], f"{feature_id}.oracle", repo_root, case_ids)
        for index, evidence in enumerate(feature["evidence"]):
            validate_evidence_reference(evidence, f"{feature_id}.evidence[{index}]", repo_root)
        if "negativeWitness" in feature:
            validate_reference(
                feature["negativeWitness"],
                f"{feature_id}.negativeWitness",
                repo_root,
                case_ids,
            )
        if "negativeOracle" in feature:
            validate_reference(
                feature["negativeOracle"],
                f"{feature_id}.negativeOracle",
                repo_root,
                case_ids,
            )

    for case in cases:
        case_id = str(case["id"])
        validate_reference(case["oracle"], f"{case_id}.oracle", repo_root, case_ids)
        validate_evidence_reference(case["evidence"], f"{case_id}.evidence", repo_root)

    if not any(case.get("tier") == "pr" for case in cases if isinstance(case, dict)):
        fail("fixture manifest must contain at least one PR case")

    summary = f"validated fixture matrix: {len(cases)} cases; requested tier={requested}"
    print(summary, file=sys.stderr if emit else sys.stdout)
    if emit:
        for case in selected:
            print(json.dumps(case, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
