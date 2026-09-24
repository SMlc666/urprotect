#!/usr/bin/env python3
"""Validate the metadata-only public AArch64 real-sample registry.

This validator deliberately has no network, archive, ELF, or process-execution
capability.  It checks the checked-in contract before a CI job is allowed to
acquire anything.  The selected registry and the candidate ledger share the
same provenance vocabulary so a selection cannot silently change its source.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


TIERS = ("pr", "nightly", "release")
RUNTIMES = {"glibc", "musl", "bionic"}
LAYERS = ("static", "baseline", "outerWrapper", "hostContext")
RESULTS = {
    "accepted-and-runs",
    "expected-rejected",
    "unexpected-rejection",
    "unexpected-acceptance",
    "runtime-failure",
    "environment-unavailable",
    "not-applicable",
}
ARCHIVE_FORMATS = {"deb", "tar.gz", "tar", "zip", "apk"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,79}$")


class ValidationError(Exception):
    """A registry contract violation."""


class Validator:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, location: str, message: str) -> None:
        self.errors.append(f"{location}: {message}")

    def require(self, condition: bool, location: str, message: str) -> None:
        if not condition:
            self.error(location, message)

    def string(
        self,
        value: Any,
        location: str,
        *,
        non_empty: bool = True,
    ) -> str | None:
        if not isinstance(value, str):
            self.error(location, "must be a string")
            return None
        if non_empty and not value.strip():
            self.error(location, "must not be empty")
            return None
        return value

    def mapping(self, value: Any, location: str) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            self.error(location, "must be an object")
            return None
        return value

    def sequence(self, value: Any, location: str) -> list[Any] | None:
        if not isinstance(value, list):
            self.error(location, "must be an array")
            return None
        return value

    def boolean(self, value: Any, location: str) -> bool | None:
        if not isinstance(value, bool):
            self.error(location, "must be a boolean")
            return None
        return value


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValidationError(f"{label} does not exist: {path}") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"could not read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{label} root must be an object")
    return value


def validate_url(validator: Validator, value: Any, location: str) -> None:
    parsed = urlparse(value) if isinstance(value, str) else None
    validator.require(
        parsed is not None and parsed.scheme == "https" and bool(parsed.netloc),
        location,
        "must be an absolute HTTPS URL",
    )
    if parsed is not None and ("\n" in value or "\r" in value or "\x00" in value):
        validator.error(location, "must not contain control characters")


def validate_relative_path(
    validator: Validator, value: Any, location: str, *, allow_empty: bool = False
) -> None:
    path = validator.string(value, location, non_empty=not allow_empty)
    if path is None:
        return
    if "\x00" in path or "\n" in path or "\r" in path:
        validator.error(location, "must not contain control characters")
        return
    path_obj = Path(path)
    parts = path.replace("\\", "/").split("/")
    validator.require(not path_obj.is_absolute(), location, "must be repository/archive relative")
    validator.require(not path.startswith("/"), location, "must not start with '/'")
    validator.require(".." not in parts, location, "must not contain '..'")
    validator.require(path not in {".", ""}, location, "must identify a file")


def validate_hash(validator: Validator, value: Any, location: str) -> None:
    validator.require(
        isinstance(value, str) and HEX64.fullmatch(value) is not None,
        location,
        "must be a lowercase SHA-256 hexadecimal digest",
    )


def validate_provenance(
    validator: Validator,
    project: dict[str, Any],
    location: str,
) -> tuple[str | None, str | None, str | None, str | None]:
    provenance = validator.mapping(project.get("provenance"), f"{location}.provenance")
    if provenance is None:
        return None, None, None, None

    source_kind = validator.string(provenance.get("sourceKind"), f"{location}.provenance.sourceKind")
    archive_url = provenance.get("archiveUrl")
    validate_url(validator, archive_url, f"{location}.provenance.archiveUrl")
    version = validator.string(provenance.get("version"), f"{location}.provenance.version")
    archive_path = validator.string(
        provenance.get("archivePath"), f"{location}.provenance.archivePath"
    )
    validate_relative_path(validator, archive_path, f"{location}.provenance.archivePath")
    archive_sha = provenance.get("archiveSha256")
    validate_hash(validator, archive_sha, f"{location}.provenance.archiveSha256")
    artifact_path = provenance.get("artifactPath")
    validate_relative_path(validator, artifact_path, f"{location}.provenance.artifactPath")
    artifact_sha = provenance.get("artifactSha256")
    if artifact_sha is not None:
        validate_hash(validator, artifact_sha, f"{location}.provenance.artifactSha256")
    archive_format = validator.string(
        provenance.get("archiveFormat"), f"{location}.provenance.archiveFormat"
    )
    if archive_format is not None:
        validator.require(
            archive_format in ARCHIVE_FORMATS,
            f"{location}.provenance.archiveFormat",
            f"must be one of {sorted(ARCHIVE_FORMATS)}",
        )
    validator.string(provenance.get("license"), f"{location}.provenance.license")
    validator.string(
        provenance.get("redistribution"), f"{location}.provenance.redistribution"
    )
    validator.string(
        provenance.get("licenseSource"), f"{location}.provenance.licenseSource"
    )

    if isinstance(archive_url, str) and isinstance(archive_path, str):
        # The path is intentionally recorded separately for review.  Require
        # its final component to occur in the URL, while allowing mirrors and
        # URL-escaped package names.
        url_path = urlparse(archive_url).path
        validator.require(
            url_path.rstrip("/").endswith(archive_path.rstrip("/"))
            or url_path.rstrip("/").endswith(Path(archive_path).name),
            f"{location}.provenance.archivePath",
            "must identify the artifact named by archiveUrl",
        )

    return source_kind, version, archive_sha if isinstance(archive_sha, str) else None, artifact_path if isinstance(artifact_path, str) else None


def validate_target(validator: Validator, project: dict[str, Any], location: str) -> str | None:
    target = validator.mapping(project.get("target"), f"{location}.target")
    if target is None:
        return None
    architecture = validator.string(target.get("architecture"), f"{location}.target.architecture")
    validator.require(
        architecture == "aarch64",
        f"{location}.target.architecture",
        "must be aarch64",
    )
    validator.string(target.get("os"), f"{location}.target.os")
    runtime = validator.string(target.get("runtime"), f"{location}.target.runtime")
    if runtime is not None:
        validator.require(runtime in RUNTIMES, f"{location}.target.runtime", f"must be one of {sorted(RUNTIMES)}")
    validator.string(target.get("loader"), f"{location}.target.loader")
    validator.string(target.get("artifactKind"), f"{location}.target.artifactKind")
    page_size = target.get("pageSize")
    if page_size is not None:
        validator.require(
            isinstance(page_size, int) and page_size > 0,
            f"{location}.target.pageSize",
            "must be a positive integer when present",
        )
    return runtime if isinstance(runtime, str) else None


def validate_fingerprint(validator: Validator, project: dict[str, Any], location: str) -> None:
    fingerprint = validator.mapping(
        project.get("featureFingerprint"), f"{location}.featureFingerprint"
    )
    if fingerprint is None:
        return
    required = {
        "producer",
        "elfClass",
        "data",
        "machine",
        "type",
        "interpreter",
        "ptLoadLayout",
        "dynamicNeeded",
        "relocations",
        "symbolVersions",
        "tls",
        "gnuProperty",
        "relro",
        "gnuStack",
        "stripped",
        "fileSizeBytes",
        "featureTags",
    }
    for key in required:
        if key not in fingerprint:
            validator.error(f"{location}.featureFingerprint.{key}", "is required")
    for key in ("tls", "gnuProperty", "relro", "stripped"):
        if key in fingerprint:
            value = fingerprint[key]
            if isinstance(value, dict) and value.get("source") == "ci-generated":
                continue
            validator.boolean(value, f"{location}.featureFingerprint.{key}")
    if "fileSizeBytes" in fingerprint:
        value = fingerprint["fileSizeBytes"]
        validator.require(
            (isinstance(value, int) and not isinstance(value, bool) and value > 0)
            or value == "ci-generated",
            f"{location}.featureFingerprint.fileSizeBytes",
            "must be a positive integer or ci-generated",
        )
    for key in ("dynamicNeeded", "featureTags"):
        values = validator.sequence(fingerprint.get(key), f"{location}.featureFingerprint.{key}")
        if values is not None:
            for index, value in enumerate(values):
                validator.string(value, f"{location}.featureFingerprint.{key}[{index}]")
    validator.mapping(fingerprint.get("ptLoadLayout"), f"{location}.featureFingerprint.ptLoadLayout")
    validator.mapping(fingerprint.get("relocations"), f"{location}.featureFingerprint.relocations")
    expected_tags = fingerprint.get("expectedFeatureTags")
    if expected_tags is not None:
        values = validator.sequence(expected_tags, f"{location}.featureFingerprint.expectedFeatureTags")
        if values is not None:
            for index, value in enumerate(values):
                validator.string(value, f"{location}.featureFingerprint.expectedFeatureTags[{index}]")


def validate_selection(validator: Validator, project: dict[str, Any], location: str) -> None:
    selection = validator.mapping(project.get("selection"), f"{location}.selection")
    if selection is None:
        return
    validator.string(selection.get("rationale"), f"{location}.selection.rationale")
    coverage = validator.sequence(selection.get("featureCoverage"), f"{location}.selection.featureCoverage")
    if coverage is not None:
        validator.require(bool(coverage), f"{location}.selection.featureCoverage", "must not be empty")
        for index, value in enumerate(coverage):
            validator.string(value, f"{location}.selection.featureCoverage[{index}]")
    distinct = validator.sequence(selection.get("distinctFrom"), f"{location}.selection.distinctFrom")
    if distinct is not None:
        for index, value in enumerate(distinct):
            validator.string(value, f"{location}.selection.distinctFrom[{index}]")


def validate_fingerprint_policy(validator: Validator, project: dict[str, Any], location: str) -> None:
    policy = validator.mapping(project.get("fingerprintPolicy"), f"{location}.fingerprintPolicy")
    if policy is None:
        return
    mode = validator.string(policy.get("mode"), f"{location}.fingerprintPolicy.mode")
    validator.require(mode == "ci-discovery-lock", f"{location}.fingerprintPolicy.mode", "must be ci-discovery-lock")
    compare = validator.sequence(policy.get("compare"), f"{location}.fingerprintPolicy.compare")
    if compare is not None:
        required = {"elfClass", "data", "machine", "type", "interpreter"}
        values = {value for value in compare if isinstance(value, str)}
        validator.require(required.issubset(values), f"{location}.fingerprintPolicy.compare", "must compare ELF class, data, machine, type, and interpreter")
    validator.string(policy.get("featureTags"), f"{location}.fingerprintPolicy.featureTags")
    validator.string(policy.get("source"), f"{location}.fingerprintPolicy.source")


def validate_policy(validator: Validator, project: dict[str, Any], location: str) -> None:
    policy = validator.mapping(project.get("executionPolicy"), f"{location}.executionPolicy")
    if policy is None:
        return
    for layer in LAYERS:
        layer_location = f"{location}.executionPolicy.{layer}"
        layer_policy = validator.mapping(policy.get(layer), layer_location)
        if layer_policy is None:
            continue
        applicable = validator.boolean(layer_policy.get("applicable"), f"{layer_location}.applicable")
        expected = validator.string(layer_policy.get("expectedResult"), f"{layer_location}.expectedResult")
        if expected is not None:
            validator.require(expected in RESULTS, f"{layer_location}.expectedResult", f"must be one of {sorted(RESULTS)}")
        if applicable is False:
            validator.require(
                expected == "not-applicable",
                f"{layer_location}.expectedResult",
                "must be not-applicable when applicable is false",
            )
            validator.string(layer_policy.get("reason"), f"{layer_location}.reason")
        elif applicable is True:
            validator.require(
                expected != "not-applicable",
                f"{layer_location}.expectedResult",
                "must be an applicable result when applicable is true",
            )
            if layer == "static":
                validator.boolean(layer_policy.get("required"), f"{layer_location}.required")
    isolation = validator.mapping(policy.get("isolation"), f"{location}.executionPolicy.isolation")
    if isolation is not None:
        for key in ("network", "filesystem", "privileges", "cleanup"):
            validator.string(isolation.get(key), f"{location}.executionPolicy.isolation.{key}")
        for key in ("timeoutSeconds", "memoryBytes", "processLimit", "outputBytes"):
            value = isolation.get(key)
            validator.require(
                isinstance(value, int) and value > 0,
                f"{location}.executionPolicy.isolation.{key}",
                "must be a positive integer",
            )
        validator.require(
            isolation.get("network") == "none",
            f"{location}.executionPolicy.isolation.network",
            "must be none",
        )
        validator.require(
            isolation.get("filesystem") in {"read-only-inputs", "read-only-rootfs-temp-output"},
            f"{location}.executionPolicy.isolation.filesystem",
            "must describe read-only inputs and bounded temporary output",
        )

    tiers = validator.sequence(project.get("tiers"), f"{location}.tiers")
    if tiers is not None:
        values = {value for value in tiers if isinstance(value, str)}
        validator.require(values == set(TIERS), f"{location}.tiers", "must include exactly pr, nightly, and release")

    expected_results = project.get("expectedResults")
    if expected_results is not None:
        expected_map = validator.mapping(expected_results, f"{location}.expectedResults")
        if expected_map is not None:
            for layer in LAYERS:
                validator.require(
                    expected_map.get(layer) == (policy.get(layer) or {}).get("expectedResult"),
                    f"{location}.expectedResults.{layer}",
                    "must match executionPolicy.expectedResult",
                )


def validate_variants(validator: Validator, project: dict[str, Any], location: str) -> None:
    variants = project.get("variants", [])
    values = validator.sequence(variants, f"{location}.variants")
    if values is None:
        return
    seen: set[str] = set()
    for index, value in enumerate(values):
        variant_location = f"{location}.variants[{index}]"
        variant = validator.mapping(value, variant_location)
        if variant is None:
            continue
        variant_id = validator.string(variant.get("variantId"), f"{variant_location}.variantId")
        if variant_id is not None:
            validator.require(variant_id not in seen, f"{variant_location}.variantId", "must be unique within a project")
            seen.add(variant_id)
        validator.string(variant.get("kind"), f"{variant_location}.kind")
        validator.string(variant.get("runtime"), f"{variant_location}.runtime")
        validator.string(variant.get("reason"), f"{variant_location}.reason")
        # A variant is metadata, not a hidden second project.  If it carries a
        # source, it must use the same provenance shape as the primary record.
        if "provenance" in variant:
            validate_provenance(validator, variant, variant_location)


def validate_project(validator: Validator, project: Any, index: int, *, selected: bool) -> tuple[str | None, str | None]:
    location = f"projects[{index}]"
    value = validator.mapping(project, location)
    if value is None:
        return None, None
    project_id = validator.string(value.get("projectId"), f"{location}.projectId")
    if project_id is not None:
        validator.require(PROJECT_ID.fullmatch(project_id) is not None, f"{location}.projectId", "must be lowercase kebab/dot identifier")
    validator.string(value.get("displayName"), f"{location}.displayName")
    identity = validator.string(value.get("identityKey"), f"{location}.identityKey")
    validate_url(validator, value.get("upstreamUrl"), f"{location}.upstreamUrl")
    validate_provenance(validator, value, location)
    runtime = validate_target(validator, value, location)
    validate_fingerprint(validator, value, location)
    validate_selection(validator, value, location)
    if selected:
        validate_policy(validator, value, location)
        validate_fingerprint_policy(validator, value, location)
    return project_id, identity


def validate_candidates(validator: Validator, data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validator.require(data.get("schemaVersion") == 1, "candidates.schemaVersion", "must be 1")
    validator.string(data.get("discoveryPolicy"), "candidates.discoveryPolicy")
    candidates = validator.sequence(data.get("candidates"), "candidates.candidates")
    result: dict[str, dict[str, Any]] = {}
    if candidates is None:
        return result
    validator.require(len(candidates) >= 20, "candidates.candidates", "must retain at least the locked corpus size")
    for index, candidate in enumerate(candidates):
        location = f"candidates.candidates[{index}]"
        value = validator.mapping(candidate, location)
        if value is None:
            continue
        project_id, identity = validate_project(validator, value, index, selected=False)
        if project_id is not None:
            validator.require(project_id not in result, f"{location}.projectId", "must be unique")
            result[project_id] = value
        disposition = validator.string(value.get("disposition"), f"{location}.disposition")
        if disposition is not None:
            validator.require(disposition in {"selected", "rejected", "deferred"}, f"{location}.disposition", "must be selected, rejected, or deferred")
        validator.string(value.get("dispositionReason"), f"{location}.dispositionReason")
        if disposition in {"rejected", "deferred"}:
            validator.require(bool(value.get("dispositionReason")), f"{location}.dispositionReason", "is required for rejected/deferred candidates")
        if identity is not None:
            validator.require(identity.strip() != "", f"{location}.identityKey", "must identify one upstream project")
    return result


def validate_registry(
    manifest: dict[str, Any], candidates: dict[str, dict[str, Any]] | None
) -> tuple[Validator, list[dict[str, Any]]]:
    validator = Validator()
    validator.require(manifest.get("schemaVersion") == 1, "manifest.schemaVersion", "must be 1")
    validator.string(manifest.get("registryName"), "manifest.registryName")
    corpus = validator.mapping(manifest.get("corpus"), "manifest.corpus")
    if corpus is None:
        return validator, []
    count = corpus.get("requiredProjectCount")
    validator.require(count == 20, "manifest.corpus.requiredProjectCount", "must be exactly 20")
    validator.string(corpus.get("selectionPolicy"), "manifest.corpus.selectionPolicy")
    tiers = validator.sequence(corpus.get("tiers"), "manifest.corpus.tiers")
    if tiers is not None:
        validator.require({value for value in tiers if isinstance(value, str)} == set(TIERS), "manifest.corpus.tiers", "must include exactly pr, nightly, and release")
    projects = validator.sequence(corpus.get("projects"), "manifest.corpus.projects")
    if projects is None:
        return validator, []
    validator.require(len(projects) == 20, "manifest.corpus.projects", "must contain exactly 20 project records")
    seen_ids: set[str] = set()
    seen_identities: set[str] = set()
    runtimes: set[str] = set()
    for index, project in enumerate(projects):
        project_id, identity = validate_project(validator, project, index, selected=True)
        if project_id is not None:
            validator.require(project_id not in seen_ids, f"manifest.corpus.projects[{index}].projectId", "must be unique; variants do not add project count")
            seen_ids.add(project_id)
            if candidates is not None:
                candidate = candidates.get(project_id)
                validator.require(candidate is not None, f"manifest.corpus.projects[{index}].projectId", "must be present in candidates.json")
                if candidate is not None:
                    validator.require(candidate.get("disposition") == "selected", f"manifest.corpus.projects[{index}].projectId", "candidate disposition must be selected")
                    validator.require(candidate.get("identityKey") == identity, f"manifest.corpus.projects[{index}].identityKey", "must match candidate identityKey")
                    selected_prov = project.get("provenance")
                    candidate_prov = candidate.get("provenance")
                    if isinstance(selected_prov, dict) and isinstance(candidate_prov, dict):
                        validator.require(selected_prov.get("archiveSha256") == candidate_prov.get("archiveSha256"), f"manifest.corpus.projects[{index}].provenance.archiveSha256", "must match candidate ledger")
            if identity is not None:
                normalized_identity = identity.casefold()
                validator.require(normalized_identity not in seen_identities, f"manifest.corpus.projects[{index}].identityKey", "must identify a distinct upstream project")
                seen_identities.add(normalized_identity)
        target = project.get("target") if isinstance(project, dict) else None
        if isinstance(target, dict) and isinstance(target.get("runtime"), str):
            runtimes.add(target["runtime"])
        validate_variants(validator, project if isinstance(project, dict) else {}, f"manifest.corpus.projects[{index}]")
    validator.require(RUNTIMES.issubset(runtimes), "manifest.corpus.projects", "must cover glibc, musl, and bionic runtimes")
    return validator, [project for project in projects if isinstance(project, dict)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=Path("fixtures/real-samples/manifest.json"),
        help="selected 20-project registry",
    )
    parser.add_argument(
        "--candidates",
        type=Path,
        help="candidate ledger to cross-check (metadata only)",
    )
    parser.add_argument(
        "--tier",
        choices=TIERS,
        help="validate that a tier is declared; all tiers remain locked to the same 20 projects",
    )
    parser.add_argument(
        "--emit",
        action="store_true",
        help="emit one compact project JSON object per line after validation",
    )
    parser.add_argument("--summary", action="store_true", help="print a compact validation summary")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        manifest = read_json(arguments.manifest, "manifest")
        candidates_data = None
        candidates: dict[str, dict[str, Any]] | None = None
        if arguments.candidates is not None:
            candidates_data = read_json(arguments.candidates, "candidate ledger")
            candidate_validator = Validator()
            candidates = validate_candidates(candidate_validator, candidates_data)
            if candidate_validator.errors:
                raise ValidationError("candidate ledger validation failed:\n  " + "\n  ".join(candidate_validator.errors))
        validator, projects = validate_registry(manifest, candidates)
        if arguments.tier is not None:
            tiers = manifest.get("corpus", {}).get("tiers")
            if tiers is not None and arguments.tier not in tiers:
                validator.error("manifest.corpus.tiers", f"missing requested tier {arguments.tier}")
        if validator.errors:
            raise ValidationError("registry validation failed:\n  " + "\n  ".join(validator.errors))
    except ValidationError as error:
        print(f"FAIL real-sample registry: {error}", file=sys.stderr)
        return 1

    corpus = manifest["corpus"]
    print(
        f"PASS real-sample registry: {len(projects)} unique projects; "
        f"runtimes={','.join(sorted({p['target']['runtime'] for p in projects}))}; "
        "network=not-used"
    )
    if arguments.summary:
        for project in projects:
            print(f"{project['projectId']}\t{project['target']['runtime']}\t{project['provenance']['version']}")
    if arguments.emit:
        for project in projects:
            print(json.dumps(project, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
