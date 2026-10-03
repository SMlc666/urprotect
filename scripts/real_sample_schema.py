"""Shared normalized contracts for the public real-sample evidence layer.

The acquisition runner owns policy and process execution.  This module owns
only vocabulary and deterministic projections so the runner, aggregate report,
and evidence gate cannot drift on first-failure or feature naming.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

RESULTS = {
    "validated",
    "accepted-and-runs",
    "expected-rejected",
    "unexpected-rejection",
    "unexpected-acceptance",
    "runtime-failure",
    "environment-unavailable",
    "not-applicable",
}
# Static validation never launches the sample.  Keep the execution-only
# success result out of this layer so schema consumers cannot accidentally
# promote a successful `validate` invocation to runtime evidence.
STATIC_RESULTS = RESULTS - {"accepted-and-runs", "runtime-failure"}
LAYERS = ("static", "baseline", "outerWrapper", "hostContext")
FIRST_FAILURE_LAYERS = (
    "acquisition",
    "fingerprint",
    "parse-model",
    "static-validation",
    "outer",
    "host-context",
    "environment",
)
MAX_REAL_SAMPLE_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_REAL_SAMPLE_ARCHIVE_MEMBERS = 100_000
MAX_REAL_SAMPLE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_REAL_SAMPLE_PACKAGE_METADATA_BYTES = 1024 * 1024
# run-isolated-real-sample.py owns these helper statuses.  Runtime policies
# must never use them as target exit codes because they carry environment and
# timeout outcomes across the shell boundary.
ISOLATION_TIMEOUT_STATUS = 124
ISOLATION_ENVIRONMENT_STATUS = 125
RESERVED_HELPER_STATUSES = frozenset({ISOLATION_TIMEOUT_STATUS, ISOLATION_ENVIRONMENT_STATUS})
ISOLATION_PROTOCOL_VERSION = 1
ISOLATION_PRODUCER = "run-isolated-real-sample.py"
RUNNER_PREFLIGHT_PROTOCOL_VERSION = 1
RUNNER_PREFLIGHT_PRODUCER = "run-real-sample-matrix.sh"
RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME = "preflight-environment-unavailable"
RUNNER_PREFLIGHT_OUTCOMES = frozenset({
    RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME,
    "preflight-product-failure",
})
RUNTIME_EXECUTION_LAYERS = ("baseline", "outerWrapper")
PR_RUNTIME_WITNESSES = {
    "musl": "busybox",
    "glibc": "gnu-coreutils",
    "bionic": "nodejs",
}


def classify_isolated_result(
    *,
    attempted: bool,
    helper_status: int | None,
    target_status: int | None,
    expected: int,
) -> str:
    """Classify the explicit helper/target result protocol.

    A target is known to have started only after the readiness boundary.  A
    target may legitimately return 124 or 125; those values are runtime
    failures unless the helper protocol separately reports its own sentinel.
    """
    if helper_status == ISOLATION_ENVIRONMENT_STATUS:
        return "environment-unavailable"
    if helper_status == ISOLATION_TIMEOUT_STATUS:
        return "runtime-failure"
    if helper_status is not None:
        return "runtime-failure"
    if not attempted or target_status is None:
        return "environment-unavailable"
    if target_status in RESERVED_HELPER_STATUSES:
        return "runtime-failure"
    if target_status == expected:
        return "accepted-and-runs"
    return "runtime-failure"


def classify_isolated_status(observed: int, expected: int) -> str:
    """Classify a legacy process status as a helper result.

    New callers must use :func:`classify_isolated_result` because a bare 124 or
    125 cannot distinguish a target exit from a helper sentinel.
    """
    if observed in RESERVED_HELPER_STATUSES:
        return classify_isolated_result(
            attempted=False,
            helper_status=observed,
            target_status=None,
            expected=expected,
        )
    return classify_isolated_result(
        attempted=True,
        helper_status=None,
        target_status=observed,
        expected=expected,
    )


def validate_isolation_result(value: Any) -> list[str]:
    """Validate a result emitted by an actual isolated-helper invocation."""
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["helper result must be an object"]
    if value.get("schemaVersion") != ISOLATION_PROTOCOL_VERSION:
        errors.append("helper result schemaVersion is unsupported")
    if value.get("producer") != ISOLATION_PRODUCER:
        errors.append("helper result producer is unsupported")
    if value.get("synthetic") is True:
        errors.append("helper result cannot be synthetic")
    attempted = value.get("attempted")
    if not isinstance(attempted, bool):
        errors.append("helper result attempted must be boolean")
    helper_status = value.get("helperStatus")
    target_status = value.get("targetStatus")
    readiness_seen = value.get("readinessSeen")
    if not isinstance(readiness_seen, bool):
        errors.append("helper result readinessSeen must be boolean")
    for name, status in (("helperStatus", helper_status), ("targetStatus", target_status)):
        if status is not None and (
            isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 255
        ):
            errors.append(f"helper result {name} must be null or an integer from 0 through 255")
    if helper_status is not None and helper_status not in RESERVED_HELPER_STATUSES:
        errors.append("helper result helperStatus is not a reserved helper sentinel")
    if helper_status is not None and target_status is not None:
        errors.append("helper result cannot contain both helperStatus and targetStatus")
    if target_status is not None and attempted is not True:
        errors.append("helper result targetStatus requires attempted=true")
    if target_status is not None and readiness_seen is not True:
        errors.append("helper result targetStatus requires readinessSeen=true")
    if helper_status == ISOLATION_ENVIRONMENT_STATUS and attempted is not False:
        errors.append("helper environment status requires attempted=false")
    outcome = value.get("outcome")
    if not isinstance(outcome, str) or not outcome:
        errors.append("helper result outcome is required")
    elif outcome == "helper-timeout":
        if helper_status != ISOLATION_TIMEOUT_STATUS or target_status is not None:
            errors.append("helper-timeout outcome requires helperStatus=124 and targetStatus=null")
    elif outcome == "helper-environment":
        if helper_status != ISOLATION_ENVIRONMENT_STATUS or target_status is not None or attempted is not False:
            errors.append("helper-environment outcome requires helperStatus=125 before target execution")
    elif outcome == "target-exit":
        if helper_status is not None or target_status is None or attempted is not True:
            errors.append("target-exit outcome requires an attempted target status and no helper status")
        if readiness_seen is not True:
            errors.append("target-exit outcome requires readinessSeen=true")
    elif outcome == "helper-protocol":
        if helper_status is not None or target_status is not None:
            errors.append("helper-protocol outcome cannot claim a helper or target status")
    else:
        errors.append("helper result outcome is unsupported")
    return errors


def validate_runner_preflight(value: Any) -> list[str]:
    """Validate a runner-owned boundary that prevented helper invocation."""
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["runner preflight result must be an object"]
    if value.get("schemaVersion") != RUNNER_PREFLIGHT_PROTOCOL_VERSION:
        errors.append("runner preflight schemaVersion is unsupported")
    if value.get("producer") != RUNNER_PREFLIGHT_PRODUCER:
        errors.append("runner preflight producer is unsupported")
    if value.get("synthetic") is True:
        errors.append("runner preflight result cannot be marked synthetic")
    if value.get("outcome") not in RUNNER_PREFLIGHT_OUTCOMES:
        errors.append("runner preflight outcome is unsupported")
    layer = value.get("layer")
    if layer not in RUNTIME_EXECUTION_LAYERS:
        errors.append("runner preflight layer is unsupported")
    stage = value.get("stage")
    if not isinstance(stage, str) or not stage.strip():
        errors.append("runner preflight stage is required")
    reason = value.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        errors.append("runner preflight reason is required")
    if value.get("attempted") is not False:
        errors.append("runner preflight must declare attempted=false")
    if value.get("helperStatus") is not None:
        errors.append("runner preflight helperStatus must be null")
    if value.get("targetStatus") is not None:
        errors.append("runner preflight targetStatus must be null")
    return errors


def required_execution_policy_errors(
    projects: list[Mapping[str, Any]],
    tier: str,
    closures: Mapping[str, Any] | None = None,
) -> list[str]:
    """Return missing tier-required runtime policy declarations.

    Registry policies are the source of applicability. A closure's default
    result can describe how an applicable policy is executed, but it cannot
    promote a registry ``not-applicable`` boundary into an execution claim.
    Keeping this check in the shared schema module makes the runner, renderer,
    and post-run gate use the same tier contract.
    """
    by_id = {
        project.get("projectId"): project
        for project in projects
        if isinstance(project.get("projectId"), str)
    }
    if tier == "pr":
        required = {project_id: runtime for runtime, project_id in PR_RUNTIME_WITNESSES.items()}
    elif tier in {"nightly", "release"}:
        required = {
            project_id: (
                project.get("target", {}).get("runtime", "unknown")
                if isinstance(project.get("target"), Mapping)
                else "unknown"
            )
            for project_id, project in by_id.items()
        }
    else:
        return [f"unsupported evidence tier for runtime coverage: {tier}"]

    errors: list[str] = []
    closure_projects = closures.get("projects") if isinstance(closures, Mapping) else None
    for project_id, required_runtime in required.items():
        project = by_id.get(project_id)
        if project is None:
            errors.append(f"{tier} runtime coverage requires missing witness {project_id}")
            continue
        target = project.get("target")
        runtime = target.get("runtime") if isinstance(target, Mapping) else None
        if runtime != required_runtime:
            errors.append(
                f"{tier} runtime coverage witness {project_id} must declare runtime "
                f"{required_runtime}, found {runtime!r}"
            )
        policy = project.get("executionPolicy")
        if not isinstance(policy, Mapping):
            errors.append(f"{project_id}: executionPolicy is required for {tier} runtime coverage")
            continue
        for layer in RUNTIME_EXECUTION_LAYERS:
            declaration = policy.get(layer)
            if not isinstance(declaration, Mapping) or declaration.get("applicable") is not True:
                errors.append(
                    f"{tier} runtime coverage requires {project_id}/{layer} "
                    "policy applicable=true; not-applicable is not a coverage result"
                )
            elif declaration.get("expectedResult") != "accepted-and-runs":
                errors.append(
                    f"{tier} runtime coverage requires {project_id}/{layer} "
                    "expectedResult=accepted-and-runs"
                )

            if not isinstance(closure_projects, Mapping):
                continue
            closure_policy = closure_projects.get(project_id, closure_projects.get("*"))
            if not isinstance(closure_policy, Mapping):
                errors.append(f"{project_id}: runtime closure policy is missing for {tier} coverage")
                continue
            closure_layer = closure_policy.get(layer)
            if not isinstance(closure_layer, Mapping) or closure_layer.get("expectedResult") != "accepted-and-runs":
                errors.append(
                    f"{tier} runtime coverage requires locked closure support for "
                    f"{project_id}/{layer} with expectedResult=accepted-and-runs"
                )
    return errors


# A runtime closure is an aggregate of independently bounded package archives.
# Keep its totals bounded even when every individual archive satisfies the
# real-sample extraction limits.
MAX_RUNTIME_CLOSURE_PACKAGES = 256
MAX_RUNTIME_CLOSURE_MEMBERS = MAX_REAL_SAMPLE_ARCHIVE_MEMBERS
MAX_RUNTIME_CLOSURE_EXPANDED_BYTES = MAX_REAL_SAMPLE_UNCOMPRESSED_BYTES
MAX_RUNTIME_CLOSURE_OPERATION_SECONDS = 120


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def layer_failure_name(layer: str, actual: str | None) -> str:
    """Map a result layer to the fixed first-failure taxonomy."""
    if actual == "environment-unavailable":
        return "environment"
    if actual == "runtime-failure":
        if layer == "outerWrapper":
            return "outer"
        if layer == "hostContext":
            return "host-context"
        return "environment"
    if layer == "static":
        return "static-validation"
    if layer == "outerWrapper":
        return "outer"
    if layer == "hostContext":
        return "host-context"
    # A baseline oracle is an execution/environment observation, not a parser
    # or product-support claim.
    return "environment"


def first_failure_layer(
    layers: Mapping[str, Any], explicit: Any = None
) -> str | None:
    """Return the first blocking layer in deterministic oracle order.

    Acquisition and fingerprint failures can be supplied explicitly by the
    runner because they occur before a layer result exists.  Otherwise the
    first expected/actual mismatch is normalized without inspecting free-form
    log text.
    """
    if isinstance(explicit, str) and explicit in FIRST_FAILURE_LAYERS:
        return explicit
    for layer in LAYERS:
        value = layers.get(layer)
        if not isinstance(value, Mapping):
            continue
        actual = _string(value.get("actual"))
        expected = _string(value.get("expected"))
        allowed = STATIC_RESULTS if layer == "static" else RESULTS
        if actual not in allowed:
            return layer_failure_name(layer, actual)
        if expected is not None and actual != expected:
            return layer_failure_name(layer, actual)
    return None


def diagnostic_code(layer: str, result: Mapping[str, Any]) -> str | None:
    """Choose a stable diagnostic field without parsing log prose."""
    for key in ("diagnosticCode", "diagnostic", "code"):
        value = _string(result.get(key))
        if value:
            return value
    actual = _string(result.get("actual"))
    if actual == "environment-unavailable":
        return "environment-unavailable"
    if actual == "runtime-failure":
        return f"{layer}.runtime-failure"
    if actual == "unexpected-rejection":
        return f"{layer}.unexpected-rejection"
    if actual == "unexpected-acceptance":
        return f"{layer}.unexpected-acceptance"
    return None


def _add_feature(features: set[str], value: Any, prefix: str = "") -> None:
    if isinstance(value, str) and value:
        features.add(f"{prefix}{value}" if prefix else value)


def observed_features(fingerprint: Mapping[str, Any]) -> list[str]:
    """Project a bounded fingerprint to canonical feature cluster names.

    The projection is deliberately conservative: a feature is emitted only
    when the fingerprint contains a positive observation.  Unknown fields do
    not become support claims or positive feature counts.
    """
    features: set[str] = set()
    for name, key in (
        ("elf.class", "elfClass"),
        ("elf.data", "data"),
        ("elf.machine", "machine"),
    ):
        value = fingerprint.get(key)
        if isinstance(value, str) and value:
            features.add(f"{name}.{value}")
    tags = fingerprint.get("featureTags")
    if isinstance(tags, list):
        for tag in tags[:256]:
            _add_feature(features, tag)

    relocations = fingerprint.get("relocations")
    if isinstance(relocations, Mapping):
        for key in ("rela", "relr", "plt", "got", "androidPacked"):
            if relocations.get(key) is True:
                features.add(f"relocations.{key}")
        families = relocations.get("families")
        if isinstance(families, Mapping):
            for family, count in list(families.items())[:128]:
                if isinstance(family, str) and isinstance(count, int) and count > 0:
                    features.add(f"relocations.family.{family}")

    dependencies = fingerprint.get("dependencies")
    if isinstance(dependencies, Mapping):
        needed = dependencies.get("needed")
        if isinstance(needed, list) and needed:
            features.add("dependencies.needed")
        if isinstance(dependencies.get("rpath"), list) and dependencies["rpath"]:
            features.add("dependencies.rpath")
        if isinstance(dependencies.get("runpath"), list) and dependencies["runpath"]:
            features.add("dependencies.runpath")

    versions = fingerprint.get("symbolVersions")
    if isinstance(versions, Mapping) and versions.get("present") is True:
        features.add("symbol-versions")
    elif versions is True:
        features.add("symbol-versions")

    tls = fingerprint.get("tls")
    if isinstance(tls, Mapping) and tls.get("present") is True:
        features.add("tls")
    elif tls is True:
        features.add("tls")

    properties = fingerprint.get("gnuProperty")
    if isinstance(properties, Mapping) and properties.get("present") is True:
        features.add("gnu-property")
    elif properties is True:
        features.add("gnu-property")

    relro = fingerprint.get("relro")
    if isinstance(relro, Mapping):
        kind = _string(relro.get("kind"))
        if kind and kind != "none":
            features.add(f"hardening.relro.{kind}")
    elif relro is True:
        features.add("gnu-relro")

    stack = fingerprint.get("gnuStack")
    if isinstance(stack, Mapping):
        executable = stack.get("executable")
        if executable is True:
            features.add("hardening.gnu-stack-exec")
        elif executable is False:
            features.add("hardening.gnu-stack-noexec")

    hardening = fingerprint.get("hardening")
    if isinstance(hardening, Mapping):
        if hardening.get("bindNow") is True:
            features.add("hardening.bind-now")
        if hardening.get("textrel") is True:
            features.add("hardening.textrel")

    if fingerprint.get("stripped") is True:
        features.add("stripped")
    elif fingerprint.get("stripped") is False:
        features.add("has-symbol-table")
    if fingerprint.get("sectionless") is True:
        features.add("sectionless")
    if isinstance(fingerprint.get("type"), str):
        elf_type = fingerprint["type"].split(" ", 1)[0].upper()
        elf_type = {"DYN": "ET_DYN", "EXEC": "ET_EXEC"}.get(elf_type, elf_type)
        features.add(f"elf.type.{elf_type}")
    if isinstance(fingerprint.get("interpreter"), str) and fingerprint["interpreter"]:
        features.add(f"loader.{fingerprint['interpreter']}")
    return sorted(features)[:512]
