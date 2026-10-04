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
TIERS = ("pr", "nightly", "release")
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
BIONIC_CONTAINER_PROTOCOL_VERSION = 2
BIONIC_OUTPUT_LIMIT_STATUS = 126
ISOLATION_PRODUCER = "run-isolated-real-sample.py"
BIONIC_CONTAINER_PRODUCER = "run-bionic-node-sample.sh"
BIONIC_NODE_RUNPATH = "/data/data/com.termux/files/usr/lib"
BIONIC_CLEANUP_AUTHORITY = "host-generated-after-docker-inspect"
RUNNER_PREFLIGHT_PROTOCOL_VERSION = 1
RUNNER_PREFLIGHT_PRODUCER = "run-real-sample-matrix.sh"
RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME = "preflight-environment-unavailable"
RUNNER_PREFLIGHT_OUTCOMES = frozenset({
    RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME,
    "preflight-product-failure",
    "preflight-runtime-failure",
})
RUNTIME_EXECUTION_LAYERS = ("baseline", "outerWrapper")


def effective_execution_policy(project: Mapping[str, Any], tier: str) -> dict[str, dict[str, Any]]:
    """Resolve one tier's execution policy from the canonical project policy.

    The base policy is the required nightly/release contract.  A project may
    explicitly narrow the PR dynamic oracle through ``tierOverrides`` (for
    example, to keep only the three real runtime witnesses in the required PR
    lane).  Consumers must use this projection rather than reading the base
    layer records directly so that an unavailable nightly closure cannot be
    represented as an expected result.
    """
    policy = project.get("executionPolicy")
    if not isinstance(policy, Mapping):
        return {}
    resolved: dict[str, dict[str, Any]] = {
        layer: dict(value)
        for layer in LAYERS
        if isinstance(value := policy.get(layer), Mapping)
    }
    overrides = policy.get("tierOverrides")
    tier_override = overrides.get(tier) if isinstance(overrides, Mapping) else None
    if isinstance(tier_override, Mapping):
        for layer in LAYERS:
            value = tier_override.get(layer)
            if isinstance(value, Mapping):
                base = resolved.setdefault(layer, {})
                base.update(value)
        isolation = tier_override.get("isolation")
        if isinstance(isolation, Mapping):
            resolved.setdefault("isolation", {}).update(isolation)
    return resolved


def effective_layer_policy(project: Mapping[str, Any], tier: str, layer: str) -> dict[str, Any]:
    """Return a copy of one layer after applying the explicit tier override."""
    return effective_execution_policy(project, tier).get(layer, {})


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
    producer = value.get("producer")
    if producer not in {ISOLATION_PRODUCER, BIONIC_CONTAINER_PRODUCER}:
        errors.append("helper result producer is unsupported")
    if producer == BIONIC_CONTAINER_PRODUCER:
        if value.get("schemaVersion") != BIONIC_CONTAINER_PROTOCOL_VERSION:
            errors.append("bionic container helper result schemaVersion must be 2")
        if value.get("runtime") != "bionic":
            errors.append("bionic container helper result must identify the bionic runtime")
    elif value.get("schemaVersion") != ISOLATION_PROTOCOL_VERSION:
        errors.append("helper result schemaVersion is unsupported")
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
    allowed_helper_statuses = RESERVED_HELPER_STATUSES | ({BIONIC_OUTPUT_LIMIT_STATUS} if producer == BIONIC_CONTAINER_PRODUCER else set())
    if helper_status is not None and helper_status not in allowed_helper_statuses:
        errors.append("helper result helperStatus is not a reserved helper sentinel")
    if helper_status is not None and target_status is not None:
        errors.append("helper result cannot contain both helperStatus and targetStatus")
    if target_status is not None and attempted is not True:
        errors.append("helper result targetStatus requires attempted=true")
    if target_status is not None and readiness_seen is not True:
        errors.append("helper result targetStatus requires readinessSeen=true")
    if helper_status == ISOLATION_ENVIRONMENT_STATUS and attempted is not False and not (
        producer == BIONIC_CONTAINER_PRODUCER
        and value.get("outcome") == "helper-environment"
        and target_status is None
    ):
        errors.append("helper environment status requires attempted=false unless a bionic Docker status inspection failed")
    outcome = value.get("outcome")
    if not isinstance(outcome, str) or not outcome:
        errors.append("helper result outcome is required")
    elif outcome == "helper-timeout":
        if helper_status != ISOLATION_TIMEOUT_STATUS or target_status is not None:
            errors.append("helper-timeout outcome requires helperStatus=124 and targetStatus=null")
    elif outcome == "helper-environment":
        attempted_allowed = attempted is False or (producer == BIONIC_CONTAINER_PRODUCER and target_status is None)
        if helper_status != ISOLATION_ENVIRONMENT_STATUS or target_status is not None or not attempted_allowed:
            errors.append("helper-environment outcome requires helperStatus=125 without an authoritative target status")
    elif outcome == "target-exit":
        if helper_status is not None or target_status is None or attempted is not True:
            errors.append("target-exit outcome requires an attempted target status and no helper status")
        if readiness_seen is not True:
            errors.append("target-exit outcome requires readinessSeen=true")
    elif outcome == "helper-protocol":
        if helper_status is not None or target_status is not None:
            errors.append("helper-protocol outcome cannot claim a helper or target status")
    elif outcome == "helper-output-limit" and producer == BIONIC_CONTAINER_PRODUCER:
        if helper_status != BIONIC_OUTPUT_LIMIT_STATUS or target_status is not None:
            errors.append("helper-output-limit outcome requires helperStatus=126 and targetStatus=null")
    else:
        errors.append("helper result outcome is unsupported")

    if producer == BIONIC_CONTAINER_PRODUCER:
        _validate_bionic_container_protocol(value, errors)
    return errors


def _validate_bionic_container_protocol(value: Mapping[str, Any], errors: list[str]) -> None:
    """Validate the host-generated Termux container execution contract."""
    digest = value.get("lockSha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        errors.append("bionic helper result lockSha256 must be lowercase SHA-256")
    if value.get("pathMode") != "outer-path-preserving":
        errors.append("bionic helper result pathMode must be outer-path-preserving")
    if value.get("pathPolicy") != "absolute-dt-runpath-preserved":
        errors.append("bionic helper result pathPolicy is unsupported")
    if value.get("runpath") != BIONIC_NODE_RUNPATH:
        errors.append("bionic helper result runpath does not match the locked absolute DT_RUNPATH")
    for field, expected in (("memoryBytes", 536870912), ("processLimit", 32)):
        actual = value.get(field)
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            errors.append(f"bionic helper result {field} must match the reviewed execution limit {expected}")
    if value.get("protocolAuthority") != "host-generated-after-docker-inspect":
        errors.append("bionic helper result must identify the host-generated Docker inspection protocol")
    if value.get("cleanupAuthority") != BIONIC_CLEANUP_AUTHORITY:
        errors.append("bionic helper result must identify host-generated container cleanup authority")
    if not isinstance(value.get("runpathVerified"), bool):
        errors.append("bionic helper result runpathVerified must be boolean")
    if not isinstance(value.get("allNamedContainersReaped"), bool):
        errors.append("bionic helper result allNamedContainersReaped must be boolean")
    for field, expected in (("timeoutSeconds", 30), ("outputLimitBytes", 1048576)):
        actual = value.get(field)
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            errors.append(f"bionic helper result {field} must match the reviewed execution limit {expected}")
    output_bytes = value.get("outputBytes")
    if isinstance(output_bytes, bool) or not isinstance(output_bytes, int) or output_bytes < 0 or output_bytes > 1048576:
        errors.append("bionic helper result outputBytes must be bounded by outputLimitBytes")
    for field in ("containerStatus", "dockerStatus", "cleanupContainerStatus"):
        if field not in value:
            errors.append(f"bionic helper result {field} is required")
        status = value.get(field)
        if status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 255):
            errors.append(f"bionic helper result {field} must be null or an integer from 0 through 255")
    target_status = value.get("targetStatus")
    container_status = value.get("containerStatus")
    if value.get("helperStatus") is not None and (target_status is not None or container_status is not None):
        errors.append("bionic helper status must keep targetStatus and containerStatus null")
    if target_status is not None:
        if container_status != target_status:
            errors.append("bionic helper targetStatus must match inspected containerStatus")
        # A Docker attach/inspect disagreement is retained as a runtime failure;
        # the evidence consumer forbids that pair from being accepted.
    inspection_failure = (
        value.get("outcome") == "helper-environment"
        and value.get("helperStatus") == ISOLATION_ENVIRONMENT_STATUS
        and target_status is None
    )
    if value.get("attempted") is True and container_status is None and value.get("helperStatus") is None and not inspection_failure:
        errors.append("bionic attempted execution requires a verified containerStatus")
    if value.get("outcome") == "target-exit" and value.get("attempted") is True:
        if value.get("readinessSeen") is not True:
            errors.append("bionic target-exit requires host-verified readiness")
    if value.get("outcome") == "helper-timeout" and value.get("helperStatus") != ISOLATION_TIMEOUT_STATUS:
        errors.append("bionic container timeout must remain helperStatus=124")
    if value.get("outcome") == "helper-environment" and value.get("helperStatus") != ISOLATION_ENVIRONMENT_STATUS:
        errors.append("bionic environment failure must remain helperStatus=125")


def validate_bionic_node_result(
    value: Any,
    *,
    expected_lock_sha256: str | None = None,
    expected_runpath: str | None = None,
    expected_image: str | None = None,
    expected_image_id: str | None = None,
    expected_loader: str | None = None,
) -> list[str]:
    """Validate the host-generated summary for the locked bionic Node witness."""
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["bionic Node.js result must be an object"]
    if value.get("schemaVersion") != 2 or value.get("producer") != BIONIC_CONTAINER_PRODUCER:
        errors.append("bionic Node.js result must use schemaVersion 2 and the bionic runner producer")
    if value.get("runtime") != "bionic":
        errors.append("bionic Node.js result runtime must be bionic")
    image = value.get("image")
    image_id = value.get("imageId")
    loader = value.get("loader")
    if not isinstance(image, str) or not image:
        errors.append("bionic Node.js result image is required")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:") or len(image_id) != 71 or any(char not in "0123456789abcdef" for char in image_id[7:]):
        errors.append("bionic Node.js result imageId must be a Docker SHA-256 identity")
    if loader != "/system/bin/linker64":
        errors.append("bionic Node.js result loader must be /system/bin/linker64")
    if expected_image is not None and image != expected_image:
        errors.append("bionic Node.js result image does not match the reviewed runtime lock")
    if expected_image_id is not None and image_id != expected_image_id:
        errors.append("bionic Node.js result imageId does not match the reviewed runtime lock")
    if expected_loader is not None and loader != expected_loader:
        errors.append("bionic Node.js result loader does not match the reviewed runtime lock")
    digest = value.get("lockSha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        errors.append("bionic Node.js result lockSha256 must be lowercase SHA-256")
    elif expected_lock_sha256 is not None and digest != expected_lock_sha256:
        errors.append("bionic Node.js result lockSha256 does not match runtime-closures.json")
    if value.get("pathMode") != "outer-path-preserving":
        errors.append("bionic Node.js result pathMode must be outer-path-preserving")
    if value.get("pathPolicy") != "absolute-dt-runpath-preserved":
        errors.append("bionic Node.js result pathPolicy is unsupported")
    if value.get("protocolAuthority") != "host-generated-after-docker-inspect":
        errors.append("bionic Node.js result must identify host-generated Docker inspection evidence")
    for field, expected in (("timeoutSeconds", 30), ("outputLimitBytes", 1048576), ("memoryBytes", 536870912), ("processLimit", 32)):
        actual = value.get(field)
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            errors.append(f"bionic Node.js result {field} must match locked value {expected}")
    output_bytes = value.get("outputBytes")
    if isinstance(output_bytes, bool) or not isinstance(output_bytes, int) or not 0 <= output_bytes <= 1048576:
        errors.append("bionic Node.js result outputBytes must be bounded by 1 MiB")
    if "containerStatus" not in value:
        errors.append("bionic Node.js result containerStatus is required")
    container_status = value.get("containerStatus")
    if container_status is not None and (
        isinstance(container_status, bool) or not isinstance(container_status, int) or not 0 <= container_status <= 255
    ):
        errors.append("bionic Node.js result containerStatus must be null or an integer from 0 through 255")
    cleanup = value.get("containerCleanup")
    if not isinstance(cleanup, Mapping):
        errors.append("bionic Node.js result must retain containerCleanup evidence")
    else:
        if not isinstance(cleanup.get("allNamedContainersReaped"), bool):
            errors.append("bionic Node.js result containerCleanup must retain a boolean reap result")
        if cleanup.get("authority") != BIONIC_CLEANUP_AUTHORITY:
            errors.append("bionic Node.js result containerCleanup authority is unsupported")
    if value.get("cleanupAuthority") != BIONIC_CLEANUP_AUTHORITY:
        errors.append("bionic Node.js result cleanupAuthority is unsupported")
    image_cleanup = value.get("temporaryImageCleanup")
    image_absent = False
    if not isinstance(image_cleanup, Mapping):
        errors.append("bionic Node.js result must retain temporaryImageCleanup evidence")
    else:
        image_state = image_cleanup.get("status")
        image_absent = image_cleanup.get("absenceVerified") is True
        attempts = image_cleanup.get("attempts")
        if image_state not in {"not-created", "removed-and-verified", "cleanup-failure", "blocked-by-live-containers"}:
            errors.append("bionic Node.js temporaryImageCleanup status is unsupported")
        if not isinstance(image_cleanup.get("absenceVerified"), bool):
            errors.append("bionic Node.js temporaryImageCleanup absenceVerified must be boolean")
        if isinstance(attempts, bool) or not isinstance(attempts, int) or not 0 <= attempts <= 2:
            errors.append("bionic Node.js temporaryImageCleanup attempts must be an integer from 0 through 2")
        if image_cleanup.get("authority") != BIONIC_CLEANUP_AUTHORITY:
            errors.append("bionic Node.js temporaryImageCleanup authority is unsupported")
        if image_state == "not-created" and (attempts != 0 or not image_absent or image_cleanup.get("reason") is not None):
            errors.append("bionic Node.js not-created image cleanup must retain verified absence without attempts")
        elif image_state == "removed-and-verified" and (not image_absent or not isinstance(attempts, int) or attempts < 1 or image_cleanup.get("reason") is not None):
            errors.append("bionic Node.js removed image cleanup requires verified absence and a bounded attempt")
        elif image_state in {"cleanup-failure", "blocked-by-live-containers"} and (
            image_absent or not isinstance(image_cleanup.get("reason"), str) or not image_cleanup.get("reason", "").strip()
        ):
            errors.append("bionic Node.js failed image cleanup must retain a reason and unverified absence")
    work_root_retained = value.get("workRootRetained")
    if not isinstance(work_root_retained, bool):
        errors.append("bionic Node.js result workRootRetained must be boolean")
    containers_clean = isinstance(cleanup, Mapping) and cleanup.get("allNamedContainersReaped") is True
    cleanup_ok = containers_clean and image_absent and work_root_retained is False
    expected_cleanup_status = "passed" if cleanup_ok else "failed"
    if value.get("cleanupStatus") != expected_cleanup_status:
        errors.append("bionic Node.js result cleanupStatus does not match verified container/image/work-root cleanup")
    statuses = value.get("containerStatuses")
    if not isinstance(statuses, Mapping) or set(statuses) != {"setup", "baseline", "outer"}:
        errors.append("bionic Node.js result containerStatuses must retain setup, baseline, and outer")
    elif any(status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 255) for status in statuses.values()):
        errors.append("bionic Node.js result containerStatuses contain an invalid status")
    cleanup_statuses = value.get("cleanupContainerStatuses")
    if not isinstance(cleanup_statuses, Mapping) or set(cleanup_statuses) != {"setup", "baseline", "outer"}:
        errors.append("bionic Node.js result cleanupContainerStatuses must retain setup, baseline, and outer")
    elif any(status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 255) for status in cleanup_statuses.values()):
        errors.append("bionic Node.js result cleanupContainerStatuses contain an invalid status")
    if value.get("runpath") != BIONIC_NODE_RUNPATH:
        errors.append("bionic Node.js result RUNPATH does not match the reviewed absolute path")
    if not isinstance(value.get("runpathVerified"), bool):
        errors.append("bionic Node.js result runpathVerified must be boolean")
    if expected_runpath is not None and value.get("runpath") != expected_runpath:
        errors.append("bionic Node.js result RUNPATH does not match runtime-closures.json")
    expected_status = value.get("expectedStatus")
    if isinstance(expected_status, bool) or not isinstance(expected_status, int) or not 0 <= expected_status <= 255:
        errors.append("bionic Node.js result expectedStatus must be an integer from 0 through 255")
    for layer in ("baseline", "outer"):
        item = value.get(layer)
        if not isinstance(item, Mapping):
            errors.append(f"bionic Node.js result {layer} record is missing")
            continue
        protocol = item.get("protocol")
        errors.extend(f"bionic Node.js result {layer}: {message}" for message in validate_isolation_result(protocol))
        if item.get("actual") not in RESULTS:
            errors.append(f"bionic Node.js result {layer} actual classification is unsupported")
        if isinstance(protocol, Mapping):
            if digest is not None and protocol.get("lockSha256") != digest:
                errors.append(f"bionic Node.js result {layer} protocol lockSha256 differs from result lockSha256")
            status_key = "baseline" if layer == "baseline" else "outer"
            if isinstance(statuses, Mapping) and statuses.get(status_key) != protocol.get("containerStatus"):
                errors.append(f"bionic Node.js result {layer} containerStatuses entry does not match its protocol")
            if isinstance(cleanup_statuses, Mapping) and cleanup_statuses.get(status_key) != protocol.get("cleanupContainerStatus"):
                errors.append(f"bionic Node.js result {layer} cleanupContainerStatuses entry does not match its protocol")
            if protocol.get("protocolAuthority") != value.get("protocolAuthority"):
                errors.append(f"bionic Node.js result {layer} protocol authority differs from summary")
            if protocol.get("cleanupAuthority") != value.get("cleanupAuthority"):
                errors.append(f"bionic Node.js result {layer} cleanup authority differs from summary")
            if protocol.get("runpathVerified") != value.get("runpathVerified"):
                errors.append(f"bionic Node.js result {layer} runpathVerified differs from summary")
            cleanup_reaped = cleanup.get("allNamedContainersReaped") if isinstance(cleanup, Mapping) else None
            if protocol.get("allNamedContainersReaped") != cleanup_reaped:
                errors.append(f"bionic Node.js result {layer} container cleanup result differs from summary")
            if item.get("actual") == "accepted-and-runs":
                if protocol.get("containerStatus") != expected_status or protocol.get("dockerStatus") != expected_status or protocol.get("targetStatus") != expected_status:
                    errors.append(f"bionic Node.js result {layer} accepted status lacks matching target, Docker, and container status")
                if protocol.get("runpathVerified") is not True:
                    errors.append(f"bionic Node.js result {layer} accepted status lacks verified DT_RUNPATH evidence")
                if protocol.get("allNamedContainersReaped") is not True:
                    errors.append(f"bionic Node.js result {layer} accepted status lacks verified named-container cleanup")
                if not cleanup_ok:
                    errors.append(f"bionic Node.js result {layer} accepted status lacks verified temporary-image and work-root cleanup")
            if item.get("containerStatus") != protocol.get("containerStatus"):
                errors.append(f"bionic Node.js result {layer} containerStatus does not match its host protocol")
            for field in ("cleanupAuthority", "runpathVerified", "allNamedContainersReaped", "cleanupContainerStatus"):
                if item.get(field) != protocol.get(field):
                    errors.append(f"bionic Node.js result {layer} {field} does not match its host protocol")
    summary_status = value.get("status")
    if summary_status not in {"passed", "failed"}:
        errors.append("bionic Node.js result status must be passed or failed")
    baseline_accepted = isinstance(value.get("baseline"), Mapping) and value["baseline"].get("actual") == "accepted-and-runs"
    outer_accepted = isinstance(value.get("outer"), Mapping) and value["outer"].get("actual") == "accepted-and-runs"
    both_accepted = baseline_accepted and outer_accepted
    required_summary_status = "passed" if both_accepted else "failed"
    if summary_status != required_summary_status:
        errors.append(
            "bionic Node.js result status must be passed exactly when both baseline and outer actuals are accepted-and-runs"
        )
    behavior_equivalent = value.get("behaviorEquivalent")
    if not isinstance(behavior_equivalent, bool):
        errors.append("bionic Node.js result behaviorEquivalent must be boolean")
    elif behavior_equivalent != both_accepted:
        errors.append("bionic Node.js result behaviorEquivalent must agree with baseline/outer actuals")
    if baseline_accepted or outer_accepted:
        if value.get("runpathVerified") is not True:
            errors.append("bionic Node.js accepted runs require verified DT_RUNPATH evidence")
        if not isinstance(statuses, Mapping) or statuses.get("setup") != expected_status:
            errors.append("bionic Node.js accepted runs require a matching successful setup container status")
        if not isinstance(cleanup, Mapping) or cleanup.get("allNamedContainersReaped") is not True:
            errors.append("bionic Node.js accepted runs require verified bounded container reaping")
        baseline_item = value.get("baseline")
        outer_item = value.get("outer")
        baseline_protocol = baseline_item.get("protocol") if isinstance(baseline_item, Mapping) else None
        outer_protocol = outer_item.get("protocol") if isinstance(outer_item, Mapping) else None
        expected_top_status = (
            outer_protocol.get("containerStatus")
            if isinstance(outer_protocol, Mapping) and outer_protocol.get("containerStatus") is not None
            else baseline_protocol.get("containerStatus") if isinstance(baseline_protocol, Mapping) else None
        )
        if container_status != expected_top_status:
            errors.append("bionic Node.js summary containerStatus must match the inspected outer/baseline result")
    if both_accepted and (
        not isinstance(statuses, Mapping)
        or any(statuses.get(key) != expected_status for key in ("baseline", "outer"))
    ):
        errors.append("bionic Node.js accepted baseline and outer runs require matching container statuses")
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
        policy = effective_execution_policy(project, tier)
        if not policy:
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
                    "expectedResult=accepted-and-runs; environment-unavailable is an observed failure"
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
