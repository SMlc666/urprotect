"""Shared normalized contracts for the public real-sample evidence layer.

The acquisition runner owns policy and process execution.  This module owns
only vocabulary and deterministic projections so the runner, aggregate report,
and evidence gate cannot drift on first-failure or feature naming.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

RESULTS = {
    "accepted-and-runs",
    "expected-rejected",
    "unexpected-rejection",
    "unexpected-acceptance",
    "runtime-failure",
    "environment-unavailable",
    "not-applicable",
}
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
        if actual not in RESULTS:
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
