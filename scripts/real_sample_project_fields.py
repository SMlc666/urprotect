#!/usr/bin/env python3
"""Serialize one real-sample record for the matrix runner's Bash consumer."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

from real_sample_schema import effective_execution_policy


def project_fields(project: dict[str, Any], closures: dict[str, Any], tier: str = "pr") -> list[str]:
    provenance = project["provenance"]
    target = project["target"]
    policy = effective_execution_policy(project, tier)
    closure_projects = closures.get("projects", {})
    closure_policy = closure_projects.get(project["projectId"], closure_projects["*"])
    baseline_policy = dict(policy["baseline"])
    outer_policy = dict(policy["outerWrapper"])

    # Closure policy fills an explicitly applicable registry layer. It must not
    # turn an explicit not-applicable boundary into a runtime claim.
    def merge_closure_policy(declared: dict[str, Any], closure_layer: Any) -> None:
        if declared.get("applicable") is False or not isinstance(closure_layer, dict):
            return
        # The registry owns the expected result. In particular, an explicit
        # environment-unavailable boundary must not be promoted by a generic
        # closure default that says accepted-and-runs.
        declared.update({key: value for key, value in closure_layer.items() if key != "expectedResult"})

    merge_closure_policy(baseline_policy, closure_policy.get("baseline"))
    merge_closure_policy(outer_policy, closure_policy.get("outerWrapper"))
    if baseline_policy.get("applicable") is not False and "command" in closure_policy.get("baseline", {}):
        baseline_policy["mode"] = "bubblewrap-rootfs"

    apk_metadata = {
        "package": provenance.get("packageName", ""),
        "version": provenance.get("version", ""),
        "architecture": target.get("architecture", ""),
        "origin": provenance.get("origin", ""),
        "license": provenance.get("license", ""),
    }
    # Bash read treats consecutive tab delimiters as one separator. Keep the
    # optional invocation field non-empty so later runtime and APK metadata
    # fields cannot shift left for policies without an invocation.
    return [
        project["projectId"],
        provenance["archiveUrl"],
        provenance["version"],
        provenance["archivePath"],
        provenance["archiveSha256"],
        provenance["archiveFormat"],
        provenance["artifactPath"],
        project["featureFingerprint"]["producer"],
        policy["static"]["expectedResult"],
        str(baseline_policy.get("applicable", False)).lower(),
        baseline_policy.get("expectedResult", "not-applicable"),
        baseline_policy.get("mode", "-"),
        base64.urlsafe_b64encode(json.dumps(baseline_policy.get("command", [])).encode()).decode(),
        str(baseline_policy.get("expectedStatus", 0)),
        baseline_policy.get("invocation") or "-",
        str(outer_policy.get("applicable", False)).lower(),
        outer_policy.get("expectedResult", "not-applicable"),
        outer_policy.get("mode", "outer-execveat"),
        target["runtime"],
        target["loader"],
        base64.urlsafe_b64encode(json.dumps(apk_metadata).encode()).decode(),
        provenance.get("sourceKind", ""),
    ]


def main() -> int:
    if len(sys.argv) not in {3, 4}:
        print("usage: real_sample_project_fields.py PROJECT_JSON RUNTIME_CLOSURES [TIER]", file=sys.stderr)
        return 2
    project = json.loads(sys.argv[1])
    closures = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    tier = sys.argv[3] if len(sys.argv) == 4 else "pr"
    if not isinstance(project, dict) or not isinstance(closures, dict):
        print("project and runtime closures must be JSON objects", file=sys.stderr)
        return 2
    print("\t".join(project_fields(project, closures, tier)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
