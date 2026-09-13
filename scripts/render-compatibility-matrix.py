#!/usr/bin/env python3
"""Render the repository compatibility matrix as a reviewable Markdown report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, default=Path("-"))
    return parser.parse_args()


def cell(value: object) -> str:
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(data: dict[str, object]) -> str:
    features = data["features"]
    cases = data["cases"]
    lines = [
        "# UrProtect Compatibility Matrix",
        "",
        f"Host contract: `{data['hostContract']['id']}` v{data['hostContract']['version']}",
        "",
        "## Features",
        "",
        "| Feature | Status | Obligation | Witness | Oracle | Evidence | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for feature in features:
        notes = []
        if feature.get("constraints"):
            notes.append("constraints: " + cell(feature["constraints"]))
        if feature.get("status") == "unknown":
            notes.append("next evidence: " + cell(feature.get("nextEvidence", "")))
        elif feature.get("status") == "rejected":
            notes.append("reason: " + cell(feature.get("reason", "")))
        lines.append(
            "| "
            + " | ".join(
                (
                    " ".join(notes)
                    if field == "notes"
                    else cell(feature.get(field, ""))
                )
                for field in (
                    "id",
                    "status",
                    "obligation",
                    "witness",
                    "oracle",
                    "evidence",
                    "notes",
                )
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| Case | Tier | Runtime | Target | Execution | Features | Evidence |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for case in cases:
        lines.append(
            "| "
            + " | ".join(
                cell(case.get(field, ""))
                for field in ("id", "tier", "runtime", "target", "execution", "features", "evidence")
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    data = json.loads(args.manifest.read_text())
    report = render(data)
    if str(args.output) == "-":
        print(report, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
