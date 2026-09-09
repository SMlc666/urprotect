#!/usr/bin/env python3
"""Enforce the initial coverage floor for the project-owned code."""

from pathlib import Path
import sys
import xml.etree.ElementTree as ET

MIN_LINE_RATE = 0.65
MIN_BRANCH_RATE = 0.30
MIN_CORE_LINE_RATE = 0.50
MIN_CORE_BRANCH_RATE = 0.35

reports = sorted(Path(".").glob("tests/**/TestResults/**/coverage.cobertura.xml"))
if not reports:
    raise SystemExit("coverage report not found")

report = max(reports, key=lambda path: path.stat().st_mtime)
root = ET.parse(report).getroot()
line_rate = float(root.attrib["line-rate"])
branch_rate = float(root.attrib["branch-rate"])
print(f"coverage report: {report}")
print(f"overall line-rate={line_rate:.4f} branch-rate={branch_rate:.4f}")

failures = []
if line_rate < MIN_LINE_RATE:
    failures.append(f"overall line-rate {line_rate:.4f} < {MIN_LINE_RATE:.4f}")
if branch_rate < MIN_BRANCH_RATE:
    failures.append(f"overall branch-rate {branch_rate:.4f} < {MIN_BRANCH_RATE:.4f}")

for package in root.findall("./packages/package"):
    if package.attrib.get("name") != "UrProtect.Core":
        continue
    core_line = float(package.attrib["line-rate"])
    core_branch = float(package.attrib["branch-rate"])
    print(f"UrProtect.Core line-rate={core_line:.4f} branch-rate={core_branch:.4f}")
    if core_line < MIN_CORE_LINE_RATE:
        failures.append(f"UrProtect.Core line-rate {core_line:.4f} < {MIN_CORE_LINE_RATE:.4f}")
    if core_branch < MIN_CORE_BRANCH_RATE:
        failures.append(f"UrProtect.Core branch-rate {core_branch:.4f} < {MIN_CORE_BRANCH_RATE:.4f}")
    break
else:
    failures.append("UrProtect.Core package is missing from the coverage report")

if failures:
    print("coverage check failed:", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    raise SystemExit(1)

print("coverage check passed")
