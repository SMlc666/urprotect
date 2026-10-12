#!/usr/bin/env python3
"""Enforce the initial coverage floor for the project-owned code."""

from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

MIN_LINE_RATE = 0.65
MIN_BRANCH_RATE = 0.30
MIN_CORE_LINE_RATE = 0.50
MIN_CORE_BRANCH_RATE = 0.35
VENDORED_PACKAGES = {"AsmStone"}

reports = sorted(Path(".").glob("tests/**/TestResults/**/coverage.cobertura.xml"))
if not reports:
    raise SystemExit("coverage report not found")

report = max(reports, key=lambda path: path.stat().st_mtime)
root = ET.parse(report).getroot()
print(f"coverage report: {report}")


def package_rates(package: ET.Element) -> tuple[float, float]:
    covered_lines = 0
    valid_lines = 0
    covered_branches = 0
    valid_branches = 0
    for line in package.findall("./classes/class/lines/line"):
        valid_lines += 1
        if int(line.attrib.get("hits", "0")) > 0:
            covered_lines += 1
        if line.attrib.get("branch", "False").lower() != "true":
            continue
        match = re.search(r"\((\d+)/(\d+)\)", line.attrib.get("condition-coverage", ""))
        if match is None:
            continue
        covered_branches += int(match.group(1))
        valid_branches += int(match.group(2))
    line_rate = covered_lines / valid_lines if valid_lines else 1.0
    branch_rate = covered_branches / valid_branches if valid_branches else 1.0
    return line_rate, branch_rate


packages = root.findall("./packages/package")
project_packages = [package for package in packages if package.attrib.get("name") not in VENDORED_PACKAGES]
if not project_packages:
    raise SystemExit("no project-owned packages remain after excluding vendored packages")

project_lines = sum(
    len(package.findall("./classes/class/lines/line"))
    for package in project_packages
)
project_covered_lines = sum(
    sum(
        int(line.attrib.get("hits", "0")) > 0
        for line in package.findall("./classes/class/lines/line")
    )
    for package in project_packages
)
project_covered_branches = 0
project_valid_branches = 0
for package in project_packages:
    for line in package.findall("./classes/class/lines/line"):
        if line.attrib.get("branch", "False").lower() != "true":
            continue
        match = re.search(r"\((\d+)/(\d+)\)", line.attrib.get("condition-coverage", ""))
        if match is not None:
            project_covered_branches += int(match.group(1))
            project_valid_branches += int(match.group(2))

line_rate = project_covered_lines / project_lines if project_lines else 1.0
branch_rate = project_covered_branches / project_valid_branches if project_valid_branches else 1.0
print(f"project-owned line-rate={line_rate:.4f} branch-rate={branch_rate:.4f}")
excluded = ", ".join(sorted(VENDORED_PACKAGES & {package.attrib.get("name", "") for package in packages}))
if excluded:
    print(f"excluded vendored packages: {excluded}")

failures = []
if line_rate < MIN_LINE_RATE:
    failures.append(f"overall line-rate {line_rate:.4f} < {MIN_LINE_RATE:.4f}")
if branch_rate < MIN_BRANCH_RATE:
    failures.append(f"overall branch-rate {branch_rate:.4f} < {MIN_BRANCH_RATE:.4f}")

for package in packages:
    if package.attrib.get("name") != "UrProtect.Core":
        continue
    core_line, core_branch = package_rates(package)
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
