#!/usr/bin/env python3
"""Run the bounded, evidence-bound Scheme-A fixture scorer.

This scorer is deliberately bounded: it validates retained strict product
evidence, verifies the frozen per-family tool identity, and delegates one
actual family recipe invocation to that pinned tool.  It does not execute the
product image or alter product evidence.  Missing tools and blue evidence fail
closed rather than producing a fabricated strength factor.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import io
import hashlib
import os
import json
import resource
import shlex
import shutil
import subprocess
import runpy
import traceback
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEME_MANIFEST = Path(os.environ.get("EVALUATOR_SCHEME_A_MANIFEST", str(REPO_ROOT / "fixtures/evaluator/scheme-a-manifest.json")))
FAMILY_IDS = (
    "runtime_dump_reassembly",
    "patch_repack",
    "function_logic_recovery",
    "static_decomposition",
    "dynamic_instrumentation",
    "integrity_handoff",
)
ROLES = ("baseline", "candidate")
REPLICA_COUNT = 3
REQUIRED_PRODUCT_FILES = (
    "protected-image.bin",
    "native-image.bin",
    "target-loader.json",
    "behavioral-oracle.json",
)
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
CALIBRATION_ROUNDS_PER_UNIT = 256
NANOSECONDS_PER_WORK_UNIT = 1_000_000
BASELINE_WORK_UNITS = 1
CANDIDATE_WORK_UNITS = 100


class ScorerError(ValueError):
    """A bounded scorer input or evidence failure."""


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_json(value))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise ScorerError(f"missing product evidence file: {path.name}")
        if path.stat().st_size > 1_048_576:
            raise ScorerError(f"product evidence JSON exceeds its bound: {path.name}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScorerError(f"could not read product evidence JSON {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ScorerError(f"product evidence JSON root is not an object: {path.name}")
    return value


def _required_file(root: Path, name: str) -> Path:
    path = root / name
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ScorerError(f"missing or empty product evidence file: {name}")
    except OSError as error:
        raise ScorerError(f"cannot inspect product evidence file {name}: {error}") from error
    return path


def _load_scheme() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        manifest = json.loads(SCHEME_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScorerError(f"cannot read frozen Scheme-A manifest: {error}") from error
    families = manifest.get("requiredFamilies")
    family_ids = tuple(item.get("familyId") for item in families or () if isinstance(item, dict))
    if family_ids != FAMILY_IDS:
        raise ScorerError("frozen Scheme-A family order changed")
    if manifest.get("replicaCount") != REPLICA_COUNT:
        raise ScorerError("frozen Scheme-A replica count changed")
    budget = manifest.get("budget")
    if not isinstance(budget, dict):
        raise ScorerError("frozen Scheme-A budget is missing")
    return dict(budget), {item["familyId"]: item for item in families}


def _load_budget() -> dict[str, Any]:
    budget, _ = _load_scheme()
    return budget


def validate_product_evidence(product_root: Path) -> dict[str, Any]:
    """Validate the retained strict artifacts needed by the blue oracle."""
    try:
        if product_root.is_symlink() or not product_root.is_dir():
            raise ScorerError("strict product evidence root is unavailable")
    except OSError as error:
        raise ScorerError(f"cannot inspect strict product evidence root: {error}") from error

    protected_path = _required_file(product_root, "protected-image.bin")
    native_path = _required_file(product_root, "native-image.bin")
    target_path = _required_file(product_root, "target-loader.json")
    oracle_path = _required_file(product_root, "behavioral-oracle.json")
    target = _read_json(target_path)
    oracle = _read_json(oracle_path)
    if target.get("schemaVersion") != 1 or target.get("stage") != "target-loader" or target.get("status") != "passed":
        raise ScorerError("retained target-loader evidence is not passed")
    if oracle.get("schemaVersion") != 1 or oracle.get("stage") != "behavioral-oracle" or oracle.get("status") != "passed":
        raise ScorerError("retained blue behavioral oracle is missing or not passed")
    if oracle.get("stdoutEqual") is not True or oracle.get("stderrEqual") is not True:
        raise ScorerError("retained blue behavioral oracle did not prove stream equivalence")
    if target.get("targetStatus") != 0 or oracle.get("baselineStatus") != 0 or oracle.get("targetStatus") != 0:
        raise ScorerError("retained blue oracle has a nonzero target status")

    protected_sha256 = _sha256_file(protected_path)
    native_sha256 = _sha256_file(native_path)
    if protected_sha256 == native_sha256:
        raise ScorerError("Protected Image and Native Image evidence aliases")
    for record, label, expected in (
        (target, "target-loader.nativeImageSha256", native_sha256),
        (oracle, "behavioral-oracle.nativeImageSha256", native_sha256),
    ):
        declared = record.get(label.rsplit(".", 1)[-1])
        if declared is not None and declared != expected:
            raise ScorerError(f"{label} does not bind native-image.bin")
    return {
        "protectedImageSha256": protected_sha256,
        "nativeImageSha256": native_sha256,
        "targetLoaderSha256": _sha256_file(target_path),
        "behavioralOracleSha256": _sha256_file(oracle_path),
        "blueOracleEvidenceSha256": _sha256_file(oracle_path),
        "targetLoaderId": target.get("loaderId"),
        "oracleId": oracle.get("oracleId"),
    }


def _registered_tool(families: dict[str, Any], family_id: str) -> str:
    family = families.get(family_id)
    if not isinstance(family, dict):
        raise ScorerError(f"frozen Scheme-A family is missing: {family_id}")
    tool = family.get("tool")
    if not isinstance(tool, dict) or tool.get("availability") != "available":
        raise ScorerError(f"pinned scorer tool is not calibrated for {family_id}")
    name = tool.get("name")
    expected_digest = tool.get("binarySha256")
    if not isinstance(name, str) or not isinstance(expected_digest, str):
        raise ScorerError(f"pinned scorer tool identity is incomplete for {family_id}")
    executable = shutil.which(name)
    if executable is None:
        raise ScorerError(f"pinned scorer tool is unavailable for {family_id}: {name}")
    actual_digest = _sha256_file(Path(executable))
    if actual_digest != expected_digest:
        raise ScorerError(f"pinned scorer tool digest changed for {family_id}")
    return executable


def _validate_tool_result(
    result: dict[str, Any],
    *,
    family_id: str,
    role: str,
    replica: int,
    budget: dict[str, Any],
    evidence: dict[str, Any],
    output_root: Path,
) -> dict[str, Any]:
    if (
        result.get("kind") != "scheme-a-scorer-result"
        or result.get("familyId") != family_id
        or result.get("role") != role
        or result.get("replica") != replica
        or result.get("status") != "passed"
        or result.get("classification") != "attack-success"
        or result.get("goalAchieved") is not True
        or result.get("censored") is not False
        or result.get("manualStepsObserved") != 0
    ):
        raise ScorerError("registered scorer did not return a passed attack result")
    if result.get("budget") != budget:
        raise ScorerError("registered scorer changed the frozen Scheme-A budget")
    success_cpu_ns = result.get("successCpuNs")
    if isinstance(success_cpu_ns, bool) or not isinstance(success_cpu_ns, int) or success_cpu_ns <= 0:
        raise ScorerError("registered scorer did not return a finite success CPU cost")
    if success_cpu_ns > int(budget["cpuSeconds"]) * 1_000_000_000:
        raise ScorerError("registered scorer exceeded the frozen CPU budget")
    blue_oracle = result.get("blueOracle")
    if not isinstance(blue_oracle, dict) or blue_oracle.get("status") != "passed" or blue_oracle.get("evidenceSha256") != evidence["blueOracleEvidenceSha256"]:
        raise ScorerError("registered scorer did not bind the retained blue oracle")
    recovered_name = result.get("recoveredArtifact")
    if not isinstance(recovered_name, str) or not recovered_name or Path(recovered_name).is_absolute() or any(part in {"", ".", ".."} for part in Path(recovered_name).parts):
        raise ScorerError("registered scorer recovered artifact path is unsafe")
    recovered_path = output_root / recovered_name
    if recovered_path.is_symlink() or not recovered_path.is_file() or recovered_path.stat().st_size == 0:
        raise ScorerError("registered scorer did not retain a recovered artifact")
    if result.get("recoveredArtifactSha256") != _sha256_file(recovered_path) or result.get("recoveredArtifactSize") != recovered_path.stat().st_size:
        raise ScorerError("registered scorer recovered artifact binding is invalid")
    resource_path = output_root / "resource.json"
    if resource_path.is_symlink() or not resource_path.is_file() or resource_path.stat().st_size == 0:
        raise ScorerError("registered scorer did not retain resource evidence")
    return result




def _run_registered_tool_in_process(command: list[str], executable: str) -> tuple[int, str, str]:
    previous_argv = sys.argv
    stdout = io.StringIO()
    stderr = io.StringIO()
    sys.argv = [executable, *command[1:]]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                runpy.run_path(executable, run_name="__main__")
                status = 0
            except SystemExit as error:
                status = error.code if isinstance(error.code, int) else 1
            except Exception:
                traceback.print_exc()
                status = 1
    finally:
        sys.argv = previous_argv
    return status, stdout.getvalue(), stderr.getvalue()
def _run_registered_tool(
    executable: str,
    family_id: str,
    role: str,
    replica: int,
    product_root: Path,
    output_root: Path,
    budget: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    command = [
        executable,
        "--family",
        family_id,
        "--role",
        role,
        "--replica",
        str(replica),
        "--product-root",
        str(product_root),
        "--output-root",
        str(output_root),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=float(budget["wallSeconds"]),
        )
        completed_returncode = completed.returncode
        completed_stdout = completed.stdout
        completed_stderr = completed.stderr
    except OSError as error:
        if error.errno == errno.EAGAIN:
            completed_returncode, completed_stdout, completed_stderr = _run_registered_tool_in_process(command, executable)
        else:
            raise ScorerError(f"registered scorer could not run: {error}") from error
    except (subprocess.SubprocessError, ValueError) as error:
        raise ScorerError(f"registered scorer could not run: {error}") from error
    _write_common_streams(output_root, completed_stdout, completed_stderr)
    (output_root / "command.log").write_text(shlex.join(command) + "\n", encoding="utf-8")
    if completed_returncode != 0:
        raise ScorerError(f"registered scorer exited with status {completed_returncode}")
    result_path = output_root / "scorer-result.json"
    result = _read_json(result_path)
    return _validate_tool_result(
        result,
        family_id=family_id,
        role=role,
        replica=replica,
        budget=budget,
        evidence=evidence,
        output_root=output_root,
    )


def _resource_record(family_id: str, role: str, replica: int, budget: dict[str, Any], status: str, reason: str | None = None) -> dict[str, Any]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    record: dict[str, Any] = {
        "schemaVersion": 1,
        "statusOwner": "independent-evaluator",
        "status": status,
        "familyId": family_id,
        "role": role,
        "replica": replica,
        "budget": budget,
        "cpuSeconds": usage.ru_utime + usage.ru_stime,
        "rssBytes": int(usage.ru_maxrss) * 1024,
        "processes": 1,
    }
    if reason is not None:
        record["reason"] = reason
    return record


def _write_raw_manifest(output_root: Path) -> None:
    lines: list[str] = []
    for path in sorted(output_root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        lines.append(f"{_sha256_file(path)}  {path.relative_to(output_root).as_posix()}\n")
    (output_root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def _command_log() -> str:
    return shlex.join([sys.executable, *sys.argv]) + "\n"


def _write_common_streams(output_root: Path, stdout: str, stderr: str) -> None:
    (output_root / "stdout.txt").write_text(stdout[:MAX_CAPTURE_BYTES], encoding="utf-8")
    (output_root / "stderr.txt").write_text(stderr[:MAX_CAPTURE_BYTES], encoding="utf-8")
    (output_root / "command.log").write_text(_command_log(), encoding="utf-8")


def run_fixture(family_id: str, role: str, replica: int, product_root: Path, output_root: Path) -> tuple[dict[str, Any], int]:
    if family_id not in FAMILY_IDS:
        raise ScorerError(f"unknown Scheme-A family: {family_id}")
    if role not in ROLES:
        raise ScorerError(f"unknown Scheme-A role: {role}")
    if replica < 1 or replica > REPLICA_COUNT:
        raise ScorerError("replica is outside the frozen range 1..3")
    budget, families = _load_scheme()
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "command.log").write_text(_command_log(), encoding="utf-8")
    evidence = validate_product_evidence(product_root)
    executable = _registered_tool(families, family_id)
    result = _run_registered_tool(executable, family_id, role, replica, product_root, output_root, budget, evidence)
    _write_raw_manifest(output_root)
    return result, 0


def _write_failure(output_root: Path, family_id: str, role: str, replica: int, budget: dict[str, Any], reason: str) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    _write_common_streams(output_root, "", reason + "\n")
    _write_json(output_root / "resource.json", _resource_record(family_id, role, replica, budget, "environment-unavailable", reason))
    result = {
        "schemaVersion": 1,
        "kind": "scheme-a-scorer-result",
        "familyId": family_id,
        "role": role,
        "replica": replica,
        "status": "environment-unavailable",
        "classification": "environment-unavailable",
        "goalAchieved": False,
        "successCpuNs": None,
        "censored": False,
        "manualStepsObserved": 0,
        "budget": budget,
        "blueOracle": {"status": "environment-unavailable", "reason": reason},
        "recoveredArtifactSha256": None,
        "recoveredArtifactSize": 0,
        "resourceEvidence": "resource.json",
        "stdout": "stdout.txt",
        "stderr": "stderr.txt",
        "commandLog": "command.log",
        "reason": reason,
    }
    _write_json(output_root / "scorer-result.json", result)
    _write_raw_manifest(output_root)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=FAMILY_IDS, required=True)
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--replica", type=int, required=True)
    parser.add_argument("--product-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result, status = run_fixture(args.family, args.role, args.replica, args.product_root, args.output_root)
    except (OSError, ScorerError, ValueError) as error:
        try:
            budget = _load_budget()
        except ScorerError:
            budget = {}
        result = _write_failure(args.output_root, args.family, args.role, args.replica, budget, str(error))
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
