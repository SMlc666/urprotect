#!/usr/bin/env python3
"""Regression tests for file-based real-sample worker scripts."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "scripts/run-real-sample-matrix.sh"
WORKER_FUNCTIONS = (
    "project_fields",
    "write_result",
    "write_runtime_closure_record",
    "record_pack_cli_status",
    "write_outer_pack_boundary",
    "remove_unreferenced_preflight_markers",
    "write_execution_evidence",
    "write_failure_evidence",
    "classify_isolation_result",
    "read_isolation_result",
    "run_isolated_command",
    "run_isolated_baseline",
    "prepare_runtime_root",
    "resolve_artifact",
    "process_project",
)


class RealSampleWorkerTests(unittest.TestCase):
    def test_matrix_materializes_workers_without_function_export(self) -> None:
        source = MATRIX.read_text(encoding="utf-8")

        self.assertNotIn("export -f", source)
        self.assertNotIn("bash -c 'set -euo pipefail; dotnet_cli=", source)
        self.assertIn('worker_script="$(\n', source)
        self.assertIn(
            'mktemp "${worker_registry_dir}/worker-${worker_registry_index}.XXXXXX.sh"',
            source,
        )
        self.assertIn('bash "${worker_script}" _ "${project_json}"', source)
        self.assertIn("remove_worker_scripts()", source)
        self.assertIn("if ! remove_worker_scripts; then", source)

        declare_block = "declare -f \\\n" + "".join(
            f"      {name} \\\n" for name in WORKER_FUNCTIONS[:-1]
        )
        declare_block += f"      {WORKER_FUNCTIONS[-1]}"
        self.assertIn(declare_block, source)

    def test_generated_worker_scalar_environment_exports_launcher_path(self) -> None:
        source = MATRIX.read_text(encoding="utf-8")
        lines = source.splitlines()
        export_start = next(
            (index for index, line in enumerate(lines) if line.startswith("export repo_root ")),
            None,
        )
        if export_start is None:
            self.fail("worker scalar export block is missing")

        export_lines = [lines[export_start]]
        while export_lines[-1].rstrip().endswith("\\"):
            next_index = len(export_lines) + export_start
            self.assertLess(next_index, len(lines), "worker scalar export block is truncated")
            export_lines.append(lines[next_index])

        exported_names = " ".join(export_lines).replace("\\", " ").split()[1:]
        self.assertIn(
            "launcher_path",
            exported_names,
            "launcher_path must be inherited by every generated worker",
        )

    def test_heredoc_function_runs_from_a_fresh_generated_bash_script(self) -> None:
        fixture = """#!/usr/bin/env bash
set -euo pipefail

write_result() {
  python3 - "$1" <<'PY_WORKER_RESULT'
import sys
print(sys.argv[1])
PY_WORKER_RESULT
}

process_project() {
  write_result "$1"
}
"""
        project_json = '{"projectId":"quoted \\\"record\\\"","value":"$HOME"}'

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "worker-source.sh"
            worker_path = root / "worker.sh"
            source_path.write_text(fixture, encoding="utf-8")
            generator = r'''set -euo pipefail
source "$1"
export cli_dll=/usr/bin/dotnet
worker_script="$2"
{
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'if [[ "$#" -ne 2 ]]; then exit 2; fi' \
    'shift'
  declare -f write_result process_project
  printf '%s\n' \
    'set -euo pipefail' \
    'dotnet_cli=(dotnet "${cli_dll}")' \
    'process_project "$1"'
} > "$worker_script"
chmod 700 "$worker_script"
bash "$worker_script" _ "$3"
'''
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    generator,
                    "worker-generator",
                    str(source_path),
                    str(worker_path),
                    project_json,
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, project_json + "\n")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
