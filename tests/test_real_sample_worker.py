#!/usr/bin/env python3
"""Regression tests for file-based real-sample worker scripts."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
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
        self.assertIn("normalize_worker_script()", source)
        self.assertIn('bash -n "${worker_script}"', source)
        self.assertIn("mark_worker_script_failure", source)
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

    def test_embedded_evidence_sanitizer_python_parses(self) -> None:
        source = MATRIX.read_text(encoding="utf-8")
        opening = source.index("<<'PYSANITIZE'; then\n") + len("<<'PYSANITIZE'; then\n")
        closing = source.index("\nPYSANITIZE\n", opening)
        embedded_python = source[opening:closing]

        compile(embedded_python, f"{MATRIX}:PYSANITIZE", "exec")

    def test_bionic_policy_heredoc_keeps_repo_argument_in_argv_shape(self) -> None:
        source = MATRIX.read_text(encoding="utf-8")
        opening = source.index("<<'PY_BIONIC_POLICY'\n") + len("<<'PY_BIONIC_POLICY'\n")
        closing = source.index("\nPY_BIONIC_POLICY\n", opening)
        embedded_python = source[opening:closing]
        lock = ROOT / "fixtures/real-samples/bionic-node-runtime-lock.json"
        manifest = ROOT / "fixtures/real-samples/manifest.json"
        result = subprocess.run(
            [
                "python3",
                "-",
                str(ROOT),
                str(lock),
                str(manifest),
                "data/data/com.termux/files/usr/bin/node",
            ],
            cwd=ROOT,
            input=embedded_python,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = result.stdout.splitlines()
        self.assertEqual(len(values), 5)
        self.assertEqual(values[1], "0")
        self.assertEqual(values[2], "outer-path-preserving")

    @staticmethod
    def _worker_definition_source() -> str:
        source = MATRIX.read_text(encoding="utf-8")
        start = source.index("project_fields() {")
        end = source.index(
            "# Worker scripts inherit only scalar environment variables.",
            start,
        )
        return "set -euo pipefail\n" + source[start:end]

    @staticmethod
    def _declare_worker_functions() -> str:
        declare_block = "  declare -f \\\n" + "".join(
            f"    {name} \\\n" for name in WORKER_FUNCTIONS[:-1]
        )
        return declare_block + f"    {WORKER_FUNCTIONS[-1]}"

    @staticmethod
    def _heredoc_markers(script: str) -> tuple[list[str], list[str]]:
        opening = re.compile(
            r"(?<!<)<<-?[ \t]*(?:['\"]?)(PY[A-Za-z0-9_]*)(?:['\"]?)"
            r"(?:[ \t]*(?:(?:;[ \t]*(?:then|do)\b)|(?:\|\||&&)|(?:#[^\r\n]*)))?[ \t]*$"
        )
        terminator = re.compile(r"[ \t]*(PY[A-Za-z0-9_]*)[ \t]*$")
        openings: list[str] = []
        terminators: list[str] = []
        for line in script.splitlines():
            match = opening.search(line)
            if match is not None:
                openings.append(match.group(1))
            match = terminator.fullmatch(line)
            if match is not None:
                terminators.append(match.group(1))
        return openings, terminators

    def test_actual_worker_function_graph_is_normalized_and_syntax_checked(self) -> None:
        definitions = self._worker_definition_source()
        declare_block = self._declare_worker_functions()
        generator = r'''set -euo pipefail
source "$1"
registry="$2"
worker_script="$3"
worker_index="$4"
umask 077
: > "$worker_script"
{
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'if [[ "$#" -ne 2 ]]; then exit 2; fi' \
    'shift'
__DECLARE_BLOCK__ | sed -E '/^[[:space:]]*PY[A-Za-z0-9_]*[[:space:]]*$/s/^/    /'
  printf '%s\n' \
    'set -euo pipefail' \
    'dotnet_cli=(dotnet "${cli_dll}")' \
    'process_project "$1"'
} > "$worker_script"
normalize_worker_script "$worker_script" "$registry" "$worker_index"
bash -n "$worker_script"
'''.replace("__DECLARE_BLOCK__", declare_block)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definitions_path = root / "worker-definitions.sh"
            registry = root / "worker-registry"
            worker_path = registry / "worker-1.ABC123.sh"
            registry.mkdir(mode=0o700)
            definitions_path.write_text(definitions, encoding="utf-8")
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    generator,
                    "worker-generator",
                    str(definitions_path),
                    str(registry),
                    str(worker_path),
                    "1",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            generated = worker_path.read_text(encoding="utf-8")
            self.assertEqual(worker_path.stat().st_mode & 0o777, 0o600)
            for name in WORKER_FUNCTIONS:
                self.assertRegex(generated, rf"(?m)^{re.escape(name)} \(\)\s*$")

            openings, terminators = self._heredoc_markers(generated)
            self.assertTrue(openings)
            self.assertEqual(Counter(openings), Counter(terminators))
            for line in generated.splitlines():
                if re.fullmatch(r"[ \t]*PY[A-Za-z0-9_]*[ \t]*", line):
                    self.assertEqual(line, line.lstrip(" \t"))

            syntax = subprocess.run(
                ["bash", "-n", str(worker_path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

            lines = generated.splitlines(keepends=True)
            tabbed_index = next(
                index
                for index, line in enumerate(lines)
                if re.fullmatch(r"[ \t]*PY[A-Za-z0-9_]*[ \t]*\r?\n", line)
            )
            terminator = lines[tabbed_index].lstrip(" \t")
            lines[tabbed_index] = "\t" + terminator
            worker_path.write_text("".join(lines), encoding="utf-8")
            tabbed = worker_path.read_text(encoding="utf-8")
            self.assertIn("\t" + terminator, tabbed)

            normalizer = r'''set -euo pipefail
source "$1"
normalize_worker_script "$2" "$3" "$4"
'''
            normalized_result = subprocess.run(
                [
                    "bash",
                    "-c",
                    normalizer,
                    "worker-normalizer",
                    str(definitions_path),
                    str(worker_path),
                    str(registry),
                    "1",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(normalized_result.returncode, 0, normalized_result.stderr)
            normalized = worker_path.read_text(encoding="utf-8")
            normalized_openings, normalized_terminators = self._heredoc_markers(
                normalized
            )
            self.assertEqual(
                Counter(normalized_openings), Counter(normalized_terminators)
            )
            for line in normalized.splitlines():
                if re.fullmatch(r"[ \t]*PY[A-Za-z0-9_]*[ \t]*", line):
                    self.assertEqual(line, line.lstrip(" \t"))

            normalized_syntax = subprocess.run(
                ["bash", "-n", str(worker_path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(normalized_syntax.returncode, 0, normalized_syntax.stderr)

    def test_worker_normalizer_handles_trailing_shell_syntax_and_tab_marker(self) -> None:
        definitions = self._worker_definition_source()
        fixture = """#!/usr/bin/env bash
set -euo pipefail
if ! python3 - <<-'PY_TRAILING'; then
print("fixture")
\tPY_TRAILING
  printf '%s\\n' 'python failed' >&2
  exit 1
fi
if ! python3 - <<PY_UNQUOTED; then
print("unquoted fixture")
PY_UNQUOTED
  printf '%s\\n' 'python failed' >&2
  exit 1
fi
"""
        normalizer = r'''set -euo pipefail
source "$1"
normalize_worker_script "$2" "$3" "$4"
'''

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definitions_path = root / "worker-definitions.sh"
            registry = root / "worker-registry"
            worker_path = registry / "worker-1.TRAILING.sh"
            registry.mkdir(mode=0o700)
            registry.chmod(0o700)
            definitions_path.write_text(definitions, encoding="utf-8")
            worker_path.write_text(fixture, encoding="utf-8")
            worker_path.chmod(0o600)

            before = worker_path.read_text(encoding="utf-8")
            self.assertIn("<<-'PY_TRAILING'; then\n", before)
            self.assertIn("\tPY_TRAILING\n", before)
            self.assertIn("<<PY_UNQUOTED; then\n", before)
            initial_syntax = subprocess.run(
                ["bash", "-n", str(worker_path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(initial_syntax.returncode, 0, initial_syntax.stderr)

            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    normalizer,
                    "worker-normalizer",
                    str(definitions_path),
                    str(worker_path),
                    str(registry),
                    "1",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            normalized = worker_path.read_text(encoding="utf-8")
            for marker in ("PY_TRAILING", "PY_UNQUOTED"):
                self.assertIn(f"\n{marker}\n", normalized)
            self.assertNotIn("\tPY_TRAILING\n", normalized)
            normalized_syntax = subprocess.run(
                ["bash", "-n", str(worker_path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(normalized_syntax.returncode, 0, normalized_syntax.stderr)

    def test_worker_normalizer_rejects_unpaired_and_extra_markers(self) -> None:
        definitions = self._worker_definition_source()
        normalizer = r'''set -euo pipefail
source "$1"
normalize_worker_script "$2" "$3" "$4"
'''
        malformed_fixtures = {
            "unpaired-opening": "#!/usr/bin/env bash\npython3 <<'PY_EXPECTED'\nprint('x')\n",
            "unpaired-marker": (
                "#!/usr/bin/env bash\npython3 <<'PY_EXPECTED'\n"
                "PY_OTHER\nPY_EXPECTED\n"
            ),
            "duplicate-marker": (
                "#!/usr/bin/env bash\npython3 <<'PY_EXPECTED'\n"
                "PY_EXPECTED\nPY_EXPECTED\n"
            ),
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definitions_path = root / "worker-definitions.sh"
            registry = root / "worker-registry"
            registry.mkdir(mode=0o700)
            registry.chmod(0o700)
            definitions_path.write_text(definitions, encoding="utf-8")

            for suffix, fixture in malformed_fixtures.items():
                with self.subTest(fixture=suffix):
                    worker_path = registry / f"worker-1.{suffix}.sh"
                    worker_path.write_text(fixture, encoding="utf-8")
                    worker_path.chmod(0o600)
                    result = subprocess.run(
                        [
                            "bash",
                            "-c",
                            normalizer,
                            "worker-normalizer",
                            str(definitions_path),
                            str(worker_path),
                            str(registry),
                            "1",
                        ],
                        cwd=ROOT,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_worker_normalizer_rejects_unexpected_and_symlink_paths(self) -> None:
        definitions = self._worker_definition_source()
        normalizer = r'''set -euo pipefail
source "$1"
normalize_worker_script "$2" "$3" "$4"
'''

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definitions_path = root / "worker-definitions.sh"
            registry = root / "worker-registry"
            registry.mkdir(mode=0o700)
            definitions_path.write_text(definitions, encoding="utf-8")

            unexpected = root / "unexpected.sh"
            unexpected.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            unexpected_result = subprocess.run(
                [
                    "bash",
                    "-c",
                    normalizer,
                    "worker-normalizer",
                    str(definitions_path),
                    str(unexpected),
                    str(registry),
                    "1",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(unexpected_result.returncode, 0)

            target = root / "worker-target.sh"
            target.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            symlink = registry / "worker-1.LINK.sh"
            symlink.symlink_to(target)
            symlink_result = subprocess.run(
                [
                    "bash",
                    "-c",
                    normalizer,
                    "worker-normalizer",
                    str(definitions_path),
                    str(symlink),
                    str(registry),
                    "1",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(symlink_result.returncode, 0)

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
