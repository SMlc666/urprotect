import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-architecture-boundaries.py"
FIXTURE = ROOT / "tests" / "ArchitectureFixtures" / "ForbiddenStructuralDependency.cs"
STRUCTURAL_DIR = ROOT / "src" / "UrProtect.Core" / "StructuralElf"


CHECKER_SPEC = importlib.util.spec_from_file_location("architecture_checker", CHECKER)
assert CHECKER_SPEC is not None and CHECKER_SPEC.loader is not None
CHECKER_MODULE = importlib.util.module_from_spec(CHECKER_SPEC)
sys.modules[CHECKER_SPEC.name] = CHECKER_MODULE
CHECKER_SPEC.loader.exec_module(CHECKER_MODULE)


class ArchitectureBoundaryTests(unittest.TestCase):
    def run_checker(self, *arguments):
        return subprocess.run(
            [sys.executable, str(CHECKER), *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_production_tree_passes(self):
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("production tree passed", result.stdout)

    def test_forbidden_fixture_is_detected_without_entering_production(self):
        result = self.run_checker("--fixture", str(FIXTURE))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forbidden fixture detected", result.stdout)
        self.assertIn("cannot depend on UrProtect.Core.Application", result.stdout)

    def test_self_test_turns_expected_fixture_failure_into_a_passing_gate(self):
        result = self.run_checker(
            "--fixture",
            str(FIXTURE),
            "--self-test",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("forbidden fixture detected", result.stdout)

    def test_checker_ignores_comments_and_literals_but_catches_inline_and_implicit_dependencies(self):
        cases = {
            "comments-and-literals": (
                "namespace UrProtect.Core.StructuralElf;\n"
                "// UrProtect.Core.Application and System.IO are documentation only.\n"
                'internal sealed class Fixture { private const string Text = "UrProtect.Core.Application"; }\n',
                False,
            ),
            "qualified-reference": (
                "namespace UrProtect.Core.StructuralElf;\n"
                "internal sealed class Fixture { private UrProtect.Core.Application.Validation.ValidationWorkflow Workflow = new(); }\n",
                True,
            ),
            "global-using-alias": (
                "global using App = global::UrProtect.Core.Application.Validation.ValidationWorkflow;\n"
                "namespace UrProtect.Core.StructuralElf;\n"
                "internal sealed class Fixture { private App Workflow = new(); }\n",
                True,
            ),
            "implicit-filesystem-api": (
                "namespace UrProtect.Core.StructuralElf;\n"
                "internal sealed class Fixture { private byte[] Read(string path) => File.ReadAllBytes(path); }\n",
                True,
            ),
        }
        for name, (source, should_fail) in cases.items():
            with self.subTest(name=name):
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=".cs",
                    prefix=f".{name}-",
                    dir=STRUCTURAL_DIR,
                    delete=False,
                    encoding="utf-8",
                ) as handle:
                    handle.write(source)
                    path = Path(handle.name)
                try:
                    failures = CHECKER_MODULE.check_sources(ROOT, [path])
                finally:
                    path.unlink()
                self.assertEqual(bool(failures), should_fail, failures)
                if name == "qualified-reference":
                    self.assertTrue(any("cannot depend on UrProtect.Core.Application" in failure for failure in failures))
                if name == "implicit-filesystem-api":
                    self.assertTrue(any("forbidden filesystem/process reference" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
