"""Migration-critical state and registry integration regressions.

The task-plan markers are workflow state consumed by future agents, not prose
formatting. These tests catch accidental promotion of open product criteria.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path
from typing import Any, Iterator


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SUPERPOWERS_SOURCE = (
    "git:github.com/obra/superpowers@"
    "2ce8aa15d05bd57213e6f746f953aafb7ded7a8b"
)
MIGRATED_RUNTIME_SPEC = "docs/engineering/specs/backend/runtime-compatibility.md"
RETIRED_RUNTIME_SPEC = ".trellis/spec/backend/runtime-compatibility.md"
MARKER_PATTERN = re.compile(
    r"^- \[(?P<checkbox>[ x])\] \*\*(?P<state>open|complete): "
    r"(?P<criterion>[a-z0-9][a-z0-9.-]*)\*\* — "
)
HOST_LOCAL_SKILLS_PATH = re.compile(
    r"(?<![A-Za-z0-9_~.])/(?:[^/\s`'\"<>]+/)*\.pi/agent/skills/"
)


def _iter_json_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _iter_json_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_json_strings(item)


def _task_states(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    states: dict[str, str] = {}
    for line in text.splitlines():
        match = MARKER_PATTERN.match(line)
        if match is None:
            continue
        criterion = match.group("criterion")
        if criterion in states:
            raise AssertionError(f"duplicate task acceptance marker: {criterion}")
        checkbox = match.group("checkbox")
        declared_state = match.group("state")
        expected_checkbox = " " if declared_state == "open" else "x"
        if checkbox != expected_checkbox:
            raise AssertionError(f"inconsistent checkbox state: {criterion}")
        states[criterion] = declared_state
    return states


class SuperpowersMigrationTests(unittest.TestCase):
    def test_child_plan_keeps_narrow_safe_default_complete_and_remaining_scope_open(self) -> None:
        path = REPO_ROOT / "docs/superpowers/plans/2026-10-24-indirect-control-jump-tables.md"
        self.assertTrue(path.is_file(), "migrated indirect-control plan must exist")
        self.assertEqual(
            {
                "child.ambiguous-safe-default": "complete",
                "child.general-ownership": "open",
                "child.cross-runtime-evidence": "open",
            },
            _task_states(path),
        )

    def test_parent_plan_keeps_indirect_control_tls_and_cfi_scopes_open(self) -> None:
        path = REPO_ROOT / "docs/superpowers/plans/2026-10-24-unify-elf-protection-infrastructure.md"
        self.assertTrue(path.is_file(), "migrated infrastructure parent plan must exist")
        self.assertEqual(
            {
                "parent.indirect-control": "open",
                "parent.tls-runtime-tuples": "open",
                "parent.cfi-unwind-tuples": "open",
            },
            _task_states(path),
        )

    def test_fixture_registry_points_at_migrated_runtime_contract_and_retained_digest_matches(self) -> None:
        manifest_path = REPO_ROOT / "fixtures/manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        references = list(_iter_json_strings(manifest))

        self.assertIn(MIGRATED_RUNTIME_SPEC, references)
        self.assertNotIn(RETIRED_RUNTIME_SPEC, references)
        self.assertTrue((REPO_ROOT / MIGRATED_RUNTIME_SPEC).is_file())

        corpus = json.loads(
            (REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json").read_text(
                encoding="utf-8"
            )
        )
        retained = [
            item
            for item in corpus["retainedEvidenceRegistries"]
            if item.get("registryId") == "fixture-matrix"
        ]
        self.assertEqual(1, len(retained))
        self.assertEqual("fixtures/manifest.json", retained[0].get("path"))
        self.assertEqual(
            hashlib.sha256(manifest_bytes).hexdigest(), retained[0].get("sha256")
        )

    def test_project_pi_git_cache_is_ignored_and_only_guard_is_tracked(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "--", ".pi/git"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual([".pi/git/.gitignore"], tracked.stdout.splitlines())

        guard = REPO_ROOT / ".pi/git/.gitignore"
        self.assertTrue(guard.is_file())
        self.assertEqual("*\n!.gitignore\n", guard.read_text(encoding="utf-8"))
        ignored = subprocess.run(
            [
                "git",
                "check-ignore",
                "--quiet",
                "--no-index",
                ".pi/git/github.com/obra/superpowers/package.json",
            ],
            cwd=REPO_ROOT,
            check=False,
        )
        self.assertEqual(0, ignored.returncode, "the downloaded package cache must stay untracked")

    def test_trellis_runtime_entrypoints_and_agents_are_removed(self) -> None:
        removed_paths = (
            ".agents/skills/trellis-meta",
            ".pi/extensions/trellis",
            ".pi/agents/trellis-check.md",
            ".pi/agents/trellis-implement.md",
            ".pi/agents/trellis-research.md",
            ".pi/prompts/trellis-start.md",
            ".pi/prompts/trellis-continue.md",
            ".pi/prompts/trellis-finish-work.md",
            ".codex/agents/trellis-check.toml",
            ".codex/agents/trellis-implement.toml",
            ".codex/agents/trellis-research.toml",
            ".codex/hooks.json",
            ".codex/hooks/session-start.py",
            ".codex/hooks/inject-subagent-context.py",
            ".codex/hooks/inject-workflow-state.py",
        )
        for relative in removed_paths:
            with self.subTest(path=relative):
                self.assertFalse((REPO_ROOT / relative).exists())

        agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertNotIn("trellis", agents.lower())
        attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertNotIn("trellis", attributes.lower())

        settings = json.loads((REPO_ROOT / ".pi/settings.json").read_text(encoding="utf-8"))
        self.assertFalse(
            any("trellis" in value.lower() for value in _iter_json_strings(settings)),
            "Pi project settings must have no Trellis integration reference",
        )
        codex_config = (REPO_ROOT / ".codex/config.toml").read_text(encoding="utf-8")
        self.assertNotIn("trellis", codex_config.lower())

    def test_trellis_data_tree_is_fully_retired(self) -> None:
        self.assertFalse(
            (REPO_ROOT / ".trellis").exists(),
            "the complete Trellis data/config tree is removed only after migration checks pass",
        )

    def test_migration_design_and_plan_have_no_host_local_skill_paths(self) -> None:
        documents = (
            REPO_ROOT
            / "docs/superpowers/specs/2026-10-24-project-local-superpowers-and-trellis-retirement-design.md",
            REPO_ROOT
            / "docs/superpowers/plans/2026-10-24-project-local-superpowers-and-trellis-retirement.md",
        )
        for path in documents:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(
                    HOST_LOCAL_SKILLS_PATH.search(text),
                    "committed migration documents must not encode developer-local Pi skill paths",
                )

    def test_staged_pi_settings_register_only_the_exact_project_superpowers_pin(self) -> None:
        result = subprocess.run(
            ["git", "show", ":.pi/settings.json"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        settings = json.loads(result.stdout)
        strings = list(_iter_json_strings(settings))
        package_pins = [
            value for value in strings if value.startswith("git:github.com/obra/superpowers@")
        ]

        self.assertEqual([EXPECTED_SUPERPOWERS_SOURCE], package_pins)
        self.assertFalse(
            any(HOST_LOCAL_SKILLS_PATH.search(value) for value in strings),
            "staged project settings must not contain machine-local skill paths",
        )


if __name__ == "__main__":
    unittest.main()
