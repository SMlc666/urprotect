#!/usr/bin/env python3
"""Exercise CI Push/PR duplicate suppression with a mocked GitHub API.

No network, repo mutation or GitHub token is needed. The exact JS embedded in
the workflow is executed by Node to guard against drift in event semantics.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def probe_script(workflow: str) -> str:
    section = workflow.split("  ci-event-gate:\n", 1)[1].split("\n  build-and-test:\n", 1)[0]
    code = section.split("          script: |\n", 1)[1].split("\n      - name: Decide full verification", 1)[0]
    return "\n".join(line[12:] if line.startswith("            ") else line for line in code.splitlines())


class PushPrDedupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_exact_pr_probe_results_and_error_boundary(self) -> None:
        if shutil.which("node") is None:
            self.skipTest("Node.js required for the embedded github-script contract")
        code = probe_script(self.text)
        # This executes the *actual* action script with mocked context/github,
        # not a separately implemented approximation of its matching logic.
        js = r'''
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const evaluator = new AsyncFunction('context', 'github', 'core', SCRIPT);
const repo = 'SMlc666/urprotect', sha = 'abc123';
const exact = {
  number: 26, state: 'open',
  head: { ref: 'ci/example', sha, repo: { full_name: repo } },
  base: { repo: { full_name: repo } }
};
async function check(ref, headSha, pulls, throws = false) {
  const context = {
    repo: { owner: 'SMlc666', repo: 'urprotect' },
    ref, sha: headSha, payload: { repository: { default_branch: 'main' } }
  };
  const github = { rest: { pulls: { list: function noop() {} } },
    paginate: async function (_fn, options) {
      if (throws) throw new Error('unavailable API');
      if (options.head !== 'SMlc666:' + ref.slice('refs/heads/'.length)) {
        throw new Error('wrong head filter');
      }
      return pulls;
    } };
  try { return await evaluator(context, github, { info() {} }); }
  catch (error) { return 'error'; }
}
(async () => {
  const cases = [
    ['exact', 'refs/heads/ci/example', sha, [exact], false, 'skip'],
    ['different-sha', 'refs/heads/ci/example', 'other', [exact], false, 'run'],
    ['different-branch', 'refs/heads/ci/other', sha, [exact], false, 'run'],
    ['not-open', 'refs/heads/ci/example', sha, [{...exact, state:'closed'}], false, 'run'],
    ['fork-head', 'refs/heads/ci/example', sha,
      [{...exact, head:{...exact.head, repo:{full_name:'other/fork'}}}], false, 'run'],
    ['external-base', 'refs/heads/ci/example', sha,
      [{...exact, base:{repo:{full_name:'other/fork'}}}], false, 'run'],
    ['no-pr', 'refs/heads/ci/example', sha, [], false, 'run'],
    ['default-branch', 'refs/heads/main', sha,
      [{...exact, head:{...exact.head, ref:'main'}}], false, 'run'],
    ['tag', 'refs/tags/v0.1', sha, [exact], false, 'run'],
    ['api-failure', 'refs/heads/ci/example', sha, [exact], true, 'error']
  ];
  for (const [name, ref, headSha, pulls, throws, expected] of cases) {
    const result = await check(ref, headSha, pulls, throws);
    if (result !== expected) throw new Error(name + ': expected ' + expected + ', got ' + result);
  }
  process.stdout.write(String(cases.length));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''.replace("SCRIPT", json.dumps(code), 1)
        result = subprocess.run(
            ["node", "-e", js], cwd=ROOT, capture_output=True, text=True, timeout=12,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "10")

    def test_api_failure_and_non_push_are_always_full_verification(self) -> None:
        section = self.text.split("  ci-event-gate:\n", 1)[1].split("\n  build-and-test:\n", 1)[0]
        self.assertIn("if: github.event_name == 'push'", section)
        self.assertIn("continue-on-error: true", section)
        self.assertIn('PROBE_OUTCOME: ${{ steps.pr-probe.outcome }}', section)
        self.assertIn('"${PROBE_OUTCOME}" == success', section)
        self.assertIn('echo $\'run_full=true$\' >> "$GITHUB_OUTPUT"', section)
        self.assertIn("pull-requests: read", section)
        self.assertIn("runs-on: ubuntu-latest", section)

    def test_all_existing_jobs_guard_heavy_work_but_keep_previous_deps(self) -> None:
        jobs = re.findall(r"^  ([a-z][a-z0-9-]*):\n", self.text.split("\njobs:\n", 1)[1], re.M)
        self.assertEqual(len(jobs), 19)
        self.assertEqual(jobs[0], "ci-event-gate")
        matches = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\n", self.text, re.M))
        for i, match in enumerate(matches):
            if match.group(1) == "ci-event-gate":
                continue
            end = matches[i+1].start() if i+1 < len(matches) else len(self.text)
            block = self.text[match.start():end]
            self.assertIn("needs['ci-event-gate'].outputs.run_full == 'true'", block)
            self.assertIn("ci-event-gate", block.split("\n    steps:", 1)[0])
        self.assertIn("needs: [ci-event-gate, bionic-native-arm64]", self.text)
        self.assertIn("      - strict-compatibility-shard", self.text)
        self.assertIn("      - independent-evaluator", self.text)
        self.assertIn("      - managed-tests", self.text)
        self.assertIn("if: ${{ needs['ci-event-gate'].outputs.run_full == 'true' && (!cancelled()) }}", self.text)

    def test_separate_ref_scopes_preserve_pr_not_cancelled_by_push(self) -> None:
        self.assertIn("group: urprotect-ci-${{ github.ref }}", self.text)
        self.assertIn("cancel-in-progress: true", self.text)
        self.assertNotIn("urprotect-ci-${{ github.head_ref", self.text)


if __name__ == "__main__":
    unittest.main()
