# Project-local Superpowers adoption and Trellis retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use Superpowers `executing-plans` to implement this plan task-by-task. Make one migration task at a time, keep each checkpoint reviewable, and do not proceed past an approval gate without explicit user approval.

**Goal:** Adopt upstream Superpowers v7.0.1 as a project-local Pi package pinned to commit `2ce8aa15d05bd57213e6f746f953aafb7ded7a8b`, migrate durable engineering guidance and both active Trellis task states, then retire Trellis project integration and files without losing user data or altering product/runtime claims.

**Architecture:** `.pi/settings.json` is the sole Superpowers registration point; no global Pi settings, trust state, or Codex integration is changed. `docs/engineering/` becomes the durable source for project contracts, and `docs/superpowers/plans/` holds this migration plus the migrated active child and parent work plans. The entire `.trellis/` tree is removed only after these docs and the pinned Pi integration pass review and validation.

**Tech Stack:** Pi project package CLI, pinned Git source, Markdown, JSON, Python `unittest`, project fixture/regression validators, native C self-tests, Git, SHA-256 backup manifests.

**Design:** [project-local Superpowers adoption and Trellis retirement](../specs/2026-10-24-project-local-superpowers-and-trellis-retirement-design.md)

## Global constraints

1. Install only with `pi install --local git:github.com/obra/superpowers@2ce8aa15d05bd57213e6f746f953aafb7ded7a8b`; upstream URI is `https://github.com/obra/superpowers`. Verify the checked-out source has exactly that full SHA. Pi may keep its managed source cache under the user agent directory, but the package declaration must exist only in this project's `.pi/settings.json`; do not alter global package registration or global settings.
2. Do not install/configure Superpowers for Codex. Preserve generic Codex configuration, but remove only Trellis-specific Codex agents/hooks.
3. Use one-time `pi --approve` for a controlled fresh validation process; do not write or alter `~/.pi/agent/trust.json`. If project-only validation cannot be done without persistent trust, stop and request separate user consent.
4. Before migration edits or deletion, make restrictive, byte-exact external backups of the current `.gitattributes`, `.pi/settings.json`, and workspace journal diffs, and archive the entire `.trellis/` tree with per-file mode/SHA-256 manifest. Do not commit these backups. Preserve `.gitattributes`, user-owned `.pi/settings.json` entries, journal facts, and ignored runtime state; rollback must restore byte-identical bytes/modes.
5. Never commit host-specific absolute skill paths from the dirty `.pi/settings.json`. Keep those pre-existing worktree entries byte-exactly unchanged; construct and verify a project-only staged settings blob and inspect it with `git show :.pi/settings.json` before commit.
6. Preserve the child open criteria for general/exhaustive ownership and remaining variants, shared-musl and ordinary/shared Bionic evidence; preserve the parent open criteria for indirect-control, broader TLS, and broader CFI/runtime tuples. Migration is administrative only and may not mark any criterion complete.
7. Keep feature/runtime status `unknown` / non-promoted where currently specified. Do not regenerate or relabel failing local provider roots; retain the distinct local provenance-member-count failure and rollback missing-script failure, and distinguish them from hosted runs `39559228628` and `39561529902`.
8. No product code, ABI, fixture behavior, or runtime support status changes are in scope. Do not push. Keep the source task records recoverable through Git history.

## Review Focus

1. Child task: exhaustive owner enumeration, private/shared inference, symbol-less selections, non-current table encodings, and metadata-missing variants must stay open. Guard with `tests/test_superpowers_migration.py` and the migrated plan's explicit unchecked section.
2. Runtime evidence: shared-musl and ordinary/shared Bionic remain open; the hosted Bionic helper-maps failure is not converted to success by local checker tests. Assert exact status language in the migration regression tests and plan.
3. Provider evidence: local exact-root failures remain visible next to (not substituted by) hosted run evidence. Keep the current failure reason and hosted run IDs in the migrated plans/docs.
4. Pi scope and trust: registration is project-local at the exact commit; no global settings/package/trust writes, no Codex Superpowers setup, and no machine-specific absolute skill paths in migration commits. Verify hashes/state and inspect staged JSON.
5. Rollback: the original dirty files and complete `.trellis/` tree remain restorable after each destructive phase. Verify archive hashes/modes before deletion and after a restore rehearsal in a temporary directory.

## Tasks

### Task 1: Protect the existing worktree and capture a rollback baseline

**Files:** external private backup directory only; no repository edits in this task.

- [x] Create a private backup directory outside the repo (`umask 077`; directory mode `0700`). Record its absolute path for the user in the migration plan checkpoint.
- [x] Save the exact current `.gitattributes`, `.pi/settings.json`, and `.trellis/workspace/SMlc666/journal-1.md` bytes, plus `git diff --binary` for these paths, file modes, and SHA-256 hashes. Do not print the settings contents or copy host skill paths into committed files.
- [x] Archive the complete `.trellis/` tree, including ignored `.runtime/`, `.developer`, and `scripts/common/__pycache__/`, preserving permissions and symlinks. Write a bounded per-file path/type/mode/size/SHA-256 manifest outside the repo.
- [x] Verify the backup manifest against the live tree and run a restore rehearsal into a new temporary directory; compare hashes/modes there. Do not overwrite the working tree during the rehearsal.
- [x] Record dispositions: keep the `.gitattributes` obsolete journal rule out of the final tree; preserve existing `.pi/settings.json` absolute skill entries locally but exclude them from commits; transfer unique journal facts into the active plans; retain the archive until migration acceptance.

**Validation:** `sha256sum -c "$BACKUP/sha256sums"`; compare `stat` modes; Python manifest audit rejects missing, extra, or changed `.trellis/` entries. Stop if the backup is incomplete.

### Task 2: Add regression tests for migration-critical state (RED first)

**Files:** `tests/test_superpowers_migration.py` (new).

- [x] Use the marker grammar `- [ ] **open: <stable-id>** — ...` and `- [x] **complete: <stable-id>** — ...` for task acceptance state; write tests that parse markers and enforce child narrow `Ambiguous` safe-default scoped-complete plus exactly two required open markers, and parent exactly three open markers for indirect-control, TLS/runtime tuples, and CFI/unwind tuples. A status mutation must fail.
- [x] Verify descriptive acceptance scope, Bionic failure caveat, local-versus-hosted provider-root distinction, hosted run IDs, and parent/child state by independent line-by-line source-to-target review in Task 4; do not create brittle free-form-prose or date-string assertions.
- [x] Assert the fixture-manifest runtime-reference path targets the migrated engineering doc and its `fixture-matrix` retained-registry digest equals SHA-256 of `fixtures/manifest.json`.
- [x] Assert the planned `.pi/settings.json` migration has one project-local Superpowers Git source at the exact commit and no committed host-specific absolute skills-directory paths. Keep assertion logic independent of user-local uncommitted paths by checking the staged/project-owned representation or a dedicated expected configuration fixture, not the raw dirty worktree file.
- [x] Run the new module and confirm the acceptance-preservation cases fail before writing the migrated plans (RED). Do not weaken assertions merely to get a pass.

**Validation:** `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_superpowers_migration`.

### Task 3: Migrate durable engineering specifications and references

**Files:** all 20 current `.trellis/spec/{backend,frontend,guides}/*.md` documents become `docs/engineering/specs/{backend,frontend,guides}/*.md`; add `docs/engineering/README.md`; update `AGENTS.md` in a later integration task; update `fixtures/manifest.json`, `fixtures/evaluator/compatibility-corpus.json`, `tests/test_fixture_matrix.py`, and any links found by repository search.

- [x] Copy and review backend, frontend, and shared-guide documents into `docs/engineering/specs/`, retaining one-to-one file names and all durable executable contracts. Remove Trellis lifecycle instructions only; do not collapse safety requirements into a generic Superpowers reference.
- [x] Add `docs/engineering/README.md` with a discoverable index, source-of-truth statement, layers, and links to all migrated indexes/specs.
- [x] Update internal relative links and all operational `.trellis/spec/...` references, including `fixtures/manifest.json` evidence paths and the two assertions in `tests/test_fixture_matrix.py`. Review each changed line to ensure evidence claims themselves are not altered.
- [x] Recompute only the fixture-matrix SHA-256 entry in `fixtures/evaluator/compatibility-corpus.json` after editing `fixtures/manifest.json`; leave frozen product-evidence baselines and unrelated retained registry entries unchanged.
- [x] Run migration unit tests; run the full `tests.test_fixture_matrix` and `tests.test_real_sample_manifest` modules; run `scripts/validate-fixtures.py fixtures/manifest.json --tier pr` and `scripts/validate-runtime-matrix.py fixtures/runtime-matrix.json`.
- [x] Search migrated docs, fixture registry, tests, and scripts for stale executable `.trellis/spec/` paths. Historical mention in this plan/design is allowed; live evidence paths are not.

**Validation:**

```sh
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_superpowers_migration tests.test_fixture_matrix tests.test_real_sample_manifest
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-runtime-matrix.py fixtures/runtime-matrix.json
```

### Task 4: Migrate the two active Trellis task states into Superpowers plans

**Files:**
- `docs/superpowers/plans/2026-10-24-indirect-control-jump-tables.md` (new)
- `docs/superpowers/plans/2026-10-24-unify-elf-protection-infrastructure.md` (new)
- `tests/test_superpowers_migration.py`

- [x] Write the child plan with its goal, parent dependency, current `in_progress` state, completed milestones as provenance only, test/evidence paths, and each source PRD unchecked criterion reproduced as open work.
- [x] Preserve the child's exact remaining scopes: general/exhaustive owner inventory and private/shared inference beyond current validated pair evidence; other table forms/instruction chains; symbol-less and metadata-missing cases; shared-musl and ordinary/shared Bionic runtime evidence. Record current Bionic helper-maps hosted failure and the local-vs-hosted provider root discrepancies without claiming resolution.
- [x] Write the parent plan with current 6/7 milestone state, child dependency, and its three open PRD areas: indirect-control, remaining TLS model/runtime/profile/lifecycle tuples, and remaining CFI/unwind runtime/profile tuples. Include completed native glibc observations only as scoped provenance.
- [x] Transfer useful active journal facts needed to resume work; omit unrelated workstation transcript details. Do not bulk-copy archived task folders; Git history is the archive source.
- [x] Rerun the migration regression module and reconcile every open checkbox in both plans against the two source PRDs and the latest implementation checkpoints before removing Trellis.

**Validation:** `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_superpowers_migration`; manually compare source acceptance lists and evidence IDs; reviewer must confirm no criterion was dropped, upgraded, or conflated.

### Task 5: Audit and activate the pinned Superpowers Pi package locally

**Files:** `.pi/settings.json` (project-local package registration only; special staging rules apply); `.pi/git/.gitignore` (Pi-generated cache guard only); temporary upstream checkout and isolated validation project outside the repository.

- [x] Fetch `https://github.com/obra/superpowers` into a private temporary review directory, checkout exact commit `2ce8aa15d05bd57213e6f746f953aafb7ded7a8b`, verify `git rev-parse HEAD`, and inspect `package.json`, Pi extension source, bootstrap skill, plan/execution/review skills, and any scripts/hooks before loading code.
- [x] Capture SHA-256 baselines for `~/.pi/agent/settings.json`, `~/.pi/agent/trust.json`, and global package listing/state (record nonexistence explicitly when absent). Save a post-run snapshot and explicit equality result beside the restricted external rollback backup; retain neither global file contents nor credentials.
- [x] Register with exactly `pi install --local git:github.com/obra/superpowers@2ce8aa15d05bd57213e6f746f953aafb7ded7a8b`. Do not use `pi install` without `--local`, do not add a Codex declaration, and do not modify global settings.
- [x] Verify Pi's project-local Git checkout under `.pi/git/github.com/obra/superpowers` resolves to the exact full commit and `pi list --approve` reports the project source. Keep only the Pi-generated `.pi/git/.gitignore` cache guard in Git; verify all downloaded package files remain ignored and untracked.
- [x] Build an isolated temporary project containing only the sanitized project package declaration (not the Trellis extension, project prompts, or host absolute skills). Start a fresh ephemeral Pi process with `--approve --no-session`; verify the Superpowers startup/bootstrap and expected skills, then verify behavior after a controlled compaction/retry. This one-time flag must not persist trust.
- [x] Compare global settings/package/trust baselines with the retained post-run snapshot and equality result; assert no writes to global registration/settings/trust. Inspect current and staged `.pi/settings.json`; retain the dirty absolute skill include/exclude entries byte-exactly in the worktree but use a clean HEAD-derived staged project configuration. Verify the staged JSON and committed blobs contain no host-specific skills-directory paths. The only tracked `.pi/git/` path is the Pi-generated `.gitignore` cache guard; package source files are ignored.
- [x] Only after this validation passes may Trellis's project extension/prompt registrations be removed in Task 6. If Superpowers does not load at the pinned commit or project-local scope cannot be proven, stop; keep Trellis intact and request a decision.

**Validation:** exact commit assertion; `pi list --approve`; isolated `pi --approve --no-session` startup/skill/compaction checks; before/after SHA/state equality for global files retained outside the repo; staged-blob host-path scan; migration test verifies only `.pi/git/.gitignore` is tracked and package cache paths are ignored.

### Task 6: Replace Trellis entry points and remove Trellis-only integrations

**Files:** `AGENTS.md`, `.pi/settings.json`, `.gitattributes`, `.agents/skills/trellis-*`, `.pi/extensions/trellis`, `.pi/agents/trellis-*`, `.pi/prompts/trellis-*`, `.codex/agents/trellis-*`, `.codex/hooks.json`, `.codex/hooks/trellis*` (actual inventory-controlled paths only), `tests/test_fixture_matrix.py`, registry/docs references.

- [x] Rewrite `AGENTS.md` as concise project rules linking `docs/engineering/README.md` and the two active plans; remove Trellis-managed markers and commands. Preserve all non-Trellis repository constraints needed on every coding session.
- [x] Remove only Trellis-specific Pi extension, agent, prompt, and package/config entries. Keep `pi-subagents` and unrelated user/project Pi configuration. Update the project package array without reformatting or deleting unrelated settings.
- [x] Remove Trellis-only Codex agents and hooks/context-injection files. Preserve `.codex/config.toml` and other generic Codex configuration; add no Superpowers Codex setup.
- [x] Remove Trellis skills under `.agents/skills/trellis-*`; preserve any non-Trellis project skills. Remove only the `.trellis/workspace` merge rule from `.gitattributes`, preserving unrelated user changes and attributes.
- [x] Update every operational fixture/test/doc reference to the migrated docs. Keep historical statements in the migration design/plans only when clearly labeled as history, not active integrations.
- [x] Run `tests.test_superpowers_migration`, `tests.test_fixture_matrix`, `tests.test_regression_matrix`, and `tests.test_real_sample_manifest`; run fixture/regression/runtime matrix validators; use explicit `PYTHONPATH` unset.

**Validation:** targeted tests all pass; no active Trellis paths in `AGENTS.md`, `.pi`, `.agents`, `.codex`, scripts, tests, or fixtures; generic Codex config and user-owned worktree edits are verified unchanged except intended project-owned entries.

### Task 7: Retire `.trellis/` and perform final workflow audit

**Files:** delete complete `.trellis/`; final adjustments limited to the inventory from Task 6; docs remain under `docs/engineering/` and `docs/superpowers/`.

- [x] Reverify the external archive manifest, modes, and hashes immediately before removal. Confirm both active plans and all 20 engineering docs are present and linked.
- [x] Delete the complete `.trellis/` tree only after Superpowers activation and migrated task-plan review are accepted. Retain its external backup until rollback is closed. Do not delete Git history.
- [x] Run all migration tests plus the complete Python suite with `PYTHONPATH` unset; run fixture, regression, runtime matrix validators; run `git diff --check`. Do not run evidence-producing native runtimes as part of this workflow-only migration, and do not change their status based on static validation.
- [x] Search the working tree for `.trellis/`, `task.py`, `trellis:*`, `trellis-continue`, `trellis-finish-work`, Trellis hooks/agents/extensions/task loaders. Classify allowed historical mentions in this migration spec/plan; reject all operational references, broken links, fixture evidence paths, and CI task hooks.
- [x] Confirm the exact project-local package pin, no global settings/package/trust changes, no Codex Superpowers setup, and no loss of user-owned dirty files. Commit-content path checks remain in Task 8.
- [x] Reconcile child and parent open checklist counts/status against the source backup one final time. Report the product work remains incomplete and the exact unresolved criteria.

**Validation:**

```sh
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json --tier pr
python3 scripts/validate-runtime-matrix.py fixtures/runtime-matrix.json
git diff --check
```

### Task 8: Commit reversible migration slices (no push)

- [ ] Commit the migrated engineering docs, active plans, and registry/test changes as a documentation-only slice.
- [ ] Commit the project-local package and replacement `AGENTS.md` guidance separately, staging a sanitized `.pi/settings.json` derived from the committed base plus migration-owned changes only.
- [ ] Commit Trellis integration removal and `.trellis/` deletion in a separate reversible slice.
- [ ] Inspect every commit with `git show --stat`, `git show --check`, and `git show <commit>:.pi/settings.json`; verify no absolute user skill paths or global/Codex setup entered history.
- [ ] Confirm rollback by reverting the removal slice in a temporary worktree and restoring the external backup files/runtime archive by manifest. Do not alter the live workspace's unrelated dirty changes.
- [ ] Do not push or archive/close the two product tasks. The migration's success does not complete their open product/runtime acceptance criteria.

## Final acceptance checklist

- [x] The pinned Superpowers package is loaded from this project's Pi settings only, and the exact upstream commit is verified.
- [x] Global Pi settings, global package registration, and `~/.pi/agent/trust.json` are unchanged; one-time approval was not persisted.
- [x] No Superpowers Codex configuration exists.
- [x] All durable contracts remain discoverable under `docs/engineering/` and fixture/test references pass.
- [x] Both active plans preserve every open source acceptance criterion, evidence limitation, and parent/child relation; neither claims task completion.
- [x] The complete `.trellis/` tree and all active Trellis-specific hooks, extensions, prompts, agents, and skills are removed only after validation.
- [ ] Existing local `.gitattributes`, `.pi/settings.json`, journal, and `.trellis/` data can be restored byte-for-byte from the restricted backup; machine-specific paths did not enter commits.
- [x] Tests and validators pass; no product/runtime-support claim changed; local and hosted provider evidence remain accurately distinct.
- [ ] All commits are local; there is no push, and the user reviews the final diff before any further operation.
