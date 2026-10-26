# Superpowers Migration Follow-up PR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Each task ends with focused verification and a reversible commit.

**Goal:** Port the already reviewed project-local Superpowers adoption and Trellis retirement from the post-PR #29 work to a clean branch based on current `origin/main`, without carrying unrelated runtime/product history.

**Architecture:** Migrate durable contracts and active plans into `docs/engineering/` and `docs/superpowers/plans/`; register the exact reviewed Superpowers source only in project `.pi/settings.json`; then remove Trellis-specific integrations and state. The migration remains administrative and does not change feature acceptance or runtime claims.

**Tech Stack:** Git worktrees, Pi project packages, Markdown, JSON, Python `unittest`, fixture/runtime validators, SHA-256 manifests.

**Spec:** `docs/superpowers/specs/2026-10-24-project-local-superpowers-and-trellis-retirement-design.md` (ported from the reviewed post-PR #29 source branch in Task 3).

## Global Constraints

1. Project-only package declaration: `git:github.com/obra/superpowers@2ce8aa15d05bd57213e6f746f953aafb7ded7a8b`; never configure Superpowers globally or for Codex.
2. Do not change global Pi settings, package registration, or trust state; use one-time approval only for a fresh project-package validation.
3. Preserve the exact child/parent task acceptance state; migration must not mark product/runtime criteria complete.
4. Preserve current-main changes and local user state; do not overwrite `.pi/settings.json` in `/root/urprotect` or alter local `main`.
5. Do not commit machine-specific absolute paths such as `/root/.pi/agent/skills/`.
6. Keep migration, package activation, and Trellis removal as separate reversible commits.
7. Run Python and fixture/runtime validation without ambient `PYTHONPATH`.

## Review Focus

1. New files or ignored runtime state under `.trellis/` on current main must not be silently lost; inventory ignored entries and preserve a restrictive external archive before deletion.
2. Project settings must contain exactly one Superpowers Git pin, no Trellis integration, and no machine-local skills paths; test committed/staged bytes, not the dirty original worktree.
3. Active child and parent plan markers must retain open ownership, TLS, CFI, and cross-runtime work; the migration cannot upgrade them.
4. Every operational `.trellis` reference in agents, fixtures, tests, CI and docs must be removed or redirected; historical migration prose may remain.
5. Generic Codex/Pi configuration and non-Trellis project resources must survive unchanged.

---

### Task 1: Establish a clean rollback baseline

**Files:** external private backup only; no tracked repository edits.

- [x] Verify each new worktree is based on `origin/main` and clean. Inspect tracked and ignored `.trellis/` entries, `.pi/settings.json`, `.gitattributes`, and relevant workspace state.
- [x] Create an external mode-0700 backup directory; archive the complete `.trellis/` tree preserving modes/symlinks and write a per-file path/type/mode/size/SHA-256 manifest. Preserve any ignored or user-owned data separately.
- [x] Verify archive hashes and modes, and rehearse extraction to a fresh temporary directory. Stop if any source-tree item is missing or changed.

### Task 2: Add migration regression tests first

**Files:** `tests/test_superpowers_migration.py` (new; source: reviewed post-PR #29 migration commit).

- [x] Add tests for child and parent acceptance markers, fixture registry path/digest, ignored Pi package cache, absent Trellis integrations/data, no machine-local paths in migration docs, and exact staged Superpowers pin.
- [x] Run `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_superpowers_migration` before porting migration files. Expected: RED because current `origin/main` has Trellis configuration/data and lacks migrated docs.
- [x] Keep assertions intact; do not weaken them to accommodate current-main differences.

### Task 3: Port durable contracts and active plans

**Files:** `docs/engineering/**`, `docs/superpowers/specs/2026-10-24-project-local-superpowers-and-trellis-retirement-design.md`, the two active migrated plans, fixture registry references, and related fixture tests.

- [ ] Port the reviewed docs/registry slice represented by source commit `7b5af05`; reconcile any current-main drift without copying unrelated runtime changes.
- [ ] Preserve all safety contracts, evidence provenance, and source task open criteria. Ensure fixture-matrix retained-registry SHA-256 matches the exact updated manifest bytes.
- [ ] Run migration, fixture, and real-sample manifest tests plus `scripts/validate-fixtures.py fixtures/manifest.json --tier pr` and `scripts/validate-runtime-matrix.py fixtures/runtime-matrix.json`.
- [ ] Commit the documentation/registry slice independently.

### Task 4: Register project-local Superpowers

**Files:** `.pi/settings.json`, `.pi/git/.gitignore`, `AGENTS.md`.

- [ ] Port the sanitized settings/guidance change represented by source commit `fdfba43`; preserve generic settings and include only the exact package pin.
- [ ] Review the pinned upstream package source/manifest and verify a fresh project-scoped Pi process loads the pinned commit with one-time `--approve`; do not persist trust or modify global state.
- [ ] Verify `git show :.pi/settings.json` contains one exact pin and no host-local absolute paths; keep only `.pi/git/.gitignore` tracked under the package cache.
- [ ] Run migration settings tests; commit this slice separately.

### Task 5: Retire Trellis integrations and current-main-only residue

**Files:** `.trellis/**`, `.agents/skills/trellis-*`, `.pi` Trellis entries, `.codex` Trellis entries, stale project references, and migration tests.

- [ ] Port the retirement represented by source commit `e4f5ea5`, then compare against current `origin/main`; remove any current-main-only Trellis files/references so the entire `.trellis/` tree and active Trellis entrypoints are absent.
- [ ] Preserve generic Codex configuration and all non-Trellis resources. Keep the original project package pin and sanitized settings from Task 4.
- [ ] Run migration/fixture/regression/real-sample test modules and all three fixture, regression, and runtime-matrix validators with `PYTHONPATH` unset. Run repository searches and `git diff --check`.
- [ ] Commit Trellis retirement separately and update the migration record to describe the clean-branch port rather than claiming the old branch is the PR.

### Task 6: Review, push, and open the migration PR

- [ ] Compare the branch to `origin/main`; verify no product/runtime code, unrelated evaluator changes, absolute machine paths, or local settings edits are present.
- [ ] Run the complete relevant Python suite and all migration/fixture/regression/runtime-matrix validators; require a clean diff check.
- [ ] Perform an independent self-review pass (delegation was not requested); resolve any correctness issues before publication.
- [ ] Push only `fix/superpowers-migration-pr`, open a PR against `main`, and inspect its CI. Do not merge it locally or on GitHub without a separate merge instruction.

**Migration acceptance:** only durable docs/task-state migration, project-local package configuration, and Trellis retirement are included; open product criteria remain open; the PR diff is based on current `origin/main` and contains no legacy branch history spillover.