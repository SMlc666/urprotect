# Project-local Superpowers adoption and Trellis retirement

**Status:** Migration implementation, validation, and three local commit slices are complete. Read-only final review passed. The user approved project-local Superpowers adoption and Trellis retirement and selected stepwise execution in the current branch. Nothing has been pushed; final diff review by the user is the remaining gate before further operation.
**Date:** 2026-10-24
**Scope owner:** Repository workflow and project knowledge migration.

## 1. Summary

Adopt Superpowers for this repository's **Pi workflow only**, registered through
Pi's project-level package settings and pinned to an exact upstream commit. Then
remove Trellis-specific workflow machinery and the `.trellis/` tree from the
repository after its durable engineering contracts and both active task states
have been migrated to ordinary project documentation and Superpowers plans.

This is a workflow/documentation migration. It does not complete the indirect-
control feature, change any ELF product behavior, or promote a runtime-support
claim. The still-open child and parent acceptance criteria remain open after the
migration.

## 2. Decisions and boundaries

### 2.1 Confirmed decisions

- Register Superpowers with Pi's **project-local** package declaration in
  `.pi/settings.json`, not in `~/.pi/agent/settings.json`.
- Use the canonical upstream repository `https://github.com/obra/superpowers`
  and Pi Git source declaration
  `git:github.com/obra/superpowers@2ce8aa15d05bd57213e6f746f953aafb7ded7a8b`
  (upstream package version `7.0.1` as inspected). Verify the resolved full
  commit SHA after installation; do not follow a floating branch or tag at
  runtime.
- Let Pi manage the package source/cache; for this `--local` Git install Pi
  materializes the checkout under `.pi/git/`. Track only the generated
  `.pi/git/.gitignore` sentinel that excludes the cache; never track the cloned
  Superpowers checkout, dependencies, or session data. Do not vendor or
  submodule the full upstream repository.
- Scope the Superpowers integration to Pi. Do not install or configure
  Superpowers for Codex. Remove Trellis-only Codex agents/hooks because the
  project is retiring Trellis, while preserving unrelated generic Codex config.
- Migrate both active tasks: `10-06-indirect-control-jump-tables` and its parent
  `10-06-unify-elf-protection-infrastructure`.
- Keep the existing acceptance state: the child remains incomplete for general
  ownership/remaining variants and shared-musl plus ordinary/shared Bionic
  evidence; the parent remains incomplete for indirect-control, broader TLS
  runtime/profile tuples, and broader CFI/unwind runtime/profile tuples.
- Archived Trellis tasks are not bulk-copied. Once removed from the worktree,
  their committed history remains available through Git history.
- Do not claim Bionic, musl, provider, or general jump-table promotion merely
  because workflow files moved or local tests pass.

### 2.2 Non-goals

- Completing the outstanding indirect-control, TLS, CFI, musl, or Bionic product
  work as part of this migration.
- Changing feature/evaluator/runtime status, rewriting prior evidence, or
  regenerating a failing local evidence root.
- Configuring Superpowers for Codex or another coding-agent platform.
- Installing Superpowers globally, changing user-level Pi settings, or
  vendoring upstream Superpowers source.
- Copying every archived task or every historical session log into the new
  documentation tree.
- Changing product code, Protected Image/Payload Frame ABIs, fixture semantics,
  or CI runtime coverage claims.

## 3. Repository state that constrains the migration

- Pi previously loaded `.pi/extensions/trellis/index.ts` and Trellis prompts
  from `.pi/settings.json`. That file had an existing uncommitted user change:
  absolute-path skill include/exclude entries into the developer's global Pi
  skills directory. Preserve that worktree content exactly, but never include
  those host-specific paths in a migration commit. When staging the package
  declaration and Trellis removals, construct/stage the project-owned settings
  delta separately from the user-owned skill diff; verify the staged blob and
  every committed settings version contain no host-specific skill paths. Keep
  the user-owned diff present and unchanged in the worktree after each commit.
- `.gitattributes` has an uncommitted union-merge rule for Trellis workspace
  journals. Retire only this now-obsolete `.trellis/workspace` rule when the
  workspace is removed; do not reset or overwrite other worktree changes.
- `.trellis/workspace/SMlc666/journal-1.md` has uncommitted session notes.
  Before deleting the workspace, copy any unique facts needed by the active
  migrated plans into those plans. Do not silently discard active progress or
  treat the journal as a substitute for the new plans.
- Before any migration edit, save byte-exact copies (or a binary-capable patch
  plus original file contents), file modes, and SHA-256 hashes for the current
  uncommitted diffs to `.gitattributes`, `.pi/settings.json`, and the journal
  outside the repository with restrictive permissions. Also archive the complete
  `.trellis/` tree with a per-file hash and mode manifest before deletion. This
  protects the ignored `.runtime/`, `.developer`, and `scripts/common/__pycache__/`
  state as well as tracked task/spec data. Record each item's disposition. Keep
  the backups until migration acceptance and rollback are closed; they contain
  user-owned local state and must not be committed or deleted implicitly.
- The task PRDs currently record the child as in progress and its parent at
  6/7 milestones. The migration must preserve the exact unchecked criteria and
  evidence caveats, rather than marking work complete for administrative
  convenience.
- Current local provider evidence-root failures remain distinct from hosted
  provider runs. The documented local positive-root provenance-member-count
  failure and rollback-root missing-script failure must remain explicit; hosted
  runs `39559228628` and `39561529902` are separate observations.
- A scoped Bionic helper-maps failure remains an unresolved hosted runtime
  observation. The recent local identity-checker and fixture changes are not a
  substitute for the missing hosted runtime evidence.
- A read-only inventory found roughly 20 durable Trellis specs, 414 task-related
  files, 3 workspace files, and 54 other Trellis files (excluding the volatile
  `.trellis/.runtime` tree). There are also project references outside
  `.trellis` in `AGENTS.md`, `.agents/skills`, `.pi`, `.codex`, tests, fixtures,
  and `.gitattributes`. Counts are inventory aids, not hard acceptance limits.

## 4. Target repository structure

The migration should establish a small, discoverable source of truth:

```text
AGENTS.md
  -> concise project-wide agent rules and links to engineering docs

.pi/settings.json
  -> existing user/project-local Pi settings, plus pinned local Superpowers
     package registration; no Trellis extension/prompt/agent registration

.pi/extensions/                 (only non-Trellis extensions, if any)
.pi/prompts/                    (only non-Trellis prompts, if any)

.codex/                         (generic existing config only; no Trellis hooks
                                 or agents, no Superpowers installation)

.agents/skills/                 (only non-Trellis project skills, if any)

docs/engineering/
  README.md                     -> indexes and source-of-truth guidance
  specs/backend/                -> migrated backend contracts
  specs/frontend/               -> migrated frontend contracts
  guides/                       -> migrated cross-layer/code-reuse guides

docs/superpowers/
  specs/                         -> this reviewed migration/design document and
                                    any active task design needed after migration
  plans/                         -> active indirect-control and parent plans
```

The final paths may be adjusted during implementation if a repository convention
or Superpowers loader constraint requires it. Any adjustment must preserve the
same source-of-truth, discoverability, and no-Trellis-runtime goals.

## 5. Knowledge and task migration

### 5.1 Durable engineering contracts

Move the current backend, frontend, and shared-guide specifications out of
`.trellis/spec/` into `docs/engineering/`, preserving the contracts rather than
copying Trellis lifecycle instructions. Update internal links, indexes, test
references, evidence contracts, and repository guidance to the new paths.

Retain safety-critical rules in executable/agent-readable project docs,
including bounded/no-follow evidence input, exact runtime identity, unique
`PT_LOAD` ownership, provider evidence non-promotion, exact integer schemas,
source-derived table/fixup validation, and required negative tests. Do not
replace these with a generic reference to Superpowers.

Trellis-specific workflow material (task lifecycle, `task.py`, Trellis channels,
Trellis context injection, Trellis memory CLI, and Trellis-generated hooks) is
not an engineering contract and should not be copied verbatim. Replace only the
project guidance that remains valuable with concise instructions in `AGENTS.md`
and links to the migrated engineering docs.

### 5.2 Active plans

Create one Superpowers implementation plan for each active task:

1. `docs/superpowers/plans/2026-10-24-indirect-control-jump-tables.md`
2. `docs/superpowers/plans/2026-10-24-unify-elf-protection-infrastructure.md`

Each plan must record:

- current state and dependency/parent relationship;
- completed milestones only as provenance, not as new promotion claims;
- every currently open acceptance criterion, copied and reconciled against its
  current PRD and implementation checkpoint;
- next actionable work, bounded validation commands, and rollback boundaries;
- evidence paths/caveats needed to continue without the Trellis task files;
- links to migrated engineering contracts and the other active plan.

The child plan must keep general/exhaustive ownership inference and remaining
variants open; preserve the distinct `Ambiguous` safe-default scope and its
limits; and keep shared-musl plus ordinary/shared Bionic acceptance open. The
parent plan must preserve the open indirect-control criterion and the remaining
TLS/CFI runtime/profile tuples. In particular, one runtime's pass cannot promote
another runtime.

The plans are the live execution records. Historical command transcripts,
archived tasks, and completed session logs do not need bulk conversion, but any
uncommitted journal fact necessary to understand current state must first be
captured in the appropriate plan or durable spec.

## 6. Pi package registration and trust

- Add a single Git package source under the project `.pi/settings.json`, pinned
  to the exact commit above. Use Pi's project-local install flow (`pi install
  --local ...`) or an equivalent reviewed JSON edit that produces the same
  declaration. Do not invoke the global install flow.
- Preserve existing local settings, especially the current unrelated absolute
  skill include/exclude entries. Review the final JSON diff before accepting
  Pi's installer output.
- Superpowers contains an executable Pi extension and skills that can direct
  command execution. Review the pinned source and package manifest (already
  inspected in this design phase), then resolve project trust explicitly before
  loading it. Do not weaken Pi trust defaults or add a project-wide auto-trust
  setting.
- This migration must not change global package registration, global Pi
  settings, or `~/.pi/agent/trust.json`. For validation, use Pi's explicit
  one-time `--approve` override for the fresh process rather than saving a
  persistent `/trust` decision. Do not silently create global trust state. If a
  one-time approval cannot safely load the project package, stop and request
  separate explicit user consent before any persistent trust change.
- Validate with a fresh Pi process/session rooted at this repository. Confirm
  the exact package commit, `using-superpowers` bootstrap at startup, expected
  skill discovery after startup/context compaction, and that global settings,
  package registration, and trust state remain unchanged.
- Existing `pi-subagents` may be used as the optional Pi delegation provider.
  This design does not add or globally reconfigure it.

## 7. Trellis retirement boundary

After the migrated docs/plans are reviewed and the Pi package is validated,
remove Trellis project integration and state, including:

- the complete `.trellis/` tree (specs, active/archived tasks, workflow scripts,
  agents, and volatile runtime markers);
- `.agents/skills/trellis-*` and their references;
- `.pi/extensions/trellis`, `.pi/agents/trellis-*`, `.pi/prompts/trellis-*`, and
  corresponding project settings entries;
- Trellis-only `.codex/agents/trellis-*` and hooks/context injection. Preserve
  generic `.codex` configuration but do not add Superpowers there;
- Trellis-managed instructions in `AGENTS.md` while preserving/replacing
  project-specific engineering guidance;
- the `.gitattributes` rule that only applies to `.trellis/workspace` journals;
- stale `.trellis` path dependencies in fixtures, tests, scripts, indexes, and
  docs, replacing them with the migrated source of truth or removing obsolete
  workflow-only checks.

Do not delete unrelated `.agents`, `.pi`, or `.codex` resources. Search and
review each external Trellis reference before changing it. The migration design
and plans may mention Trellis as historical context; such prose is not an
active integration. After retirement, no `.trellis/` directory, active Trellis
commands, extensions, skills, prompts, task hooks, or task-loader dependency may
remain in the working tree.

## 8. Rollout and rollback

Perform the migration in gated, reviewable steps:

0. **Protect pre-existing worktree state:** create the restrictive, external,
   byte-exact backups and hashes described in §3; record the ownership and
   disposition of each dirty file. Do not stage those user changes.
1. **Knowledge baseline:** migrate durable specs and create both active plans;
   compare open acceptance items against the source task files. No package or
   deletion changes in this step.
2. **Pi activation:** register the pinned package project-locally, preserve
   existing `.pi/settings.json` content, keep machine-specific user skill paths
   out of commits, and validate a fresh Pi session using one-time `--approve`.
   Confirm no global settings, package, or trust file changed. Trellis remains
   available until this passes.
3. **Trellis removal:** remove only inventoried Trellis integration/state and
   update remaining project references. Run the full reference/config audit.
4. **Final audit:** run path/link checks, relevant documentation and regression
   validators, `git diff --check`, package identity checks, and final task-plan
   acceptance reconciliation. Report outstanding product criteria unchanged.

Keep these steps in separate commits so the workflow can be bisected and the
Trellis removal can be reverted without losing the migrated plans. Do not push
or delete the source control history as part of this design. Rollback means
revert the relevant migration commit(s), restore the prior project settings,
re-enable the Trellis files/config from Git, and reapply any backed-up
uncommitted `.gitattributes`, `.pi/settings.json`, and workspace-journal changes
byte-for-byte. Verify their original hashes and modes after restoration. Keep
those external backups until the migration is accepted; rollback must not modify
global Pi settings, package registration, or trust state.

## 9. Acceptance criteria for the migration

- [x] Superpowers is registered only in this project's `.pi/settings.json`
      using the canonical repository and exact full commit declaration above;
      installed source resolves to that commit. Global Pi settings and package
      registration are unchanged.
- [x] A fresh Pi process using one-time `--approve` loads the pinned
      Superpowers bootstrap and expected skills; startup and compaction behavior
      are verified. No persistent trust entry is written to
      `~/.pi/agent/trust.json`.
- [x] Backend/frontend engineering contracts and shared guides remain
      discoverable under `docs/engineering/`, with valid links and no loss of
      safety-critical constraints.
- [x] Both active task plans preserve every source open acceptance criterion,
      current evidence caveat, and parent/child dependency; the child/parent do
      not become complete merely due to migration.
- [x] The original `.pi/settings.json`, `.gitattributes`, and workspace journal
      diffs have restrictive external byte-exact backups, file modes, and SHA-256
      records before edits; the complete `.trellis/` tree also has a restorable
      archive and per-file hash/mode manifest. Useful active journal facts are
      transferred before workspace deletion; every original diff has a
      documented preserve/discard disposition and can be restored byte-for-byte
      on rollback.
- [x] Migration commits do not contain host-specific absolute skill paths from
      the dirty user settings; the local worktree retains that user-owned diff
      unchanged. Each committed blob was audited.
- [x] Trellis-specific Pi/Codex/agent instructions, hooks, agents, prompts,
      task scripts, task/spec tree, and active project references are removed;
      generic Codex configuration remains and receives no Superpowers setup.
- [x] No product code/runtime claims are changed. Bionic and general provider/
      table support remain unknown/non-promoted; local and hosted evidence stay
      separately described.
- [x] Migration is committed in reversible slices and the final audit finds no
      broken links, dangling task loaders, or active Trellis integration. A full
      isolated-clone revert and external-backup restoration rehearsal passed.

## 10. Approval and execution record

The user approved the migration and asked for stepwise execution on the current
branch. Tasks 1–8 implementation and validation are complete; final diff review
is presented to the user before any further operation. Three commits are local:
`7b5af05` (engineering docs/plans and registry), `fdfba43` (project-local
Superpowers and `AGENTS.md`), and `e4f5ea5` (Trellis integration/data removal).
No push was performed. The user chose a project-local Pi installation only; no
global or Codex Superpowers setup was added. No product feature or runtime-
support criteria are completed by this migration.
