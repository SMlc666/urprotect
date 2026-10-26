# Runtime Evidence Follow-up PR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Each task is test-first, independently verifiable, and committed in a reviewable slice.

**Goal:** Port the post-PR #29 Bionic/musl evidence work and the diagnosed ELF/CI fixes onto current main without bringing in the old branch's unrelated tree history.

**Architecture:** Reuse the product/evidence baseline already merged by PR #29, then port only the post-merge runtime, independent-checker, test, and workflow changes. Keep evidence exact-rooted and scoped; the runtime review branch is stacked on the Superpowers migration PR so its updated active plan and engineering contracts exist without duplicating the migration diff.

**Tech Stack:** C/C++, .NET 8, Python 3 `unittest`, Bash/POSIX shell, GitHub Actions, native AArch64/Bionic and container/musl evidence.

**Spec:** `docs/engineering/specs/backend/runtime-compatibility.md` (provided by the migration PR base), plus the active indirect-control plan in that base.

## Global Constraints

1. Preserve exact source/runtime identity and evidence provenance; do not promote support based on local tests or a different runtime.
2. Preserve bounds, no-follow checks, unique owner rules, strict half-open intervals, and fail-closed checker behavior.
3. A zero-file `PT_TLS` structural observation may have no owner only when its zero-length file range and virtual range are bounded; semantic TLS projection must remain unresolved without a unique owner.
4. Bionic evidence must carry the exact digest suffix of the locked image; musl admission must retain the reviewed libc digest requirement.
5. GitHub container steps remain POSIX-shell compatible; artifact handoff paths must match the actual archive root.
6. The PR2 branch is stacked on `fix/superpowers-migration-pr`; review/merge order is migration first, runtime second. Never merge or force-push without explicit authorization.
7. Do not alter `/root/urprotect/.pi/settings.json`, local `main`, or other worktrees.

## Review Focus

1. Bounded checker arithmetic: valid `SHT_NOBITS` may extend conceptually past EOF, while other section bytes and all checked arithmetic remain bounded.
2. Zero-file TLS distinction: preserve the bounded ownerless structural fact without projecting it into a resolved semantic binding; reject unbounded offsets and conflicting owners.
3. Runtime identity: Bionic pinned image digest and musl reviewed libc digest must be independently checked against retained bytes.
4. Artifact handoff: downloading an artifact containing `bionic/` at its archive root must not create `bionic/bionic/` or weaken run-specific checksums.
5. CI failures from unavailable locked Node.js archives or runner/network timing must be reported separately from code regressions and must not be masked.

---

### Task 1: Stack on the migration branch and establish current baseline

**Files:** branch ancestry only; no runtime code changes.

- [x] Update `fix/runtime-evidence-followup-pr` to include the reviewed `fix/superpowers-migration-pr` tip while retaining its original `origin/main` ancestry. Confirm the intended PR base is the migration branch and that the runtime-only product diff is empty before porting.
- [x] Confirm the migration plan/spec paths exist at the new base and inspect current CI/workflow/runtime source state, including the current Bionic artifact root, Bionic digest emitter, shared checker NOBITS bounds, and zero-file TLS parser condition.
- [x] Run `dotnet test UrProtect.sln` with restore on the clean base and record the baseline; capture environment-only failures separately. Restore/build succeeded. The first full run had 763/764 pass, with the 2-second FIFO nonblocking test timing out; that focused test passed three isolated replays and a full no-build/no-restore rerun passed 764/764.

### Task 2: Port shared-musl and Bionic evidence slices

**Source commits to audit:** `2cf83d3`, `3b134cc`, `a86fee1`, `683860c`, `712a673`, `2619bee`, `63c94bb`, `1111158`, `50f424f` from the reviewed post-PR #29 source branch. Do not cherry-pick the old branch wholesale; its migrated specifications are already in the base.

**Files:** relevant `.github/workflows/ci.yml`, native runtime identity/host-context code, Bionic and shared-table producer/checker scripts, fixture metadata, and Python tests.

- [x] Port the shared-musl test/fixture/checker changes first; the new tests failed against the unported checker/runtime API, then passed after the shared checker, runner, and fixture changes were applied.
- [x] Add/port Bionic handoff, image-inspection, and native identity regressions before the corresponding implementation changes; the pre-implementation regressions failed on the absent parser/bridge and Bionic runtime path, and the pinned-image/runtime-identity mismatch cases passed after implementation.
- [x] Port only the matching scripts/native/workflow changes. Keep POSIX shell and source-derived independent checking contracts; omit Trellis-path docs, and reconcile the contract inventory with the current migration base.
- [x] Run `tests.test_shared_jump_table_evidence`, `tests.test_rehydration_evidence`, `tests.test_bionic_handoff_bridge`, `tests.test_bionic_artifact_permissions`, and `tests.test_protected_image_workflow` with ambient `PYTHONPATH` removed. The combined related suite (including regression-matrix tests) passed 151/151 after a Release build; an initial run's four failures were all the missing Release CLI assembly prerequisite, not assertions.
- [x] Commit the cross-runtime evidence slice separately. Exclude Trellis-path doc patches already represented by the migrated engineering specs. Committed as `606902c`.

### Task 3: Port and verify the diagnosed follow-up fixes

**Source commits:** `cd6211a`, `5059742`, `6e70ffa`, `b738fb4`, `8b01bd9`, `9ff0c80`, `a58237e`.

**Files:** `scripts/run-bionic-fixture.sh`, `scripts/check-shared-jump-table-evidence.py`, `.github/workflows/ci.yml`, `src/UrProtect.Core/StructuralElf/ElfTlsParser.cs`, matching Python/managed regressions, and the migrated indirect-control/zero-file-TLS plans.

- [x] For Bionic `imageDigest`, execute the actual JSON emitter in the regression; the pre-fix test observed `imageDigest == None`, and the fixed emitter reports the pinned image suffix.
- [x] For `SHT_NOBITS`, use a standards-valid AArch64 ET_REL synthetic ELF (`sh_addr=0`, `sh_offset=EOF`); the positive conceptual range is accepted, while file-backed out-of-bounds and 64-bit overflow cases reject.
- [x] For runtime-matrix artifact handoff, the workflow-root test failed with the archive downloaded to `.artifacts/bionic`, then passed after download at `.artifacts`.
- [x] For ownerless zero-file PT_TLS, the parser regression first failed on nonzero `p_vaddr`; it now accepts the bounded empty range at exact EOF, retains owner index `-1`, keeps semantic `TlsBindingUnresolved`, and still rejects out-of-bounds offsets and ownerless nonzero-file templates.
- [x] Run focused Python/managed regressions and update the active/design plans with hosted evidence and external-sample caveats. The relevant Python modules passed 138/138, `ElfParserTests` passed 42/42, and ownerless TLS regressions passed 3/3; Python ran with `PYTHONPATH` unset.
- [x] Commit the follow-up fixes as a separate reviewable slice. Committed as `dfdeb82` after the 765/765 full managed test run.

### Task 4: Full local and hosted verification; publish stacked PR

- [x] Run `dotnet test UrProtect.sln` after restoring packages; run the full Python unittest suite with `PYTHONPATH` removed, fixture PR validator, regression-matrix validator, runtime-matrix validator, relevant identity checker tests, `bash -n` for modified scripts, and `git diff --check`. Results: managed tests 765/765; full Python discovery 538 tests, 2 skipped, no failures; fixture PR validation 13 cases; regression matrix 7/7; runtime matrix tests 14/14 plus six-cell registry validation; runtime closures 19/19; native AArch64 `make -C native/urprotect-runtime test` passed, including native identity cases; `bash -n` passed for all six modified shell scripts and the complete PR diff passed `git diff --check`. The first Python run exposed one stale migration-state expectation after the scoped cross-runtime criterion was marked complete; updated that regression, then its isolated test and the full suite passed.
- [ ] Push `fix/runtime-evidence-followup-pr` and open its PR with base `fix/superpowers-migration-pr`; verify GitHub reports only runtime/evidence changes in the PR diff.
- [ ] Trigger/inspect fresh hosted Bionic, musl, and runtime-matrix exact-root evidence. Retain run-specific artifacts and digest checks.
- [ ] Report `real-sample-matrix` HTTP 404 or transient network/timing failures as separate lane outcomes; do not claim global CI green unless every mandatory job passes.
- [ ] Do not merge either PR. After the migration PR merges, retarget runtime PR to `main` and refresh checks only with authorization/maintainer approval.

**Runtime acceptance:** the PR contains only current-main-relative evidence work and targeted fixes; Bionic and musl observations remain scoped to fresh run artifacts; external download failures remain explicit and are not hidden by narrowed checks.