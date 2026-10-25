# Hosted provider result and registry consistency audit

**Scope:** Read-only review of the named task's PRD/design/implementation checkpoints, backend provider/runtime specs, fixture/runtime/evaluator registries, regression matrix, and provider workflow steps. No reviewed documentation, registry, evidence root, code, or workflow was modified. This research note is the only audit artifact written.

## Result

**FAIL — documentation/registry alignment needs a small correction.** The provider status/report themselves remain correctly unpromoted; the failures are stale current wording, a wrong regression-matrix artifact witness, and locally retained evidence roots that do not pass the current exact-root checkers.

## Hosted provider result and promotion boundary

- The task's latest provider checkpoints (`implement.md` lines 1034–1049) and the PRD's checked scoped-provider criterion record hosted producer/checker/root-bound passes in PR #25 run `39559228628` and merged-main run `39561529902`. The checkpoint says the provider-positive and separate provider-loaded rollback evidence were retained. The preceding checkpoint at `implement.md:804` records 17 successful PR jobs (five expected skips) and 13 successful merged-main jobs (nine expected skips), and explicitly says the provider row remains unknown/non-promoted.
- The current PRD provider criterion (`prd.md:51`) likewise records these run IDs without promoting support. The current provider sections of `runtime-compatibility.md`, `external-consumer-proof.md`, `error-handling.md`, `quality-guidelines.md`, and `index.md` record the hosted passes and preserve `unknown` / `scoped-observation-not-promoted`, with final documentation/registry review and broader criteria outstanding.
- The on-disk positive report at `.artifacts/indirect-control/external-provider/current/runtime.indirect-control.external-provider.glibc.host-context-entry/external-provider-evidence.json` has `acceptanceState: scoped-observation-not-promoted`, and identifies only AArch64/glibc. The separate rollback report says `status: accepted`; this is a lifecycle observation, not feature promotion. `fixtures/manifest.json` keeps the provider feature `status: unknown` and limits the scope to the project-built provider/one consumer.
- `ci.yml` lines 520–637 wires the provider positive and source-loader rollback producers and exact-root checkers in `protection-and-tls`, with `if: always()`, run-keyed root markers/logs/statuses, and independent checker steps. This workflow wiring and the recorded hosted runs are **not** evidence of branch-protection required-check mapping; no branch-protection configuration was inspected or queried.

## Findings requiring correction

1. **Current design text still claims the hosted provider run is open.** `.trellis/tasks/10-06-indirect-control-jump-tables/design.md:277–278` says that an official hosted CI run and branch-protection confirmation “remain open.” The branch-protection half remains unconfirmed, but the hosted-run half conflicts with the later recorded passes. Minimal wording correction: record the two passing run IDs and say that branch-protection mapping plus final documentation/registry review remain outstanding; do not imply the runs prove branch protection.

2. **The external-provider regression row names a nonexistent outer SHA256SUMS.** `tests/regression-matrix.json:614` lists `.artifacts/indirect-control/external-provider/current/SHA256SUMS`. In the retained current tree that file is absent; the closed positive manifest is at `.../current/runtime.indirect-control.external-provider.glibc.host-context-entry/SHA256SUMS`. The fixture row already names the unit-level path (`fixtures/manifest.json:479`). `tests/test_regression_matrix.py:77` currently asserts the wrong outer-root path, so the passing unit test preserves rather than catches the mismatch. Minimal correction: change the matrix artifact path and corresponding assertion to the unit-level `SHA256SUMS`; leave required/expected/tier values unchanged.

3. **The fixture row's remaining-evidence wording is stale/overbroad, although its status is correct.** `fixtures/manifest.json:487,490` still lists fresh hosted producer/checker/root-bound passes alongside final documentation review as conditions before keeping the row unknown. The hosted conditions are recorded as passed; final documentation/registry review and broader task/runtime criteria remain open. Rephrase `nextEvidence`/the constraint to acknowledge the recorded hosted runs while retaining `status: unknown` and the non-promotion boundary. If the manifest text changes, refresh only its `fixture-matrix` auxiliary digest in `fixtures/evaluator/compatibility-corpus.json`; do not change feature status.

## Local retained-root residual

The current local artifact copies do not independently reproduce the recorded hosted pass with the current checkers:

- `scripts/check-external-provider-evidence.py` on the named positive unit root fails with `retained build provenance tar has an unexpected member count`. The retained tar has 34 members, and the current checker requires the current `BUILD_PROVENANCE_FILES` inventory. Its unit `SHA256SUMS` still verifies.
- `scripts/check-external-provider-rollback-evidence.py --root .artifacts/indirect-control/provider-loaded-rollback/current` fails because the retained root lacks `evidence-tools/run-external-provider-rollback-oracle.sh`. Its `SHA256SUMS` still verifies.

These local directories are dated 2026-10-21 and are not a substitute for the uploaded hosted run roots. The failures do not prove that the recorded hosted runs failed, but they mean these local `current` copies cannot be cited as present-day exact-root passes without a fresh producer/checker run or inspection of the corresponding hosted artifacts. No hosted artifact/API query was made.

## Registry linkage and hypothetical rows

- All five `retainedEvidenceRegistries` hashes in `fixtures/evaluator/compatibility-corpus.json` match their current auxiliary files. In particular, `fixture-matrix` matches `fixtures/manifest.json` SHA-256 `c86605ac73f670c992fe36ab5bacf8363e08e2b900509176368c6722b8723d47`; the other matched registries are public-real-sample-corpus, runtime-covering-matrix, tls-transformed-runtime-matrix, and explicit-protection-policy. The evaluator corpus does not contain a direct provider feature row; its fixture manifest link is explicitly auxiliary.
- `fixtures/runtime-matrix.json` has six runtime-environment cells and no provider/indirect-control feature row. It therefore does not promote provider execution on musl/Bionic.
- `tests/regression-matrix.json` has both provider E2E and provider-loaded rollback cases required for PR/nightly/release on native ARM64, with `expected: pass`. Those are gate declarations, not support status; their one artifact-path defect is above.
- Keep the hypothetical no-hosted-result rows in `external-consumer-proof.md` and `runtime-compatibility.md`, as well as dated earlier task checkpoints. The current runtime matrix/error tables are conditional classifications, and `implement.md:1043,1048` explicitly says the hypothetical cases were left intact. They are not current assertions that the hosted provider result is absent. In particular, retain `runtime-compatibility.md:1846,1866–1870`; the adjacent current-state prose records the hosted runs. The combined no-hosted-result/branch-protection row at `1854` can be made clearer in a future docs edit, but branch-protection confirmation is still absent and it should not be deleted as a hypothetical boundary.

## Validation performed

- `env -u PYTHONPATH python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr` — passed, 13 cases.
- `env -u PYTHONPATH python3 scripts/validate-regression-matrix.py tests/regression-matrix.json --tier pr` — passed.
- Targeted unit tests for provider `unknown` status + manifest/evaluator digest linkage and regression-matrix required provider rows — passed, 2 tests. The regression unit currently asserts the incorrect outer SHA256SUMS path noted above.
- `git diff --check` — passed.
- Correct working-directory `sha256sum -c SHA256SUMS` for both local unit roots — passed; these checks establish byte closure only, not current semantic acceptance.
- Exact-root positive and rollback checkers — failed as described in the local residual section.
- `python3 ./.trellis/scripts/task.py current --source` returned no task. The audit target was resolved from the explicit user/task context as `.trellis/tasks/10-06-indirect-control-jump-tables`; no task activation/status was changed.

## Proposed minimal follow-up

Correct the stale hosted-result sentence in `design.md`, align the regression row/test's positive manifest path, and revise the fixture `nextEvidence` wording without changing `status`. If the manifest text is edited, update/check the evaluator's fixture-manifest digest. Keep all hosted results scoped; preserve the hypothetical failure cases and historical checkpoint entries. A fresh exact-root check is still needed before treating the local `current` evidence copies as current.
