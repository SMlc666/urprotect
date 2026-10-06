# Final 100x integration review implementation plan

## 1. Prerequisites

- Verify positive immutable compatibility baseline-v2 and Scheme-A baseline-v2 references are content-addressed and unchanged.
- Verify all evaluator runs use the exact final checkout and declared native execution environment.

## 2. Full gate rerun

- Run all producer/rehydration/native handoff strict rows and all six Scheme-A baseline/candidate replica suites.
- Run the full independent evaluator and its evidence checker; verify fixed/growth counts and all six family factors from raw records.
- Run every existing product, parser/pack/HostContext, real-sample, runtime, benchmark, fuzz, stress, workflow-contract, and evidence checker.

## 3. Final audit

- Recompute all closed manifests, artifact hashes, corpus identities, tool/recipe/budget/oracle bindings, and anti-gaming projections.
- Verify no legacy direct-ELF or auxiliary evidence contributes to strict counts.
- Confirm `claimable` is recomputed as the conjunction and no hand-edited output is accepted.

## Validation

Use the full validation command set in the parent task implement plan plus the exact independent evaluator commands for PR/nightly/release tiers. Retain complete evidence for success and failure.

## Rollback

If any stage/family/CI gate fails, retain the full evidence tree, leave `claimable=false`, and disable only newly added profile/jobs as appropriate. Do not alter frozen baselines, rules, or thresholds.
