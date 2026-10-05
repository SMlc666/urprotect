# Complete final 100x integration review

## Goal

Prove the full parent objective end-to-end: compatibility growth reaches at least 100 distinct complete strict units over immutable baseline-v2 denominator 1, each of six Scheme-A attack families independently reaches at least 100x under its frozen policy, all anti-gaming checks pass, and all product/CI/benchmark/sample/test/fuzz evidence remains retained and green.

## Requirements

- Preserve the immutable v2 compatibility baseline/reference and the v1 historical zero baseline.
- Require an append-only reviewed corpus with 100 distinct identity keys and exact per-unit source/Protected Image/Native Image/loader/oracle stage bindings.
- Require compatibility fixed-view non-regression and integer growth `candidateGrowthCompleteUnits >= 100 * frozenBaselineCompleteUnits`.
- Require three baseline and candidate replicas for every Scheme-A family under identical pinned tool/recipe/oracle/budget/runtime identity, finite immutable baseline successes, and independent factor `>=100` per family.
- Require evaluator anti-gaming, evidence closure, exact commit freshness and native environment identity.
- Preserve all prior real-sample, runtime, protection, native handoff, test, fuzz, benchmark, stress, and CI evidence/gates.
- Emit `claimable=true` only when both independent dimensions, anti-gaming, and all existing gates pass.

## Acceptance Criteria

- [ ] Evaluator reports >=100 distinct complete strict growth units with fixed view passing and compatibility factor >=100.
- [ ] All six Scheme-A family factors are >=100 under the frozen immutable policy.
- [ ] Anti-gaming and all CI/product evidence checks pass; evidence trees are closed and commit-bound.
- [ ] Final evaluator gate has `claimable=true` derived from verified evidence, not hand-edited markers.

## Out of Scope

- Any weakening of the parent 100x rules, Scheme-A family membership, budgets, or oracles.
- Counting duplicate identities, reruns, profile/runtime/selector variants as growth units.
- Treating compatibility alone or Scheme-A alone as an overall pass.
