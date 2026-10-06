# Freeze positive immutable compatibility baseline v2

## Goal

Freeze the first positive immutable strict-chain compatibility denominator from a fresh exact-commit evaluator run. Preserve the historical `compatibility-1x-baseline-zero` object, the exact parent 100x compatibility rule, and independent Scheme-A `baseline-not-calibrated` status. This child produces a denominator snapshot, not a 100x claim.

## Requirements

- Rerun the strict evaluator and product evidence at one exact checked-out commit; require `git rev-parse HEAD == gate.commit == environment.commit`.
- Close and verify evaluator root, unit raw, product-chain, and product-evidence manifests. The observed root `SHA256SUMS` digest must equal both gate manifest digest fields.
- Require one fixed corpus row with all six stages passed for the same source-image hash, profile, runtime cell, target loader, oracle, and run. Require distinct Protected Image and Native Image bytes and exact producer/rehydrator/native/loader/oracle links.
- Publish additive content-addressed `fixtures/evaluator/baselines/compatibility-1x-v2.json` and `compatibility-1x-v2-reference.json`; never mutate `compatibility-1x-baseline-zero` or its reference.
- Preserve `compat-corpus-v1`, `evaluator-v1`, all protocol/corpus/oracle/runtime/fixture identities, and the exact 100x growth rule. Do not modify Scheme-A recipes, budgets, thresholds, or required families.
- Emit `positive-baseline-v2-gate.json` with exact source/evidence/stage hashes, `completeUnits: 1`, `schemeAStatus: baseline-not-calibrated`, `schemeAClaimable: false`, and rollback metadata.
- Fail closed with no new baseline/reference publication when commit freshness, environment capability, manifest closure, stage linkage, oracle equality, or old-baseline immutability fails.

## Local Gate: compatibility-positive-immutable-baseline-v2

- `status=pass` only after all freshness, closure, identity, six-stage, hash, loader, behavior, and Scheme-A invariants pass.
- `status=blocked` retains the failed evaluator tree and previous zero baseline without writing v2 outputs.
- A passing v2 gate establishes a frozen denominator of one and a future growth target of 100; it does not set `claimable=true`.

## Acceptance Criteria

- [x] Fresh evaluator/environment/gate commit identity matches the checkout.
- [x] Historical zero baseline bytes/reference remain unchanged and content-addressed.
- [x] Fresh evaluator root and nested manifests are closed and digest-consistent.
- [x] Exactly one complete strict unit passes all six stages with distinct Protected/Native Image hashes and matching loader/oracle evidence.
- [x] v2 baseline payload/reference and local gate are deterministic, immutable, and externally hash-bound.
- [x] Scheme-A remains six-family `baseline-not-calibrated` with null factors and no claim.
- [x] Failed preconditions publish no v2 baseline/reference and retain rollback evidence.

## Out of Scope

- Product code, loader semantics, corpus/protocol/threshold changes, Scheme-A calibration, or claiming compatibility 100x.
