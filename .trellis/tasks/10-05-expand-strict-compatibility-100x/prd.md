# Expand strict compatibility corpus to 100 complete units

## Goal

Reach the parent 100x compatibility growth condition from immutable baseline-v2 (`completeUnits=1`) by registering and completing 99 additional unique end-to-end strict units. Every added identity must exercise real producer -> Protected Image -> rehydration -> Native Image -> native loader -> frozen behavior oracle evidence; repeated builds, selector variants on the same identity, or runtime reruns do not inflate identity count.

## Requirements

- Preserve the v2 baseline/reference, fixed row, protocol, Scheme-A manifest and all thresholds.
- Before additions, define and validate an append-only corpus methodology with stable unique `unitId` and `identityKey`, locked source provenance/hash, producer recipe/build, profile/runtime/loader/oracle.
- Add distinct upstream/source identities; every candidate must be behaviorally executable and eligible for the strict chain. Unsupported producer/loader features remain explicit failed first-stage evidence and do not count.
- Use the current generic rehydrator/materializer/handoff and avoid sample-specific product branches. Expand product capability only in independently reviewed child tasks with nearest-negative tests.
- Run full native strict evidence per identity under the declared AArch64 glibc cell and retain six stage-specific hashes and closed raw manifests.
- Keep strict candidate fixed view non-regressing and growth identities distinct. Enforce exact integer target `candidateGrowthCompleteUnits >= 100 * 1`.
- Keep Scheme-A `baseline-not-calibrated`, all six required families, null factors, and `claimable=false`; compatibility growth alone is not an overall 100x claim.

## Local Gate: strict-compatibility-growth-100x

1. Frozen fixed unit remains complete and unchanged.
2. Exactly 100 distinct frozen/growth unit identities are complete with six stages passed; no duplicated source identity, run, selector, profile repeat, or artifact variant counts as new.
3. All 100 unit records bind their corpus row, source/source-image, Protected Image, rehydrator consumer, Native Image, loader, and oracle; all associated evidence manifests close.
4. Candidate growth count is at least 100, fixed view passes, compatibility factor is exactly computed against denominator 1, and no rounding or eligibility filtering is used.
5. Scheme-A remains independently not calibrated and overall `claimable=false` unless its separate required gate passes.

## Acceptance Criteria

- [x] Append-only reviewed corpus contains 100 unique strict-eligible unit identities including the fixed v2 unit.
- [x] All 100 strict units complete the six-stage oracle-backed chain with closed/hash-bound evidence.
- [x] Independent evaluator reports baselineCompleteUnits=1, candidateFixedCompleteUnits>=1, candidateGrowthCompleteUnits>=100, factor>=100.0, fixedViewPass=true, growthViewPass=true.
- [x] Anti-gaming checks reject duplicate identities, replays, selector/profile variants, fabricated stage hashes, and changed frozen metadata.
- [ ] All existing product/evaluator/negative/fuzz/runtime/benchmark/CI checks remain passing and no legacy direct-ELF evidence is counted.
- [ ] Scheme-A remains separate and non-claimable until each frozen family independently calibrates and passes.

## Out of Scope

- Changing 100x math or denominator semantics.
- Weakening Scheme-A or declaring an overall claim from compatibility alone.
- Counting reruns, profile/runtime variants, selector changes, or repackaging as distinct identities.
- Silent direct-ELF fallback or special-casing source identities in product code.
