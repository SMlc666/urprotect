# Bind the independent evaluator to the strict Protected Image chain

## Goal

Make the read-only independent evaluator consume the retained producer -> Protected Image -> rehydration -> Native Image -> native loader -> behavior-oracle evidence without hard-coding the old `baseline-zero` placeholder. Preserve the frozen corpus identity, Scheme-A manifest, 100x thresholds, and claimability rules; the first integrated result may remain non-claimable because the immutable 1x baseline is still zero and Scheme-A is not calibrated.

## Requirements

- Add a read-only evaluator input binding to `.artifacts/protected-image/<tier>/<runtime>/<unit>/` and validate that the evidence root is bounded, real, symlink-free, unit-specific, and produced by the current product chain.
- Recompute the six compatibility stage records from retained JSON/bytes rather than trusting a single producer field. Bind stage-specific hashes, ABI/consumer/loader/oracle identities, source-image hash, unit/profile, and closed raw manifests.
- Preserve the corpus row's source provenance/hash as the registered identity while recording the compiled Source Image hash separately; never silently equate a source file digest with a compiled image digest.
- Copy or reference exact raw evidence inside the evaluator tree and emit a strict `compatibility/<unit>/unit.json` that can become complete when all six stages pass. Failed/missing stages remain explicit first-failure rows.
- Keep old baseline-zero behavior when product evidence is absent. With the current one-unit vertical slice present, report the observed complete candidate unit but retain `baseline-zero`, null factor, `claimable=false`, and Scheme-A `baseline-not-calibrated`.
- Add CI artifact download/binding so the evaluator job sees build-and-test Protected Image/rehydration evidence on success/failure while retaining existing evaluator and upload gates.
- Add anti-gaming tests for forged stage fields, missing stage-specific hashes, mismatched source-image/role hashes, unsafe evidence roots, stale/partial files, and producer-only evidence.

## Local Gate: evaluator-strict-chain-v1

1. The evaluator's current PR output contains one complete strict unit when the retained vertical-slice evidence passes all six stages.
2. The output remains non-claimable with `baseline-zero`, null compatibility factor, and `baseline-not-calibrated` Scheme-A status; no threshold or baseline mutation occurs.
3. Removing/tampering any producer, rehydration, Native Image, handoff, loader, oracle, or checksum record produces an explicit incomplete/failure stage and fails the evidence gate.
4. The evaluator output remains closed, content-addressed, read-only against source/manifests/baseline, and passes existing schema/anti-gaming tests.

## Acceptance Criteria

- [x] Evaluator binds retained strict-chain evidence and recomputes all six stage records.
- [x] Current vertical slice is visible as a complete candidate unit while frozen baseline/claimability semantics remain unchanged.
- [x] Missing/tampered/producer-only evidence is rejected or classified with the correct first-failure stage.
- [x] CI downloads/retains product-chain evidence for the evaluator job on success/failure without replacing existing jobs.
- [x] Existing full .NET/native/protection/rehydration/evaluator/schema/anti-gaming checks remain passing.
- [x] No corpus identity, baseline object, Scheme-A recipe, or 100x threshold is mutated.

## Out of Scope

- Freezing a new positive baseline or claiming compatibility 100x.
- Scheme-A attack execution/calibration.
- Appending 100 distinct challenge units or changing evaluator growth math.
- Product loader semantics or additional Native Image layout strategies.
