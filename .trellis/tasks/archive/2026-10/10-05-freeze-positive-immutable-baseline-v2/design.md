# Positive immutable compatibility baseline-v2 design

## Boundary

This child owns a read-only local gate and additive baseline assembly over a fresh evaluator tree. It does not implement product stages or change evaluator policy. The historical zero baseline remains immutable input:

```text
fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json
```

Additive outputs are `compatibility-1x-v2.json`, `compatibility-1x-v2-reference.json`, and `.artifacts/evaluator/pr/positive-baseline-v2-gate.json`.

## Gate algorithm

1. Compare checkout, evaluator gate, and environment commits.
2. Verify evaluator root, unit raw, product-chain, and product-evidence manifest entries and require observed root-manifest SHA to equal both gate digest fields.
3. Verify native AArch64/glibc compatibility capabilities and exact corpus/protocol/oracle/runtime identities; Scheme-A capability remains independent.
4. Verify one required fixed unit has exactly six passed stage keys with matching unit/source-image/profile/runtime/oracle identity.
5. Recompute Protected Image, Native Image, source-image, handoff, loader, oracle, and manifest hashes; require distinct Protected/Native hashes and target behavior equality.
6. Verify historical zero-baseline bytes and digest remain unchanged.
7. Deterministically project one-unit baseline-v2 payload, hash it, then write an external reference whose digest points to the payload bytes. Never use a circular self-hash.
8. Verify Scheme-A still contains all six required families, remains `baseline-not-calibrated`, has null family factors, and emits no claim.
9. Emit `status=pass` only after every condition passes; otherwise emit `blocked` and do not publish v2 payload/reference.

The resulting denominator is one. The parent still applies the exact integer growth condition `candidateGrowthCompleteUnits >= 100 * frozenBaselineCompleteUnits`; freezing v2 itself is not a 100x result.

## Rollback

Before publication, retain failed evaluator evidence and leave the historical zero baseline active. After publication, never overwrite v2; a changed corpus/protocol/oracle/toolchain/runtime creates a new content-addressed version. A failed strict stage never falls back to direct protected ELF.
