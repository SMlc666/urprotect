# Strict compatibility corpus expansion implementation plan

## 1. Preregister unique identities

- Build a candidate ledger of source provenance/hash, stable identityKey/unitId, producer recipe digest, profile/runtime/loader, independent oracle, eligibility rule, and artifact retention path.
- Verify no identity/source/oracle duplicates and no use of reruns/selector/profile variants to inflate counts.
- Review the source selection and append-only corpus version before execution.

## 2. Prove product eligibility and nearest negatives

- Run current Protected Image producer, rehydrator, and native handoff on representative stratified candidates.
- For each newly supported product operation/layout class, add positive and nearest-negative fixtures in its own product child first; never use candidate identities to encode product special cases.
- Require behavior-oracle reproducibility between native baseline and rehydrated Native Image.

## 3. Execute all registered candidates

- Use a native AArch64 glibc lane with frozen environment/toolchain, bounded resources, and closed evidence directories.
- Record every candidate failure at its first stage; do not silently skip an eligible registered row.
- Recompute source/protected/native/handoff/loader/oracle hashes and all six stage statuses.

## 4. Evaluate exact growth gate

- Run independent evaluator with positive v2 reference.
- Require fixed-view non-regression and at least 100 distinct complete growth identities.
- Preserve Scheme-A baseline-not-calibrated and `claimable=false` unless its independent gate separately passes.

## 5. Validation

```sh
python3 scripts/validate-evaluator-manifests.py --baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
python3 tests/test_evaluator_strict_chain.py
python3 tests/test_evaluator_positive_baseline.py
PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
PATH=/root/.dotnet:$PATH ./scripts/run-strict-compatibility-corpus.sh --tier pr --runtime glibc --skip-existing
PATH=/root/.dotnet:$PATH ./scripts/run-independent-evaluator.sh --tier pr --baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
PATH=/root/.dotnet:$PATH python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
PATH=/root/.dotnet:$PATH python3 scripts/check-strict-compatibility-growth.py .artifacts/evaluator/pr
```

## Rollback

Disable only the new compatibility candidate expansion job/rows if the gate regresses. Retain manifests, negative records, and raw evidence; never change v2 baseline or fall back from failed strict stages to auxiliary direct execution.
