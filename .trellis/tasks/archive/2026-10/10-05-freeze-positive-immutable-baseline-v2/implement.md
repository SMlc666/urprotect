# Positive immutable compatibility baseline-v2 implementation plan

## 1. Fresh exact-commit preflight

- Confirm current task/branch and `git rev-parse HEAD`.
- Run producer/rehydration evidence and independent evaluator at that exact commit.
- Confirm evaluator gate/environment commits match checkout and required compatibility capability facts are present.
- Verify historical zero baseline/reference hashes before writing any new file.

## 2. Implement local checker

Add `scripts/check-positive-immutable-baseline-v2.py` with bounded read-only inputs:

```sh
python3 scripts/check-positive-immutable-baseline-v2.py \
  --evaluator-root .artifacts/evaluator/pr \
  --product-root .artifacts/protected-image/pr/glibc/compat.protection-symbolized-fixture.glibc.outer-execveat \
  --previous-baseline fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json \
  --output .artifacts/evaluator/pr/positive-baseline-v2-gate.json
```

The checker validates root/nested manifests, all six stages, exact hash/role/oracle links, old-baseline immutability, Scheme-A non-claimability, and deterministic JSON. It emits `blocked` without publishing a payload/reference on failure.

## 3. Publish additive payload/reference

- Project `compatibility-1x-v2.json` with one complete unit and exact evidence ledger.
- Hash payload bytes and write `compatibility-1x-v2-reference.json` externally.
- Re-run checker with payload/reference inputs and verify no overwrite of v1 zero baseline.

## 4. Tests and CI

- Add local-gate tests for pass, stale commit, root-manifest mismatch, tampered stage, source/Native alias, missing negative, Scheme-A drift, and rollback/no-publication.
- Keep existing evaluator runner/checker and full product checks passing.
- Add additive CI execution/upload only after the local gate is proven; no claimability policy change.

## Validation

```sh
python3 scripts/validate-evaluator-manifests.py
python3 scripts/check-positive-immutable-baseline-v2.py --help
python3 tests/test_positive_baseline_v2.py
python3 tests/test_evaluator_strict_chain.py
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build
```

## Rollback

If any precondition fails, publish only a blocked local gate and retain raw evidence. Never overwrite the zero baseline or select v2 as active until the parent reviews the pass.
