# Strict evaluator chain binding implementation plan

## 1. Evidence adapter

- Add bounded read-only product-evidence adapter/checks in `scripts/evaluator_lib.py` or a dedicated evaluator module.
- Validate source image, producer role/stage, Protected Image canonical bytes, rehydration/native roles, handoff, target-loader, behavioral-oracle, and closed product manifest.
- Copy verified product evidence into evaluator raw evidence and hash the copied tree.

## 2. Unit projection

- Replace only the hard-coded `make_compatibility_unit` placeholder path when a valid product evidence root is present.
- Project all six stage statuses and stage-specific digest/required fields; preserve baseline-zero fallback if the root is absent or invalid.
- Add `sourceImageSha256` as a separate computed binding from the corpus source-provenance `sourceSha256`.

## 3. CI integration

- Download build-and-test `test-evidence-${{ github.run_id }}` in the independent evaluator job, tolerating missing evidence only so failure artifacts remain diagnosable.
- Pass/resolve the product evidence root without changing evaluator output ownership or existing job dependencies.

## 4. Tests

- Add evaluator unit tests for complete projection, missing/tampered stage, role/source mismatch, unsafe/symlink evidence, closed-manifest drift, producer-only fallback, and zero-baseline non-claimability.
- Run full .NET/native/protection/rehydration checks and all evaluator schema/anti-gaming tests.

## Validation

```sh
python3 tests/test_evaluator_strict_chain.py
python3 scripts/validate-evaluator-manifests.py
./scripts/run-independent-evaluator.sh --tier pr
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build
```

## Rollback

Unset the product evidence root/download step and retain the baseline-zero projection, without changing frozen manifests, Scheme-A rules, or prior evaluator artifacts.
