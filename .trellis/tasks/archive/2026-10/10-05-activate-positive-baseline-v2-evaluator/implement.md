# Positive baseline-v2 evaluator activation plan

## 1. Runner input

- Add `--baseline-reference` to `run-independent-evaluator.py` and shell wrapper passthrough.
- Validate/copy selected reference and its payload into evaluator evidence; use selected baseline in `validate_all_manifests` and `calculate_compatibility`.
- Keep default historical reference unchanged.

## 2. Tests

- Add focused tests for v2 measured values, stale reference/payload, omitted default fallback, and no mutation of old baseline.
- Run evaluator schema/anti-gaming/compatibility/Scheme-A tests and full current product evidence checks.

## 3. CI/report

- Add an explicit v2 rehearsal/profile only after local tests pass; do not switch the required default claim gate until parent review.
- Record selected baseline ID in evidence and keep `claimable=false` until growth and Scheme-A gates pass.

## Validation

```sh
python3 tests/test_evaluator_positive_baseline.py
./scripts/run-independent-evaluator.sh --tier pr --baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
```

## Rollback

Remove only the explicit v2 baseline argument/profile and return to the historical zero-baseline reference; retain v2 evidence and payload immutably.
