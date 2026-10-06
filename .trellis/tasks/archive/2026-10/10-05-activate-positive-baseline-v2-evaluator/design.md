# Positive baseline-v2 evaluator activation design

## Boundary

The evaluator runner accepts an explicit baseline-reference path, validates it through the existing content-addressed baseline validator, and passes its baseline object into the existing compatibility calculation. No manifest or historical reference is rewritten.

```text
--baseline-reference v2-reference
  -> validate reference/payload
  -> calculate_compatibility(v2 completeUnits=1)
  -> measured factor=1.0, growthTarget=100
  -> Scheme-A remains independent/non-calibrated
```

The default path remains `fixtures/evaluator/baseline-reference.json`, preserving old baseline-zero runs and tests.

## Evidence and rollback

The evaluator copies the selected reference into its own evidence tree and records the selected baseline ID/digest in gate/analysis-input. A mismatched reference, changed payload, old baseline mutation, or missing strict unit fails before a claimable result. Rollback is selecting the historical reference again; no product/evidence files are deleted or mutated.
