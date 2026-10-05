# Final 100x integration gate design

The parent final gate consumes the independent evaluator plus all existing CI job outputs. It is a verification/integration child, not a product implementation path.

```text
immutable baseline-v2 (1 strict unit)
  + append-only 99+ unique strict units
  -> independent compatibility fixed/growth derivation

six immutable Scheme-A family baselines
  + identical candidate replicas/tools/recipes/budgets/oracles
  -> six independent >=100 factors

both dimensions + anti-gaming + existing CI evidence
  -> claimable derived by evaluator only
```

The gate must use exact commit-bound closed evidence, recompute all stage/family counts, preserve auxiliary evidence distinctions, and fail closed for any missing/unknown/environment-unavailable/protocol-failure row. CI may only require claimability after both denominator and Scheme-A baselines are positively calibrated; once calibrated, a failed 100x dimension blocks the final claim.
