# Strict compatibility growth gate evidence

Date: 2026-10-05

The reviewed append-only corpus now contains 100 registered rows: one frozen
v2 identity and 99 growth identities. Each growth row has a distinct source
provenance, source SHA-256, identity key, unit ID, producer recipe digest,
profile, runtime cell, loader, and frozen oracle ID.

The retained native glibc run was produced by:

```sh
PATH=/root/.dotnet:$PATH \
  ./scripts/run-strict-compatibility-corpus.sh \
  --tier pr --runtime glibc
```

The independent evaluator used the immutable v2 reference:

```sh
PATH=/root/.dotnet:$PATH \
  ./scripts/run-independent-evaluator.sh \
  --tier pr \
  --baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
PATH=/root/.dotnet:$PATH \
  python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
PATH=/root/.dotnet:$PATH \
  python3 scripts/check-strict-compatibility-growth.py .artifacts/evaluator/pr
```

Observed gate values:

- `baselineArtifactId`: `compatibility-1x-v2`
- `baselineCompleteUnits`: `1`
- `candidateFixedCompleteUnits`: `1`
- `candidateGrowthCompleteUnits`: `100`
- `growthTarget`: `100`
- `factor`: `100.0`
- `fixedViewPass`: `true`
- `growthViewPass`: `true`
- all anti-gaming checks: `true`
- Scheme-A: `baseline-not-calibrated`, all six factors `null`
- overall `claimable`: `false`


This local checkout is AArch64 but reports Ubuntu 26.04/Android-kernel facts and therefore records `environment.status=environment-unavailable`; the local run is evidence for the chain implementation, not a declared runtime-cell claim. The CI job runs the same corpus on `ubuntu-24.04-arm` inside the isolated evaluator wrapper and the strict growth checker requires `environment.status=available` before accepting the growth gate.
The evaluator root is closed and the six stage records for all 100 complete
units are hash-bound to their product evidence. Auxiliary direct-ELF and
legacy wrapper evidence are not projected into the strict units. The local
checker is `scripts/check-strict-compatibility-growth.py`; it independently
recomputes the 100-row identity set, fixed row, gate values, Scheme-A
separation, and complete six-stage unit set after the evaluator evidence
checker passes.

The compatibility corpus/protocol manifest ledger is append-only: the
historical zero baseline and positive v2 payload/reference remain immutable,
while the current protocol ledger records the expanded corpus digest. The
frozen fixed row is checked by its content-addressed row digest before the
positive denominator is accepted.
