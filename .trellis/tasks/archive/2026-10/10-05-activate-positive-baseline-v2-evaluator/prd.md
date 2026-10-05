# Activate positive baseline v2 in evaluator

## Goal

Make the independent evaluator consume the additive content-addressed `compatibility-1x-v2` denominator without mutating historical `compatibility-1x-baseline-zero` or changing protocol/corpus/Scheme-A policy. Establish a measured one-unit 1x result with an exact future growth target of 100.

## Requirements

- Add an explicit evaluator baseline-reference input/profile for `compatibility-1x-v2-reference.json`; default historical behavior remains unchanged when omitted.
- Validate v2 reference/payload content address, immutable flags, exact corpus/protocol identity, one complete unit, and all six stage/hash/oracle links.
- Re-run the current strict unit against v2 and report `compatibility.status=measured`, `baselineCompleteUnits=1`, `candidateFixedCompleteUnits=1`, `candidateGrowthCompleteUnits=1`, `factor=1.0`, `growthTarget=100`, `growthViewPass=false`, and `claimable=false` because growth and Scheme-A do not pass.
- Preserve Scheme-A `baseline-not-calibrated`, six required families, null factors, and no strength claim.
- Add tests for omitted/zero baseline fallback, v2 activation, stale/mismatched reference, and no historical baseline mutation. Keep evaluator output read-only and closed.

## Local Gate: evaluator-positive-baseline-v2

A fresh run with `--baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json` passes the v2 identity and strict unit checks, yields exact measured 1x values and target 100, and remains non-claimable.

## Acceptance Criteria

- [x] Evaluator v2 reference input and content-address validation exist.
- [x] Fresh v2 run reports measured 1x, future target 100, fixed-view pass, growth-view fail, null Scheme-A factors, and claimable false.
- [x] Historical zero baseline/reference and default baseline-zero behavior remain unchanged.
- [x] CI/evaluator tests and full product evidence remain passing.
- [x] No compatibility growth or Scheme-A policy is silently redefined.

## Out of Scope

- Adding 99 new compatibility identities or claiming 100x.
- Scheme-A tool implementation/calibration.
- Product loader or protection changes.
