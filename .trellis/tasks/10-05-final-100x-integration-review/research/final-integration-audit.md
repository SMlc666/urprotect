# Final 100x integration audit

Date: 2026-10-05
Commit under test: `1a660a0ddf932cd1247739e060be7e6a219fcf6c`

## Normative evaluator result

The explicit positive-baseline run was executed after the product, native, and managed checks:

```text
EVALUATOR_COMPATIBILITY_MODE=1 EVALUATOR_NETWORK_DISABLED=1 \
  ./scripts/run-independent-evaluator.sh --tier pr \
  --baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
```

Both commands passed their evidence checks. The recomputed gate is deliberately non-claimable:

- baseline: `compatibility-1x-v2`, immutable denominator `1`;
- candidate fixed complete units: `1`, fixed-view pass: `true`;
- candidate growth complete units: `1`, required growth: `100`, growth-view pass: `false`;
- compatibility factor: `1.0`;
- Scheme-A status: `baseline-not-calibrated`;
- all six family factors: `null` (no pinned attack toolset or finite baseline replicas);
- anti-gaming checks: all `true`;
- `claimable`: `false`.

The checked-in corpus still contains one required identity and the Scheme-A manifest still contains the six frozen required families. No identity or attack result was added by this review.

## Integration polish applied

- `.github/workflows/ci.yml` now installs the pinned SDK in the independent evaluator job, validates both historical and positive baseline references, and passes the immutable positive baseline-v2 reference explicitly. This prevents the CI job from silently falling back to the historical zero denominator.
- Claim derivation is shared by the runner and checker and now requires the evaluator environment status to be `available` in addition to the existing compatibility, Scheme-A, and anti-gaming conjunction. An unavailable declared native/isolation cell cannot produce a claimable gate.
- Added a focused schema test for the environment fail-closed rule.

Frozen baseline, corpus, protocol, Scheme-A policy, budgets, and thresholds were not edited.

## Validation outcomes

Passed:

- `dotnet restore UrProtect.sln --locked-mode`.
- `dotnet build UrProtect.sln --configuration Release --no-restore` (0 warnings, 0 errors).
- `dotnet test UrProtect.sln --configuration Release --no-build` (175 passed).
- `python3 -m unittest discover -s tests -p 'test_*.py'` (282 passed).
- Historical and explicit-v2 evaluator manifest validation.
- Evaluator schema, anti-gaming, positive-baseline, strict-chain, compatibility-unit, and Scheme-A gate tests.
- Explicit v2 evaluator plus post-run checker.
- Protected Image producer E2E and evidence checker.
- Generic rehydration/Native Image/native handoff E2E and evidence checker (all six stages passed for the frozen unit).
- Protection E2E (`glibc`, PR tier).
- Fixture matrix and fixture evidence gate (7 PR cases).
- Regression stress (6 tests) and coverage-guided fuzz smoke.
- Native runtime `contract-check` and `make test` (HostContext, TLS, PLT, version, dependency graph, and memfd handoff tests).
- Managed HostContext handoff smoke.
- Benchmark executable (all benchmark sections completed).
- Real-sample registry plus manifest/fingerprint/aggregate/evidence/security tests.
- Coverage floor check and prior feature evidence gates.

Environment-limited or blocked (retained as residuals, not converted to passes):

- Packed fixture matrix and musl container smoke: `musl-gcc` is absent.
- Bionic fixture: Docker is absent.
- Full runtime matrix: local host reports Ubuntu `26.04`, while the declared current cell requires Ubuntu `24.04`; no local runtime claim was made.
- Runtime evidence checker rejects the retained stale artifact because its recorded CLI build hash differs from the current checkout build.
- Real-sample acquisition/runner: correctly refuses outside GitHub Actions CI before network access.
- Positive-baseline-v2 publication checker `--check-only` was not used as a final-gate command; when pointed at the already-active v2 evaluator it correctly blocks because that publication-time checker requires the historical baseline-zero input. The immutable v2 reference itself validates and the explicit v2 evaluator/checker pass.

## Residual parent goals

The parent remains open and non-claimable. The existing expansion child must produce 99 additional distinct complete strict units (with closed six-stage evidence) before the integer growth target can pass. The existing Scheme-A calibration child must provide three finite immutable baseline successes for each frozen family and then candidate measurements; no family currently has a factor. Native CI must rerun the declared runtime, musl, bionic, packed, and real-sample cells before those evidence gates can be considered green.
