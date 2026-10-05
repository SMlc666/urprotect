# Final 100x integration audit

Date: 2026-10-05

## Normative CI evaluator result

The authoritative final PR evaluator run is GitHub Actions run `37334303825` (`independent-evaluator` job), with the complete producer/test/runtime/sample evidence graph retained. The evaluator artifact is commit-bound to checkout merge commit `63d6ef75d2dc595ebdd4e45eb94d53d932ba4396` and passed the independent evidence checker, strict compatibility growth gate, and positive-baseline claim gate.

The selected inputs were:

```text
./scripts/run-independent-evaluator.sh \
  --tier pr \
  --scheme-a-manifest fixtures/evaluator/scheme-a-manifest-v2.json \
  --baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
python3 scripts/check-independent-evaluator.py \
  .artifacts/evaluator/pr \
  --scheme-a-manifest fixtures/evaluator/scheme-a-manifest-v2.json \
  --require-claimable-if-baseline-positive
python3 scripts/check-strict-compatibility-growth.py \
  .artifacts/evaluator/pr \
  --scheme-a-manifest fixtures/evaluator/scheme-a-manifest-v2.json
```

Recomputed `gate.json` values:

- compatibility baseline complete units: `1`;
- candidate fixed complete units: `1`, fixed-view pass: `true`;
- candidate growth complete units: `100`, growth target: `100`, growth-view pass: `true`;
- exact compatibility factor: `100.0`;
- first-failure counts: `{}`;
- Scheme-A status: `pass`;
- Scheme-A all-required pass: `true`;
- family lower-bound factors:
  - `runtime_dump_reassembly`: `379.48496421478177`;
  - `patch_repack`: `229.17218116099104`;
  - `function_logic_recovery`: `450.3232947574726`;
  - `static_decomposition`: `444.21828107401967`;
  - `dynamic_instrumentation`: `449.4210220298976`;
  - `integrity_handoff`: `300.7807568926059`;
- evaluator environment: `available`, `glibc.current.native-arm64`;
- anti-gaming fields: all `true`;
- `claimable`: `true`.

The retained evaluator tree contains 100 complete strict units, six stages per unit, six Scheme-A families with three baseline and three candidate replicas, copied Scheme-A v2 baseline reference/artifact, closed raw manifests, and a closed top-level `SHA256SUMS`. The Scheme-A gate binds `scheme-a-baseline-v2`; it does not reuse the compatibility baseline ID.

## Immutable policy and identity audit

- Historical `compatibility-1x-baseline-zero`, its reference, and default evaluator behavior remain unchanged.
- Compatibility `compatibility-1x-v2` remains the one-unit immutable denominator and its reference remains content-addressed.
- Historical `scheme-a-manifest.json` remains the default `scheme-a-v1` policy with six required families and `baseline-not-calibrated` status.
- Additive `scheme-a-manifest-v2.json` is parent-bound to the frozen v1 manifest, content-addressed, and selected explicitly by CI.
- Additive Scheme-A baseline reference/artifact is immutable, never overwritten, and stores the maximum finite baseline replica cost for every family. Candidate factors are recomputed against those frozen costs.
- No duplicate identity, rerun, selector/profile variant, auxiliary direct-ELF result, compatibility stage projection, or hand-edited marker contributes to the claim.

## Product and CI evidence

The PR graph passed `build-and-test`, `real-sample-matrix`, `runtime-matrix-native-arm64`, `bionic-native-arm64`, `musl-container-smoke`, and `independent-evaluator`; optional jobs that were not applicable to the PR event remained explicitly skipped. The evaluator job preserved always-upload evidence and required all existing evidence-job results before the final claim gate.

The evaluator sandbox fallback is covered by a staged read-only checkout, exact checkout commit handoff, host-captured tool identity handoff before seccomp, network-deny seccomp, bounded resources, and an in-process wrapper fallback only for `EAGAIN` child creation under the frozen process limit. Other missing tools, invalid evidence, or scorer failures remain explicit unavailable results.

Local verification also passed:

- `python3 -m unittest discover -s tests -p 'test_*.py'` — `290` tests;
- focused evaluator, strict-chain, positive-baseline, workflow, anti-gaming, and Scheme-A tests — all passed;
- historical and additive evaluator manifest validation;
- additive Scheme-A baseline checker with three finite baseline replicas per family;
- explicit additive evaluator plus independent evidence checker;
- evaluator under `RLIMIT_NPROC=1`, exercising the in-process scorer fallback;
- `git diff --check`, Python syntax compilation, and shell syntax checks.

The CI build-and-test job also retained the existing .NET, fixture, native runtime, handoff, benchmark, fuzz, stress, real-sample, and matrix evidence gates. The final claim is based on the CI artifact, not local environment substitution.

## Rollback

Rollback preserves all immutable v1/v2 baseline objects, manifests, raw evidence, and negative witnesses. Disable only the additive Scheme-A v2 selection and evaluator job if a later run regresses; restore the historical default manifest/reference selection without changing compatibility or Scheme-A thresholds.
