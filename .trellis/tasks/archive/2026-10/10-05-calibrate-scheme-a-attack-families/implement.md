# Scheme-A attack harness implementation plan

## 1. Freeze adapter interfaces

- Define typed recipe/tool/environment/replica/status/scorer contracts without editing the frozen Scheme-A v1 manifest.
- Require content-addressed tool/container hashes, exact command/environment digests, deterministic seed, frozen budget, source/artifact/native hashes, runtime identity, and blue oracle ID for every attempt.
- Add schema validation and closed raw evidence manifests before executing tools.

## 2. Implement six red/blue adapters

- Implement each family as a separately versioned runner/scorer with an independent objective predicate.
- Run all baseline attempts in an isolated AArch64-compatible environment with network disabled, read-only inputs, process-tree time/CPU/RSS/output/artifact limits, and zero manual steps.
- Retain command/stdout/stderr/resource/tool/environment/raw outputs, status, and scorer decision for success, failure, unavailable, timeout, and protocol failure.
- Add synthetic scorer tests and nearest-negative inputs before any baseline execution.

## 3. Calibrate and freeze immutable baseline v2

- Run exactly three baseline replicas per required family using the locked recipes/tools/budgets/oracles.
- Require all replicas per family to yield finite reproducible success costs before freezing any family baseline; mixed outcomes remain uncalibrated/blocked.
- Create new append-only Scheme-A baseline-v2 payload/reference without overwriting v1; record immutable content digest and all source/tool/recipe/oracle/environment/raw-manifest hashes.

## 4. Candidate scoring and integration

- Run three candidate replicas under byte-identical family policy.
- Compute each family factor using the frozen scorer/cost rule and require each family independently `>=100`; maintain the fixed six-family conjunction.
- Feed scored attempt records to the evaluator without changing compatibility math. Overall claim remains false until compatibility gate also passes.
- Add a bounded tiered CI job and always-upload evidence on success/failure; PR executes fixed recipes, nightly/release may add repetitions but do not weaken PR.

## 5. Validation

```sh
python3 scripts/validate-evaluator-manifests.py
python3 tests/test_scheme_a_gate.py
python3 tests/test_scheme_a_attack_adapters.py
python3 tests/test_scheme_a_evidence.py
python3 scripts/check-scheme-a-baseline-v2.py --tier pr
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
```

## Rollback

Disable only the additive Scheme-A attack job/adapters. Preserve v2 baseline/evidence failures and all prior v1 manifests. Never alter frozen budgets, family requirements, oracle semantics, or report a compatibility-only overall claim.
