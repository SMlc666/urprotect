# Calibrate Scheme-A attack families

## Goal

Implement and run the versioned red/blue Scheme-A harness so every frozen attack family obtains three finite reproducible baseline successes, freezes an immutable baseline, and can then be measured against candidates under the exact per-family `>=100x` gate.

## Requirements

- Preserve `scheme-a-v1`, six required family IDs/order, frozen budgets, network-disabled policy, zero manual steps, tool/recipe identity, and per-family 100x conjunction.
- Add pinned attack tools/runner and reproducible recipes for `runtime_dump_reassembly`, `patch_repack`, `function_logic_recovery`, `static_decomposition`, `dynamic_instrumentation`, and `integrity_handoff`.
- Each family must produce three finite baseline replicas with identical source/artifact/runtime/tool/recipe/budget/oracle bindings and complete raw evidence before a family baseline can be calibrated.
- Use independent objective success scorers and validate blue behavior/integrity oracle for every attempt. Missing tool/capability or nonfinite/mixed baseline results remain environment-unavailable/unknown/not-calibrated, never pass or infinity.
- Freeze additive content-addressed Scheme-A baseline v2 only after all family baselines and all three replicas are reproducibly verified. Preserve existing Scheme-A manifest and historical baseline; create a new reviewed manifest/reference version instead of mutating frozen inputs.
- Add tamper, replay, missing-evidence, mixed-replica, tool/budget/oracle-drift and timeout/resource-limit negative tests; retain raw evidence on every result.
- Keep compatibility baseline/growth calculations separate. Scheme-A alone cannot make the overall evaluator claimable.

## Local Gate: scheme-a-baseline-calibration-v2

1. All six frozen family IDs are present and required in original order.
2. Each family has three successful baseline replicas with finite measured CPU cost and matching tool/recipe/source/artifact/runtime/budget/oracle hashes.
3. Each raw evidence tree is bounded, closed, content-addressed, and independently revalidated by its family scorer.
4. Every family baseline is immutable/content-addressed and has a new reference version; no historical manifest/baseline is overwritten.
5. Candidate factor math and anti-gaming checks preserve strict per-family 100x policy; missing candidate capability remains visible and gate-blocking.

## Acceptance Criteria

- [x] All six red-team recipes and blue oracles are pinned, deterministic, isolated, bounded, and machine-scored.
- [x] Three finite reproducible baseline successes are retained for each required family.
- [x] A content-addressed immutable Scheme-A baseline v2 and local checker pass.
- [x] Nearest-negative, tamper/replay, tool/oracle/budget drift, mixed results and missing evidence fail closed.
- [x] Existing compatibility, evaluator, product, runtime, fuzz, benchmark, and CI contracts remain passing.
- [x] No family threshold, frozen budget, required-family list, or overall conjunction is weakened.
## Out of Scope

- Changing the six family definitions or 100x threshold.
- Counting compatibility growth as Scheme-A strength.
- Promoting overall `claimable=true` unless compatibility also independently passes.
