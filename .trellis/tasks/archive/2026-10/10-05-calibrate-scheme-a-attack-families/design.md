# Scheme-A attack harness and calibration design

## Boundary

The evaluator remains a read-only scorer. This child adds pinned attack runners, immutable attack baselines, raw evidence capture, and independent per-family scorers. Product evidence is consumed by hashes only; it is not changed by the attack harness.

```text
strict Native Image + frozen blue oracle
  -> pinned red tool/recipe (3 baseline replicas)
  -> host-owned bounded process accounting/raw evidence
  -> family-specific objective scorer
  -> immutable content-addressed baseline v2
  -> identical candidate recipe/budget/tool/oracle
  -> factor per family, then frozen six-family conjunction
```

## Family adapters

- `runtime_dump_reassembly`: recover bytes through the target process/runtime dump interface; scorer validates loader-accepted rebuilt image and frozen behavior equivalence.
- `patch_repack`: make a behavior mutation only through the attacker-visible artifact workflow; scorer verifies mutated oracle behavior without a producer rebuild.
- `function_logic_recovery`: produce machine-readable recovered semantics/CFG; scorer compares it to a frozen semantic inventory with zero manual steps.
- `static_decomposition`: run pinned static tools against Protected Image/Native Image and score frozen structural inventory thresholds.
- `dynamic_instrumentation`: attempt required internal trace/state or replacement objective under isolation and resource limits; scorer checks the exact marker/trace predicates.
- `integrity_handoff`: tamper/replay/repack inputs; scorer observes whether forbidden behavior or required rejection is reached, binding the blue oracle and handoff records.

Each adapter has a versioned recipe, executable/container hash, command digest, environment digest, deterministic seed, resource budget, and independently testable scorer. Baseline and candidate use identical adapter contracts. Missing tools/capabilities remain unavailable, not calibrated.

## Immutable data

Create new Scheme-A baseline-v2 manifest/reference outputs only after all six families each have three finite reproducible baseline successes. The frozen v1 manifest and compatibility baseline-v2 remain unchanged. The new reference hashes canonical baseline payload bytes and binds all recipe/tool/oracle/budget/replica/artifact identities. Mixed baseline replicas or any family without a finite success blocks freezing.

## Rollback

Disable only the new Scheme-A runner/profile when its gate fails; keep failed raw evidence and prior manifests. Never downgrade required families, budgets, scorers, or factors to obtain a pass. Overall `claimable` remains false until compatibility also independently passes.
