# Independent Evaluator Design

## Boundary

The evaluator is a read-only measurement control plane under `scripts/`, `fixtures/`, `tests/`, and `.artifacts/evaluator/`. It binds product-produced artifacts and native execution evidence; it does not implement Protected Image semantics or a loader.

## Compatibility protocol

Pre-register an append-only corpus with unique `unitId`/`identityKey`, source/provenance hashes, profile, runtime cell, loader, and oracle. Maintain fixed and growth views. A unit is complete only when all six stages pass for the same source/profile/runtime/oracle. Count distinct complete IDs; retain every failure and first-failure layer. Current product state must report baseline-zero because the Protected Image and rehydration stages do not exist.

## Scheme-A protocol

Use six family IDs: `runtime_dump_reassembly`, `patch_repack`, `function_logic_recovery`, `static_decomposition`, `dynamic_instrumentation`, `integrity_handoff`. The manifest freezes applicability, recipes, tools, seed, replica count, budgets, threat model, and objective success predicates. Three deterministic replicas are required for baseline and candidate. Cost is process-tree CPU nanoseconds to independently verified success; unsuccessful fully budgeted candidates are censored lower bounds. A family passes only with a finite immutable baseline and factor >=100. The gate is conjunction over required families.

## Evidence tree

```text
.artifacts/evaluator/<tier>/
  environment.json
  protocol.json
  corpus-manifest.json
  baseline-reference.json
  compatibility/<unit-id>/unit.json + raw/SHA256SUMS
  strength/<family>/replica-N/attempt.json + raw/SHA256SUMS
  benchmark/
  gate.json
  analysis-input.json
  SHA256SUMS
```

All retained evidence is bounded, normalized, hashed, and path-safe. Public sanitization must retain exact hash/size and deterministic regeneration metadata when raw bytes are removed.

## Status rules

`passed`, `failed`, `environment-unavailable`, `not-applicable`, `unknown`, and `protocol-failure` are explicit. `baseline-zero`, `baseline-not-calibrated`, and `not-ready` represent missing denominators/protocol calibration and never pass the parent claim.

## Handoff

`gate.json` is normative. `analysis-input.json` contains first-failure layers, family factors, missing evidence, regressions, and residual blockers. The analysis agent must use it to create the next Trellis child and local gate.
