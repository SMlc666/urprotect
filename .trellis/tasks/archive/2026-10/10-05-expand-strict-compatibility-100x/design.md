# Strict compatibility corpus expansion design

## Identity and evidence model

One compatibility identity is an upstream source/provenance + frozen behavior contract + producer chain identity. Runtime reruns, compiler rebuilds, different protected operation seeds, profile/runtime variants, and selector variants of the same registered source are evidence attempts for that identity, not new growth units.

```text
registered identity
 -> locked Source Image
 -> explicit producer recipe
 -> Protected Image role/bytes
 -> GenericRehydrationEngine
 -> distinct Native Image role/bytes
 -> sealed memfd/execveat target loader
 -> frozen per-identity behavior oracle
 -> six-stage evaluator unit
```

The existing evaluator fixed row and content-addressed v2 baseline remain immutable. New corpus rows append only after source, producer, oracle, profile, runtime, target loader, and strict eligibility are reviewed.

## Stratification and selection

Use a preregistered, bounded selection plan across producer recipes and executable-code/ELF shape, while respecting the current rehydrator's explicit layout and operation limits. Reject eligibility by deterministic manifest rule before execution; keep failed eligible rows in the candidate set with first-failure stage. Do not special-case identity names in product code. Each source gets an oracle checked from an independent baseline execution and the same retained target process comparison.

## Gate and rollback

The local checker consumes evaluator gate/unit records and closed raw manifests, recomputes identity uniqueness and six-stage bindings, checks all baseline fixed rows, and requires at least 100 distinct complete candidate growth units against v2 denominator 1. On any mismatch or failed chain, emit a blocked report retaining all evidence. Roll back by disabling only new corpus rows/runner scheduling; never delete or rewrite v2 or historical zero-baseline objects.
