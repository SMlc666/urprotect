# Reconcile compatibility claims and release evidence

## Goal

Integrate completed compatibility and architecture-quality child deliverables
into one internally consistent support matrix, aggregate report, documentation
set, specification, and release evidence package.

## Dependencies and constraints

- This child is the final integration deliverable and waits for every selected
  feature/runtime/refactor child to pass its own quality gates.
- It must not invent support claims or upgrade `unknown`/`rejected` rows without
  their source child’s evidence.
- Outer, HostContext, parser/model, and runtime-specific rows remain distinct.

## Requirements

- Reconcile feature IDs/statuses and sample result vocabulary across manifests,
  generated reports, tests, scripts, README, `COMPATIBILITY.md`, release
  packaging, and Trellis specs.
- Check for stale frame/profile/version language, duplicate contract owners,
  duplicate active implementations, and evidence paths with no producer.
- Run complete managed/native/fixture/fuzz/stress/evidence/release checks at
  their declared tiers.
- Record remaining rejected/unknown boundaries and unavailable environments
  as explicit limitations.

## Acceptance Criteria

- [ ] Generated compatibility and real-sample reports agree with manifests
      and retained artifacts.
- [ ] Every released claim points to positive and negative evidence plus a
      matching runtime environment.
- [ ] Full cross-layer tests and release smoke pass; all artifacts are
      non-empty and provenance-complete.
- [ ] Architecture/code-quality review finds no duplicate active owners,
      unplanned monolith growth, stale contracts, or unexplained diagnostics.
- [ ] Final support boundary and remaining work are documented without treating
      sample count as proof by itself.
