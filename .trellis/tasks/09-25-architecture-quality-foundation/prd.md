# Audit and refactor architecture foundation

## Goal

Establish the architecture and behavior baseline required for broad AArch64
compatibility work. Characterize current contracts, identify responsibility
hotspots and duplicate owners, then refactor the first boundaries without
changing compatibility claims or public behavior.

## Dependencies and constraints

- This is the first implementation child of parent task
  `09-25-compatibility-expansion-quality`.
- Broad feature acceptance children depend on this child’s owner map and
  characterization gates. The child may not become a repository-wide rewrite.
- Preserve stable diagnostics, JSON reports, frame bytes, CLI exits, native
  status/stream behavior, evidence result vocabulary, and fail-closed behavior.
- Candidate hotspots are `ElfParser.cs`, `PayloadFrame.cs`, `CliApplication.cs`,
  `host_adapter.c`, native self-test mutation helpers, and repeated evidence
  script logic. File size alone does not require extraction.

## Requirements

- Map managed, native, fixture, script, CI, report, and release data flow.
- Inventory contract literals, address arithmetic, feature IDs, diagnostics,
  result vocabulary, and evidence path/hash ownership.
- Add characterization tests or probes for every contract selected for change.
- Define a small number of cohesive owner boundaries and migrate one boundary
  at a time. Do not leave two active implementations of one contract.
- Record preserved behavior, migration order, performance baseline, and
  rollback for each extraction.
- Update durable backend specs when the architecture owner changes.

## Acceptance Criteria

- [ ] Architecture/data-flow audit names legacy hotspots, coupling, duplicate
      owners, missing tests, and the recommended refactor order.
- [ ] Characterization coverage protects diagnostics, reports, frame layout,
      output identity, native dispatch/release, and evidence classifications
      touched by the first refactors.
- [ ] At least the first high-impact hotspot is refactored behind a clear owner
      boundary with no compatibility-claim change and no duplicate active path.
- [ ] Managed, native, contract, metadata, and relevant fuzz/stress gates pass
      or have a recorded environment limitation.
- [ ] Parent and child implementation plans identify remaining hotspots and
      containment rules instead of silently deferring quality work.
