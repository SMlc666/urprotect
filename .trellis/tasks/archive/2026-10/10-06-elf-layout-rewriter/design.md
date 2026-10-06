# Technical design: generic ELF layout rewriter

## Boundary

This child owns physical AArch64 ELF placement and materialization after the semantic rewrite plan has selected transformed regions and fixups. It replaces the current `PT_NULL`-only append logic with one bounded planner and one materializer.

It does not own instruction decoding, relocation-expression semantics, indirect-target resolution, TLS model resolution, CFI generation, CLI option parsing, or native runtime claims. Those inputs arrive through the project-owned semantic/protection plan and typed extension records. Atomic publication continues to use the existing publisher boundary; this child returns bytes and deterministic layout evidence and never publishes a partial file.

## Data flow

```text
ElfFile + source bytes
  + ProtectionPlan / SemanticRewritePlan
  + typed veneer and metadata requests
    -> ElfLayoutPlanner
       - validate source ranges and load-map ownership
       - enumerate legal placement candidates
       - choose one deterministic strategy
       - assign output file/virtual ranges
       - assign direct/veneer/long-branch decisions
       - emit typed byte/header edits
    -> ElfLayoutPlan + ElfLayoutEvidence
    -> ElfLayoutMaterializer
       - clone source bytes
       - apply checked non-overlapping edits
       - reparse with ElfParser and validate with ElfValidator
       - return Native Image bytes only after post-encode checks
    -> existing atomic publisher / workflow evidence
```

The planner is immutable after construction. It never mutates `ElfFile`, the semantic plan, or source bytes. The materializer consumes only a validated plan and fails before returning output when any edit, address, digest, or post-parse invariant does not match.

## Project-owned models

Add the layout contracts under `src/UrProtect.Core/Elf/`:

- `ElfLayoutStrategy`: `ExistingExecutableLoadExtension`, `AvailableProgramHeaderSlot`, and `RelocatedProgramHeaderTable`.
- `ElfLayoutOptions` and bounded layout limits, including maximum output bytes, program-header count, generated code bytes, veneer count, and alignment.
- `ElfLayoutRange`: typed file/virtual range pair with checked end calculations.
- `ElfProgramHeaderPlan`: source index, original header, planned output header, and edit classification.
- `ElfLayoutPlacement`: region identity, source identity, file offset, virtual address, size, permissions, and alignment.
- `ElfBranchPlacementDecision`: source/target identities, direct/near-veneer/long-address decision, range, and optional veneer identity.
- `ElfLayoutPlan`: source digest, selected strategy, old/new program-header table ranges, output length, planned headers/placements, branch decisions, preserved-metadata fingerprint, and sorted byte edits.
- `ElfLayoutEvidence`: bounded canonical projection for strategy, table placement, segment placement, address-map entries, branch decisions, and source/output digests.
- `ElfLayoutResult`: plan, materialized bytes, reparsed output, evidence, and diagnostics.

The models use `FileOffset`, `VirtualAddress`, and `RuntimeAddress` rather than unqualified address integers. Canonical ordering is by source program-header index, placement identity, and edit offset. No AsmStone or CLI report type leaks into these records.

## Candidate strategies

All strategies use the same candidate API and invariant validator. A `PT_NULL` entry is an available resource, not a separate writer.

1. **Existing executable PT_LOAD extension**: extend a compatible terminal RX `PT_LOAD` when the generated range can be appended without mapping unrelated existing bytes, violating load ordering, overlapping another load, or changing protected metadata. The existing header is edited in place; no program-header count change is required.
2. **Available PT_NULL slot**: append a new RX `PT_LOAD` at a bounded aligned file/virtual range and replace one in-bounds `PT_NULL` record. The ELF header and existing table remain in place.
3. **Relocated/expanded program-header table**: append a new RX `PT_LOAD` containing the relocated expanded table and generated code, update `e_phoff`/`e_phnum`, and update an existing `PT_PHDR` record when present. The old table bytes remain untouched unless the plan explicitly owns an overlap-free edit.

Candidates are scored deterministically by the tuple `(program-header-table relocation, program-header-count delta, metadata header edits, padding bytes, strategy rank)`. The planner selects the lowest valid score. This makes the same source/plan produce the same strategy while still allowing RX extension to win when it is genuinely the least invasive option. A caller may request a strategy only for a test fixture or evidence boundary; an unavailable requested strategy produces a diagnostic rather than silently falling back.

## Address and range invariants

- Every source and generated range is checked against `ElfFile`/`LoadMap` using checked arithmetic before allocation or conversion.
- New and extended `PT_LOAD` records satisfy `p_offset % p_align == p_vaddr % p_align`; `p_align` is zero/one or a bounded power of two. The planner derives the common segment alignment from the owning layout options and does not duplicate `LoadMap` conversion arithmetic.
- File ranges and virtual ranges do not overlap incompatible load mappings. Load ordering remains monotonic, and a new segment cannot intersect `PT_INTERP`, `PT_DYNAMIC`, `PT_TLS`, `PT_GNU_RELRO`, `PT_GNU_STACK`, `PT_GNU_PROPERTY`, `PT_NOTE`, or section data unless the plan explicitly records an owned metadata edit.
- The program-header table range is fully file-backed, its count and entry size remain representable, and an existing `PT_PHDR` remains mapped to the planned table. Extended numbering is rejected unless the parser/model explicitly supports it.
- Source section headers may be absent. When present, their offsets and sizes are preserved unless a future layout extension supplies a typed section-header edit; a table relocation never guesses section ownership.
- Output size, generated code, veneer count, table count, edit count, and aggregate padding are bounded before materialization.

## Branch and veneer placement

The layout plan consumes branch fixups from the semantic/protection plan. A direct AArch64 `B`/`BL`/entry Branch26 is selected only when the signed, instruction-aligned displacement is representable. When direct range fails, the planner asks the typed veneer request set for a near placement and records `NearVeneer`; it does not synthesize opaque bytes or guess a target. A long-address decision is recorded only when the semantic encoder supplies a typed long-form sequence. If no valid direct, veneer, or long-form placement exists, the planner returns a stable range diagnostic and no materialized bytes.

Veneers are placed in the same RX placement list and address map as generated code. Their file/virtual ranges are included in overlap, alignment, output-limit, and post-parse validation. The layout child owns placement; the semantic relocation child owns the encoding and target expression.

## Materialization and validation

`ElfLayoutMaterializer` applies sorted, non-overlapping typed edits to a source snapshot. It verifies the source digest, every edit range, program-header serialization, and output bound before writing. It then reparses the complete candidate through `ElfParser`, validates the model and `LoadMap`, checks all planned output headers and ranges, and verifies the planned entry/veneer branch encodings through the semantic validator. Failure returns diagnostics and no output bytes.

The materializer does not write a destination path. `RehydrationPublisher`/the unified workflow retains the existing temporary-file, flush, read-back, and atomic-rename behavior. Layout evidence is returned to the workflow so the selected strategy, old/new table ranges, address map, branch decisions, and hashes can be retained without a second writer.

## Integration contracts

- `GenericRehydrationEngine` delegates physical placement to this planner/materializer instead of searching for a `PT_NULL` slot or embedding a raw append writer.
- `ProtectionPlan` remains a compatible adapter while the semantic-plan consumer is integrated; no parallel raw-byte model is introduced.
- The semantic relocation child supplies typed regions, fixups, target identities, and veneer requests. The indirect-control-flow, TLS, and CFI children attach their extensions to the same plan.
- The workflow child owns the versioned Protected Image artifact evolution, CLI publication, and three-runtime evidence aggregation. Layout evidence is serializable and bounded, but this child does not add a second artifact ABI.
- External `readelf`/`llvm-readelf` checks remain script/fixture responsibilities. The Core validator proves bounded model invariants; the fixture matrix proves toolchain/runtime observations.

## Failure contract

Malformed headers, occupied or overlapping ranges, table/count overflow, invalid alignment, unsupported metadata movement, branch overflow without a typed relaxation, edit overlap, source digest mismatch, post-parse mismatch, or output-limit violations return stable diagnostics and no output bytes. Unknown program-header types and metadata are preserved or rejected according to the existing parser contract; they are never rewritten as a best effort.

## Verification shape

Focused tests cover:

- one planner API across PT_NULL, existing RX extension, and rebuilt-table fixtures;
- occupied program-header tables with no PT_NULL slot;
- 4 KiB and non-page-sized congruent load alignment;
- PT_PHDR and sectionless inputs;
- metadata overlap, malformed table, alignment, output-limit, and count overflow negatives;
- direct Branch26, near veneer, long-form handoff, and unreachable-target diagnostics;
- deterministic plan/evidence snapshots and byte-identical repeated materialization;
- parser reparse plus external readelf structure checks for promoted fixtures;
- atomic publication/no-partial-output behavior through the existing rehydration publisher.

The three-runtime baseline/protected status and stream-oracle rows are owned by the parent workflow/runtime children; this child publishes the layout strategy and invariant evidence they consume.
