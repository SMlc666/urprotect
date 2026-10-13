# Technical design: demand-driven indirect control flow and jump tables

## Boundary and corrected architecture

This child owns indirect-target semantics for explicitly selected function passes. It does not turn the ELF wrapper or generic validator into a whole-image disassembler.

The ownership boundary is:

```text
ElfParser / ElfValidator / LoadMap
  -> bounded ElfStructuralIndex facts

selected function pass
  -> local decode, CFG, register/data-flow, and indirect-expression discovery

IndirectTargetResolver
  -> demand-driven table/relocation/symbol/target queries
  -> exact/bounded/runtime/deferred target contract

ProtectionRewritePlan + AddressMap
  -> selected-function dependency closure and target bindings

ElfLayoutPlan / NativeImageMaterializer
  -> whole-file physical placement and byte edits; no semantic rediscovery
```

Whole-ELF structural parsing is allowed and required. Whole-ELF instruction scanning is not a prerequisite. `NoOpPipeline`, `urprotect validate`, `ElfPackService`, layout, and rehydration must remain structurally valid without decoding unrelated executable bytes. The architecture audit in `research/analysis-boundary-audit.md` is a prerequisite before this child is implemented.

## Inputs and outputs

### Inputs

- An explicit selected-function semantic plan from `Aarch64FunctionAnalyzer`/`Aarch64SemanticPlanFactory`.
- `ElfFile` structural facts: load map, symbols, relocations, dynamic metadata, section metadata when present, and bounded source bytes.
- Typed `AddressMap` entries for selected functions, blocks, instructions, tables, veneers, and relocation sites.
- Optional typed target-translation or stable-veneer requests from sibling/workflow contracts.

### Outputs

- `IndirectTargetResolution` records with `Exact`, `BoundedSet`, `RuntimeResolved`, `Deferred`, or `Unresolved` state.
- `JumpTablePlan` records containing table encoding, bounds, ownership, target identities, source references, and rewrite policy.
- Semantic extension records attached to the shared `SemanticRewritePlan`; no parallel raw-byte model.
- Typed table-entry/reference fixups consumed by `ElfLayoutPlan` and the semantic encoder.
- Bounded target-selection and address-map evidence for the workflow/runtime lanes.

## Structural facts versus code semantics

Reuse existing parser/model owners. Do not duplicate ELF arithmetic or parse the same untyped bytes in each resolver.

`ElfStructuralIndex` is a bounded projection over `ElfFile`, not a second parser. It provides on-demand queries for:

- file/virtual ranges and executable/load ownership;
- relocation records at an address or range;
- symbol identity/binding/visibility and function ranges;
- writable/read-only data ownership;
- dynamic/GOT/PLT metadata;
- section ranges when present, without requiring sections;
- bounded raw reads for a requested table range.

It does not decode every executable segment. The resolver requests only ranges named by a selected-function expression or a structural candidate.

## Indirect expression normalization

The selected-function pass discovers producer chains ending in `BR Xn`, `BLR Xn`, or an equivalent indirect control-flow operation. The resolver normalizes supported chains into a symbolic expression such as:

```text
target = base + sign_extend(load(table + index * entryWidth)) * scale + addend
```

or:

```text
target = page_base(place) + signed(entry[index]) + addend
```

The normalized record retains:

- source instruction and producer-chain identities;
- base expression and address domain;
- index expression and proven range;
- entry width and signedness;
- scale/addend/page-relative behavior;
- table range and file/virtual mapping;
- default/fallthrough target;
- target ownership and relocation/symbol evidence.

A relative-address family is not rejected because it is indirect. It is resolved whenever its expression and proof inputs are complete. A missing proof is a named deferred/unresolved condition, never a guessed target.

## Target-resolution lattice

Resolution is monotonic and evidence-bearing:

1. **Exact**: one target identity/address is proven.
2. **BoundedSet**: a finite target set and index/default bounds are proven.
3. **RuntimeResolved**: the target remains runtime-owned but a versioned binding and target-translation contract exist.
4. **Deferred**: the representation is understood but a layout or runtime resolver must supply a missing decision.
5. **Unresolved**: the required expression, bound, ownership, or target mapping is not proven.

`BoundedSet` is never collapsed to one target because one candidate currently maps. All candidates remain in the semantic snapshot and evidence.

## Jump-table model

A `JumpTablePlan` must include:

- stable table identity;
- source file/virtual range and output range when moved;
- base expression and source instruction;
- entry width: 1, 2, 4, or 8 bytes;
- signedness, scale, addend, and relative/absolute encoding;
- index lower/upper bounds;
- default target and fallthrough behavior;
- ordered target identities/addresses and resolution state;
- ownership evidence: selected-function private, shared, external, relocation-owned, or runtime-owned;
- rewrite policy: in-place, copied-and-retargeted, preserved-at-original-address, stable veneer, or runtime translation.

The table range is accepted for sectionless/stripped input when structural/data-flow evidence proves a bounded file-backed range, entry decoding, ownership, and valid target mapping. Section/relocation metadata strengthens ownership but is not mandatory.

## Ownership and preservation policy

The resolver is demand-driven from selected roots. It does not scan every function to find all table users.

- **Private selected table**: relocate or rewrite entries through `AddressMap`.
- **Shared table**: preserve the original table or clone it and rewrite only the selected function's table reference. Never mutate a table used by an unselected function without a complete ownership proof.
- **External/runtime-owned table**: preserve the table and external binding; attach explicit runtime ownership evidence.
- **Target outside selected closure**: preserve its original address/PLT identity unless a typed closure entry explicitly includes it.
- **Target proven movable but out of direct range**: request a typed stable veneer or long-form semantic fixup.
- **Target not proven movable**: keep the target/table at its original address where possible. If preservation cannot maintain semantics, return a deterministic pre-publication diagnostic.

This policy maximizes compatibility without pretending that an opaque runtime pointer follows relocated code automatically.

## Stable veneers and runtime translation

Stable-address veneers are preferred when the old target address can be retained and the semantic encoder supplies a valid veneer sequence. The layout child places the veneer; this child owns the target identity and required register/flag/ABI effects.

Runtime target translation is a separate extension. It requires:

- a versioned runtime binding name;
- old-to-new map ownership;
- register, NZCV, stack, call/return, BTI/PAC, and exception/unwind preservation rules;
- explicit external-target behavior;
- independent native glibc, musl, and bionic evidence before promotion.

A missing static proof never implicitly enables runtime translation.

## Integration with selected-function protection

`FunctionProtectionService` remains the request root. For each selected function:

1. analyze only the selected function and its local CFG;
2. project indirect expressions and table references into the shared semantic plan;
3. call the resolver only for discovered dependencies;
4. add target/table extensions and typed fixups to the same semantic snapshot;
5. derive the smallest validated protection closure;
6. pass the resolved contract to the layout planner/materializer.

`protect-image` serializes the semantic target/table state through the future versioned operation contract. `rehydrate-image` consumes it and never re-infers target semantics from source bytes.

## Compatibility and failure behavior

- Structural wrapper validation is decoder-independent by default.
- Unknown instructions outside selected analysis scope do not affect structural validation or selected-function publication.
- Malformed tables, ambiguous ownership, out-of-range entries, inconsistent relocations, and missing target proofs produce stable diagnostics with no partial publication unless a preservation strategy is explicitly valid.
- Evidence distinguishes transformed, preserved, deferred, runtime-resolved, and unresolved targets.
- A selected function is not claimed fully transformed unless every reachable indirect target required by the pass has a validated destination or declared preservation/translation contract.

## Verification plan

Positive fixtures cover:

- canonical relative switch tables;
- signed relative 8/16/32/64-bit entries;
- absolute tables;
- ADRP/LDRSW/ADD/BR and related compiler patterns;
- bounded function-pointer tables;
- indirect calls to selected and unselected targets;
- shared-table copy-and-retarget;
- stable-address veneer targets.

Negative/nearest-boundary fixtures cover:

- missing bounds;
- malformed width/signedness/scale;
- table out of range or overlapping ELF metadata;
- ambiguous ownership;
- externally owned table;
- target outside executable mappings;
- target set exceeding configured limits;
- unresolved runtime target without a declared binding;
- unrelated unknown instructions proving structural wrapper validation remains independent.

Each promoted row retains baseline/protected target-selection behavior and separate glibc, musl, and bionic evidence. The three-runtime workflow remains a parent/runtime-child responsibility; this child supplies target-resolution and table-rewrite evidence.
