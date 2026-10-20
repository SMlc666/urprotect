# Indirect-Control / Jump-Table Gap Audit

Audit scope: current checkout, child task `10-06-indirect-control-jump-tables`, and the shared parent task. This report is research only; no production code or task status was changed.

## Executive Summary

Phase 0 is substantially present. Generic validation and packing are structural by default; whole-image observation is explicit; protection starts from explicit selectors; the current `protect`/`protect-image`/`rehydrate-image` path has one workflow owner; and the bounded semantic snapshot, shared layout planner, materializer, and AsmStone encoder boundary are real contracts.

The child acceptance gap remains real: no selected-function data-flow/table resolver exists, indirect CFG edges still fail analysis except TLSDESC, the protection emitter rejects generic calls/indirect branches, the only jump-table record is a serialization placeholder, and the snapshot is consumed by rehydration only for TLS/CFI. There are no indirect/jump-table positive fixtures, runtime rows, target-selection report fields, or evidence checks.

Recommended first positive family: one canonical, private, compiler-shaped 32-bit signed-relative jump table in one selected function, with a proven finite index bound and every target inside that selected function's relocation closure. Keep the first row narrow: `LDRSW`/signed 32-bit entries, scale 1, one proven table base, no shared/external/runtime-owned table, no veneer, and no 8/16/64-bit or absolute encodings. This is the smallest end-to-end row that exercises the required bounded target set, target ownership, address map, table entry rewrite, and behavior oracle. An exact indirect call with a statically proven stable target is a smaller semantic sub-slice, but the current emitter and PC-relative producer handling do not yet provide a useful fixture path; promote it after the table resolver's proof/closure contract exists.

## What Phase 0 Already Implements

- **Structural-vs-code boundary.** `ValidationWorkflow.ValidateStructurally` performs decoder-independent structural validation and `ValidateObservationOnly` is the explicit whole-image observation path (`src/UrProtect.Core/Application/Validation/ValidationWorkflow.cs:12-57`). The corresponding regressions cover backend failure independence and unrelated unknown executable bytes (`tests/UrProtect.Core.Tests/Application/ValidationWorkflowTests.cs:25-61`). Packing explicitly calls the structural path (`src/UrProtect.Core/Application/Pack/ElfPackService.cs:68-72`).
- **Selected-function root.** `SelectedFunctionProtectionPlanner` resolves the requested selectors, validates selected ranges, and invokes `Aarch64FunctionAnalyzer` only for those functions (`src/UrProtect.Core/Application/Protection/SelectedFunctionProtectionPlanner.cs:18-83`). The test decoder records only addresses inside the selected symbol (`tests/UrProtect.Core.Tests/Application/FunctionProtectionTests.cs:70-96`). This is the correct place to add demand-driven indirect queries; do not add a whole-image scanner.
- **One current workflow and no direct writer route.** `ProtectionWorkflow` owns planning, Protected Image emission, materialization, and final output (`src/UrProtect.Core/Application/Protection/ProtectionWorkflow.cs:84-127,178-184,265-282`). The direct `FunctionProtectionService.Protect` route is asserted absent (`tests/UrProtect.Core.Tests/Application/ProtectionWorkflowTests.cs:18-27`). `FunctionProtectionLayoutAdapter.cs` is intentionally empty of a second writer (`src/UrProtect.Core/Application/Protection/FunctionProtectionLayoutAdapter.cs:1-5`).
- **General bounded layout.** The planner exposes existing executable-load extension, available PHDR slot, and relocated PHDR table strategies (`src/UrProtect.Core/ElfLayout/ElfLayoutContracts.cs:9-15`; `src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs:68-75`). It accepts bounded regions/branches/TLS/unwind edits (`src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs:23-65`), and the single materializer copies source bytes, applies typed edits, reparses, validates, and emits evidence (`src/UrProtect.Core/ElfLayout/ElfLayoutMaterializer.cs:63-112`). The occupied-table positive test proves the no-`PT_NULL` path (`tests/UrProtect.Core.Tests/Layout/ElfLayoutTests.cs:104-129`).
- **AsmStone boundary.** The project-owned encoder supplies semantic family/address/access inputs, delegates legality/operand encoding to AsmStone, and round-trip decodes generated words (`src/UrProtect.Core/Aarch64Semantics/Aarch64InstructionEncoder.cs:106-114`). The source checker excludes only that adapter and passes on the rest of production (`scripts/check-aarch64-encoding-boundary.py:11-16,69-102`). The adapter already exposes memory/index/register semantics and distinguishes `BL` from `BLR` (`src/UrProtect.Core/Aarch64Semantics/Aarch64Decoder.cs:330-347,354-383,466-493`; `tests/UrProtect.Core.Tests/Semantics/AsmStoneAdapterTests.cs:39-60`).
- **Shared semantic plan/snapshot.** The plan has one `AddressMap`, typed instructions/fixups, and extension collection (`src/UrProtect.Core/SemanticPlanning/SemanticRewriteModels.cs:177-190,275-303`). The snapshot has bounded collection/byte limits (`src/UrProtect.Core/SemanticPlanning/SemanticPlanSnapshotContracts.cs:23-46`), canonical ordering/digest, and deferred/unresolved fixup states (`src/UrProtect.Core/SemanticPlanning/SemanticPlanSnapshotCanonicalization.cs:460-468`). Existing tests prove extension round-trip and bounded canonicalization, including synthetic indirect/jump-table records (`tests/UrProtect.Core.Tests/Semantics/SemanticPlanSnapshotTests.cs:221-293,341-398`). These tests are schema tests, not positive transformation evidence.

## Current Gaps and Exact Extension Points

### 1. Selected analysis still rejects indirect control flow

`Aarch64FunctionAnalyzer` performs bounded decoding of the selected symbol (`src/UrProtect.Core/Aarch64Semantics/FunctionAnalysis.cs:142-203`) but does not track producer chains, register values, index ranges, or table ownership. It creates an `Indirect` successor with no target and then returns `IncompleteControlFlow` for every indirect terminator except the narrow TLSDESC marker (`src/UrProtect.Core/Aarch64Semantics/FunctionAnalysis.cs:275-291,434-468`). Direct calls only get a fallthrough CFG edge (`:235-239`); no indirect-call target contract exists.

**Extension:** add a selected-function data-flow/resolution pass after bounded decode and before the block reachability check in `FunctionAnalysis.cs`. It should query only ranges named by the selected instruction producer chain. Keep unresolved/ambiguous state in a typed analysis result; never turn an unknown `BR`/`BLR` into a guessed edge.

### 2. Projection already exposes the resolver handoff, but only as unresolved metadata

The projector maps an indirect instruction to an unresolved control-flow target with a stable diagnostic (`src/UrProtect.Core/SemanticPlanning/Aarch64SemanticInstructionProjector.cs:553-578`). The factory turns unresolved/bounded/runtime control-flow references into `SemanticIndirectTargetExtension` records (`src/UrProtect.Core/SemanticPlanning/Aarch64SemanticPlanFactory.cs:746-800,1090-1116`). This is the correct semantic handoff, but there is no resolver implementation that replaces the target with an exact/bounded proof or adds a table record.

**Extension:** consume the selected analysis's proof record in `Aarch64SemanticPlanFactory` via `Aarch64SemanticPlanFactoryOptions.Extensions`, or add a sibling resolver call at that boundary. Do not create a second raw-byte model. The extension must preserve producer-chain identities, normalized affine expression, bounds, ownership, and target bindings.

### 3. Target lattice and jump-table extension are incomplete for the child contract

The current target enum has `Exact`, `BoundedSet`, `RuntimeResolved`, and `Unresolved` only (`src/UrProtect.Core/SemanticPlanning/SemanticValueModels.cs:7-13`); `Deferred` exists only as `SemanticFixupResolutionState` (`src/UrProtect.Core/SemanticPlanning/SemanticPlanSnapshotContracts.cs:16-21`). The child design names `Deferred` as a target state, so implementation must either keep deferral exclusively at fixup/snapshot state or make the distinction explicit; do not silently conflate it with `RuntimeResolved`.

`SemanticJumpTableExtension` currently carries only table identity, source range, positive entry size, target list, and an optional encoding string (`src/UrProtect.Core/SemanticPlanning/SemanticPlanExtensions.cs:30-64`). Its canonical encoding/decoding/validation only covers those fields and a target-count bound (`src/UrProtect.Core/SemanticPlanning/SemanticPlanSnapshotEncoding.cs:362-377`, `SemanticPlanSnapshotDecoding.cs:1009-1044`, `SemanticPlanSnapshotValidation.cs:608-623`). It lacks:

- base expression and source indirect instruction;
- entry width restriction to 1/2/4/8, signedness, scale, and addend;
- proven index lower/upper bounds and entry count;
- default/fallthrough target;
- source/output table ranges and an explicit table `AddressMap` entry;
- ownership (`private`, `shared`, `external`, `runtime`);
- rewrite policy (`in-place`, copied/retargeted, preserved, veneer, or declared runtime binding);
- per-entry source/value/target bindings and resolution state.

**Extension:** enrich the one `SemanticJumpTableExtension` and the one canonical codec. The existing `MaximumTargetsPerJumpTable` is a serialization bound, not proof of bounded table bytes or safe file-backed reads. Structural reads must use existing `ElfFile`/`LoadMap`/relocation/symbol facts and a new bounded projection/query seam; no whole-image disassembly or second ELF parser.

### 4. Ordinary protection planning never builds a semantic snapshot

`FunctionProtectionService.Plan` calls `BuildTlsSemanticSnapshot` after code emission (`src/UrProtect.Core/Application/Protection/FunctionProtectionPlanning.cs:41-66`). That builder skips analyses with no TLS facts and returns null when there are no TLS bindings (`src/UrProtect.Core/Application/Protection/FunctionProtectionPlanning.cs:132-140,514-547`). Therefore an ordinary selected function with an indirect branch/call has no canonical semantic plan to carry its target/table proof.

**Extension:** generalize this method to build one semantic plan for every selected transformed function. TLS, indirect targets, jump tables, relocation bindings, and CFI extensions must be collected into the same `SemanticRewritePlan` and `SemanticPlanSnapshot`; do not append a second snapshot or add a parallel Protected Image operation.

### 5. The current emitter rejects the feature before layout

The emitter rejects every direct call except the exact dynamic-TLS resolver and every indirect branch except TLSDESC (`src/UrProtect.Core/Application/Protection/FunctionProtectionCodeEmitter.cs:328-363`). During flattened emission, non-terminal control flow is rejected (`:547-583`), a terminal indirect branch is special-cased only for TLSDESC (`:586-611`), and a generic terminal indirect branch falls through to the “no in-function successor” failure (`:613-679`). If register permutation is disabled, source words are copied unchanged (`:706-716`), so no semantic target/table fixup can be applied there.

**Extension:** teach the selected-function builder/emitter to consume the resolved closure. For the first table row, the terminal `BR` must either retain a validated output table/target mapping or lower to a dispatcher-state sequence whose generated words are requested through `IAarch64InstructionEncoder`. Any relocated `ADRP`/`ADD`/literal producer must be rewritten through the semantic plan; raw source-word copying is not sufficient.

### 6. Layout has no table request/evidence contract

`ElfLayoutPlanner.Plan` accepts regions, branch requests, TLS fixups, and unwind edits, but no table/reference requests (`src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs:23-30,39-62`). `ElfLayoutEditKind` has no table/data-relocation category (`src/UrProtect.Core/ElfLayout/ElfLayoutContracts.cs:37-47`), and `ElfLayoutPlan`/`ElfLayoutEvidence` expose only generic address-map/branch decisions plus TLS/unwind lists (`src/UrProtect.Core/ElfLayout/ElfLayoutContracts.cs:342-378`). The materializer applies generic edits and validates ELF/TLS, but does not resolve semantic jump-table entries (`src/UrProtect.Core/ElfLayout/ElfLayoutMaterializer.cs:63-112`).

**Extension:** add a typed table-entry/reference request and decision to the existing layout plan, or convert a validated semantic table plan into bounded `ElfLayoutByteEdit` records before calling the planner. The latter is viable for an in-place first row if the semantic layer supplies exact output bytes and source range; the plan/evidence must still record table identity, source/output ranges, ownership, rewrite policy, and every entry binding. Keep one `ElfLayoutMaterializer`; do not add a table-specific writer.

### 7. Protected Image and rehydration do not consume indirect extensions

Protected Image v1 currently has only `EmitRegion`, `ApplyEntryBranch26`, and `SemanticPlanSnapshot` operations (`src/UrProtect.Core/Application/Protection/ProtectedImageV1.cs:42-52`). The snapshot operation is bounded and validated, but its publication validation only applies TLS consistency (`:800-838,841-925`). Rehydration conditionally decodes the snapshot as a TLS-presence carrier (`src/UrProtect.Core/Application/Rehydration/GenericRehydrationEngine.cs:341-375`) and converts only TLS fixups and CFI effects into layout inputs (`:630-654,710-737`); indirect/jump-table extensions are ignored.

**Extension:** keep the single snapshot operation, add a common semantic-extension validation/materialization projection, and feed table edits/target bindings into the same `ElfLayoutPlanner.Plan` call. `rehydrate-image` must consume the recorded contract and never rediscover target semantics from source bytes.

### 8. Reports, fixtures, and runtime evidence have no indirect row

The protection report exposes passes, selected/transformed functions, resource plan, output hash, and diagnostics, but no target-resolution mode, table identity, ownership, target candidates, address-map bindings, or rewrite policy (`src/UrProtect.Cli/Rendering/ProductReport.cs:108-149,237-295`). The evidence checker verifies only current recipes, selected transformation/pass order, execution status, readelf output, and hashes (`scripts/check-protection-evidence.py:23-87`). The native E2E script exercises only register permutation and control-flow flattening fixtures (`scripts/run-protection-e2e.sh:139-198`), and the checked-in assembly fixture contains no indirect control flow (`fixtures/samples/protection/target.S:1-23`). No indirect/jump-table feature row appears in the current fixture manifest/regression matrix or contract inventory.

**Extension:** add one positive and nearest-negative fixture family, target-selection evidence to the product report and normalized runtime artifact, and separate glibc/musl/bionic rows. Do not infer runtime support from the managed snapshot round-trip.

## Smallest Positive Slice

Use one compiler-shaped relative jump table with this bounded contract:

- selected function is the only analysis root;
- prior compare/branch proves `0 <= index <= N` and identifies one default/fallthrough target;
- one file-backed private table range is found on demand from the producer chain;
- entries are exactly signed 32-bit offsets, `target = tableBase + signExtend(entry)`, scale 1, addend 0;
- every decoded target is four-byte aligned, inside an executable load, and inside the selected function's validated closure;
- table and all target blocks get typed source/output `AddressMap` entries;
- first placement keeps the table in place and emits bounded entry byte edits, or copies it only if the layout plan records the copy and retargeted base; no shared/external/runtime-owned table in this row;
- no veneer, runtime translation, absolute table, alternate entry widths, or unbounded index in the first positive row;
- transform/protect-image/rehydrate-image all carry and consume the same canonical snapshot and produce baseline/protected target-selection evidence.

An exact indirect call can be added as a smaller follow-on row when its producer chain yields one target identity and the target remains stable or is explicitly in the selected closure. The current code has no producer-chain proof and rejects the call in the emitter, so calling a runtime pointer or treating an opaque `BLR` as a static target is outside the first row.

## Required Negative Cases

Each negative must assert a stable first diagnostic, no Protected Image/native output, and no partial evidence:

1. Missing index bound or incomplete producer chain (`BR`/`BLR` target remains opaque).
2. Table range not file-backed, truncated, overflowing, overlapping metadata, or outside a load map.
3. Unsupported entry width, signedness, scale, addend, or malformed relative arithmetic; include multiplication/addition overflow.
4. Entry resolves outside executable mappings, is unaligned, or is outside the selected closure without a preservation/veneer contract.
5. Empty/duplicate target candidates, target set over configured bounds, or inconsistent target count versus table byte range.
6. Shared table with an unselected consumer, ambiguous ownership, external/runtime-owned table, or a table whose relocation/symbol facts disagree with the decoded representation.
7. Default target/fallthrough absent or not in the validated CFG; indirect call target not proven stable.
8. Required target is movable but no `AddressMap` binding exists, or output branch/table displacement cannot be encoded by the declared semantic/layout contract.
9. Snapshot tampering, duplicate table identity, invalid canonical extension fields, and a second semantic snapshot operation.
10. Regression boundary: unrelated unknown executable bytes and decoder backend failure still pass structural validation, while unknown bytes inside the explicitly selected function fail selected analysis.

## Commands and Tests Needed

Already run in this audit:

- `python3 scripts/check-architecture-boundaries.py` -> passed.
- `python3 scripts/check-aarch64-encoding-boundary.py` -> passed.
- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore --filter 'FullyQualifiedName~Semantics|FullyQualifiedName~Layout|FullyQualifiedName~FunctionProtection|FullyQualifiedName~ValidationWorkflow'` -> passed, 161 tests.
- `python3 -m unittest discover -s tests -p 'test_*.py'` -> failed in three unrelated Bionic staged-merge cases (`test_bionic_node_runner.py`, directory-over-symlink and two replacement cases); retain as repository residual risk, not evidence for this child.

Add before promotion:

- Managed unit tests for the selected-function producer/value-range resolver: canonical relative table, exact/bounded targets, default edge, signed entries, overflow, missing bound, and selected-only decode scope.
- Semantic-plan tests proving one snapshot contains the indirect extension, complete table metadata, table/target `AddressMap` entries, per-entry rewrite bindings, canonical ordering, digest, and unresolved/deferred classification.
- AsmStone boundary tests for every generated `ADRP`/`ADD`/`LDRSW`/`BR` or lowered dispatcher instruction; decode every returned word through `AsmStoneAdapter`. Add a source-boundary self-test fixture for any attempted manual instruction-word writer.
- Layout/materializer tests for in-place table-entry rewrites, copied/retargeted table if implemented, every-`PT_NULL`-occupied source, output reparse, source/output map evidence, edit overlap, and no bytes on failure.
- Protected Image and rehydration integration tests proving exactly one snapshot operation, target/table extension validation, same target bindings after decode, one layout planner/materializer, and no source-byte semantic rediscovery.
- Native fixture/evidence tests comparing baseline/protected stdout, status, selected case IDs, target-selection set/order, table ownership/mode, hashes, and readelf output for glibc, musl, and bionic separately.
- Required local validation remains: `dotnet build UrProtect.sln --configuration Release --no-restore`, the focused managed test command above, `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`, `python3 tests/test_regression_matrix.py`, `./scripts/run-protection-e2e.sh --tier pr --runtime glibc`, and `./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc`; add the corresponding indirect rows before enabling musl/bionic promotion.

## Boundary Rules for Implementation

- Use existing program-header/load-map/symbol/relocation facts and bounded raw reads; do not add whole-image disassembly or a second ELF parser.
- Resolve only from selected-function roots and explicitly requested table/target ranges.
- Build one semantic plan and one canonical snapshot; do not add a parallel raw-byte table model or migration/fallback path.
- Let `Aarch64InstructionEncoder`/AsmStone own every generated or relocated instruction word. Table entries are data edits, but their arithmetic and ownership must be typed and validated before the one layout writer consumes them.
- Let `ElfLayoutPlanner` choose placement and `ElfLayoutMaterializer` apply edits/reparse/validate. The semantic resolver must not write ELF bytes directly.
- Preserve explicit unresolved/deferred/runtime states in the plan and evidence; publication requires a validated destination or an explicit preservation/translation contract.

## Current scoped implementation and evidence addendum (2026-10-20)

This addendum supersedes the earlier pre-implementation inventory where it
said that the provider runner, checker, transformed observation, rollback
oracle, or required CI wiring did not yet exist. The original audit remains
historical context. One provider family is now implemented and independently
checked on native AArch64/glibc; the row remains `unknown` and
`scoped-observation-not-promoted` until hosted CI and the still-open task
criteria are satisfied.

### Target-resolution modes versus fixup states

`SemanticTargetResolution` has four target modes: `Exact`, `BoundedSet`,
`RuntimeResolved`, and `Unresolved`. `Deferred` is not another target mode: it
is a `SemanticFixupResolutionState` used when an exact static output binding is
not yet available. Current projection maps Exact to Resolved, BoundedSet and
RuntimeResolved to Deferred, and Unresolved to Unresolved. Do not infer
runtime ownership from a Deferred fixup, or treat a runtime target as a local
bounded candidate.

| Mode | Current meaning in the bounded indirect-control work | Address-map consequence |
|---|---|---|
| `Exact` | A uniquely proven source target/instruction identity, including fixed local targets where the owner is rederived from source. | A movable local instruction/target must have a checked source→output `AddressMap` binding. Preserve-original-VA owners require identity mapping and byte/symbol validation. |
| `BoundedSet` | A finite, bounded candidate set, used for local bounded control-flow/table resolution; a candidate list alone is not output-placement proof. | Each moved local target needs its own checked output mapping. In the shared signed-relative table row, schema-3 target bindings separately connect table/entry/target identities, source target/base VAs, mapped output target/base VAs, source entry bytes, edits and Native Image bytes. |
| `RuntimeResolved` | A target resolved by a runtime owner rather than a statically known consumer VA. The external provider `BR` carrier is linked to `external-provider-table:{ProviderSha256}:{TableIdentity}`; dynamic imports and TLS have their own owner bindings. | Provider table/target addresses stay in the provider identity domain: no fabricated consumer `AddressMap` rows, no provider-table clone, and no VA translation in managed publication. At runtime the checker derives provider mappings/load bias and binds each entry displacement to the provider target symbol and measured mapping. Consumer GOT/page mappings remain identity-preserved and are validated separately. |
| `Unresolved` | Missing, ambiguous or unsupported proof; this includes unsafe bounds/default, missing owner evidence, malformed range, or unproven selected indirect edges. | No output mapping can make the unresolved proof publishable. Fail closed before the applicable artifact/loader boundary and retain the first diagnostic/stage. |

This summary distinguishes the semantic address map from runtime loader
mappings. The former relates source-image local addresses to emitted output;
the latter proves where a separately identified provider DSO/table/target was
actually mapped. A provider target address is not a source-image address merely
because the target is executable at runtime.

### Completed scoped provider evidence and still-open promotion gates

- The transformed source→`protect-image`→`rehydrate-image`→Native Image run is
  retained at
  `.artifacts/indirect-control/provider-rollback-native-image-implementation-20261020-4/runtime.indirect-control.external-provider.glibc.host-context-entry`.
  It exercises selected `urp_entry` and control `urp_observer` for indices
  0–3 and the safe default, binds provider SONAME/build ID/SHA-256, consumer
  GLOB_DAT/GOT, table bytes, all four target symbol rows, statuses/streams,
  Native Image output and release, and remains explicitly
  `scoped-observation-not-promoted`.
- The dedicated post-acquisition rollback root is
  `.artifacts/indirect-control/provider-loaded-rollback-ci-validation-20261020T153308Z-18193`.
  Its source-loader oracle rejects after provider/consumer binding, checks
  cleanup of mappings/descriptors/references, then verifies successful reload,
  entry/observer dispatch and release. This source-loader root is distinct from
  both the wrong-pin prepublication negative and transformed Native Image
  rollback record.
- The independent integration review reported a scoped pass for the current
  transformed and source-loader roots, checker suites, CI workflow shape, and
  unknown/non-promoted registry status. Local managed/native/Python and matrix
  validations are recorded in the child `implement.md`. The official hosted
  workflow has not run on the uncommitted YAML; hosted artifact upload and
  branch-protection mapping remain to be confirmed.
- `fixtures/manifest.json` remains `unknown`; evaluator digest registration is
  current. `tests/regression-matrix.json` requires the transformed provider and
  separate source-loader rollback rows on native AArch64. No musl/Bionic,
  arbitrary provider/dependency, other table family, or general indirect-call
  result is inferred.
- The task now records its scoped external-table evidence criterion as complete,
  but the general ownership-policy criterion, three-runtime evidence, and final
  general target-resolution/address-map report remain unchecked. The historical
  Bionic staged-merge failures listed in the earlier audit remain unexplained;
  a later green full Python suite does not explain those failures.
