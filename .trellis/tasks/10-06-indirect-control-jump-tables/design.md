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
  -> exact/bounded/runtime/unresolved target modes; separate deferred fixup state

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

- `IndirectTargetResolution` records use the target modes `Exact`, `BoundedSet`, `RuntimeResolved`, or `Unresolved`. `Deferred` is a separate fixup-resolution state, not a fifth `SemanticTargetResolution` value.
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

Resolution is monotonic and evidence-bearing across two related but distinct
dimensions:

1. **Exact**: one target identity/address is proven.
2. **BoundedSet**: a finite target set and index/default bounds are proven.
3. **RuntimeResolved**: the target remains runtime-owned and has an explicit
   runtime binding; this does not itself assert static target translation.
4. **Unresolved**: the required expression, bound, ownership, or target mapping
   is not proven.

`SemanticTargetResolution` implements exactly these four modes. `Deferred` is a
`SemanticFixupResolutionState` for a known representation that lacks a final
static output binding; current canonical projection maps `BoundedSet` and
`RuntimeResolved` targets to deferred fixups, while `Exact` is resolved and
`Unresolved` remains unresolved. Do not encode `Deferred` as a target mode or
infer runtime ownership from a deferred fixup. `BoundedSet` is never collapsed
to one target because one candidate currently maps. All candidates remain in
the semantic snapshot and evidence.

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

## Static local function-pointer calls (bounded first mode)

The first function-pointer positive is an exact static local call, not an
arbitrary indirect-call allowance. A selected caller may contain a compiler-
shaped BLR Xn whose bounded, same-basic-block reaching definition resolves
through an ADRP/ADD address producer and an exact stack spill/reload to one
defined, non-preemptible STT_FUNC in the same executable file-backed source
image. The linked SHT_RELA rows, their sh_link/sh_info, the symbol-table
identity, relocation pair/sites/addends, and decoded expression must agree.
Missing sections/relocations, a preemptible or ambiguous symbol, clobber,
conflicting control-flow path, or arbitrary runtime pointer remains unresolved.

For the initial mapping policy, transform only the selected urp_entry.
Preserve the callback target at its original source VA and bind that
identity/preserve-original decision explicitly in the canonical plan and
address map. Re-encode the moved caller's page-relative producer to that
preserved VA through Aarch64InstructionEncoder; do not leave stale source
PC-relative bits. An unselected urp_observer continues to call the same
preserved target. This first mode does not support a selected/moved callee,
runtime translation, veneer synthesis, or a general pointer table.

Represent the exact static target separately from RuntimeResolved imports.
Use a typed static-call ownership contract that binds the call/register,
ordered producer chain, section-linked relocation identities, exact symbol
row and source range, and target mapping policy. Rehydration independently
rederives those facts from source ELF and instruction bytes before publication.
Do not reuse the dynamic-import owner with fabricated GOT data or a free-form
runtime binding. The current nested snapshot is strict URP-SPS5/version 5 and
rejects versions 1-4 rather than dual-decoding; the original jump-table
ownership byte ordinals 0-3 remain stable, with `Ambiguous=4` appended. The
outer Protected Image ABI remains v1. Publication revalidates the final caller sequence and callback
symbol/range/bytes at the original VA.

The native oracle must execute source and transformed selected callers through
HostContext and compare the unselected observer as a control. Retain measured
process/entry statuses, byte streams, source/protected/native hashes, and exact
runtime identity. This is one compiler/toolchain-shaped native-glibc row only;
it does not promote other compilers, runtimes, moved callees, or arbitrary
function pointers.

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
- Evidence distinguishes target-resolution modes (`Exact`, `BoundedSet`, `RuntimeResolved`, `Unresolved`) from fixup states (`Resolved`, `Deferred`, `Unresolved`) and rewrite outcomes (transformed or preserved); none substitutes for another.
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

## External provider DSO: bounded first positive

The user-selected provider path is a bounded external-table contract, not a relaxation for arbitrary shared objects. The first positive is one self-contained AArch64 `ET_DYN` provider and one consumer. The provider has no `DT_NEEDED`, `DT_RPATH`, or `DT_RUNPATH`; it exports one exact defined `STT_OBJECT` (the 16-byte table) in a file-backed read-only `PT_LOAD` and a small set of defined executable `STT_FUNC` targets in the same DSO. Its table contains signed 32-bit displacements relative to the table address, so target offsets remain invariant under provider ASLR. The consumer has one undefined global/default `STT_OBJECT` with the same name, one exact non-PLT `R_AARCH64_GLOB_DAT` GOT owner, and a bounded `CMP`/safe-default, ADRP/GOT-LDR, indexed LDRSW, table-base ADD, and BR chain. The consumer's undefined object `st_size` may be zero (as emitted by GNU ld); the provider definition and verified runtime binding establish the 16-byte size and range. The GOT slot carries the table pointer; it is never treated as table storage.

### Trusted provider identity and loader boundary

- The host, not the source ELF or Protected Image, supplies the provider file and expected identity through an explicit runtime configuration. The configuration binds the bounded DSO bytes by SHA-256, GNU build ID, and exact `DT_SONAME`. No payload-controlled path or search root is accepted.
- The native adapter compares SHA-256 before ELF parsing, validates the provider ELF contract, then loads the provider from a sealed file descriptor into a fresh isolated glibc link-map namespace with local visibility. The consumer is loaded into that exact namespace, so its exact `DT_NEEDED` binds to the verified provider without base-namespace/global-symbol resolution. A single 8 MiB aggregate parser-work budget is charged before bounded program-header/load-range lookups, GNU-hash bucket/chain traversal, dynsym iteration, and string comparisons; the indexed `PT_LOAD` ranges avoid rescanning program headers per symbol. The adapter verifies the actual provider `link_map`, table mapping/bytes, and consumer GOT binding before publishing the image handle, and retains the provider through consumer release. Missing/extra/duplicate provider dependencies, identity mismatch, duplicate table definition, provider dependency/path tags, or a writable/non-file-backed table fail closed before consumer loading/publication. A pre-existing same-SONAME base-namespace mapping is rejected by policy; a different-SONAME global definition of the same symbol is harmless to binding and must not replace the isolated provider.
- A consumer may declare only this exact provider SONAME, and only when the trusted host configuration names that same identity. The existing libc singleton/pair dependency rules remain unchanged; no arbitrary dependency graph, `LD_LIBRARY_PATH`, `LD_PRELOAD`, `LD_AUDIT`, `RPATH`, or `RUNPATH` exception is introduced. The provider DSO itself is dependency-free.
- HostContext runtime identity and mapping evidence must be measured in the executing process: loaded DSO path/inode or sealed-file identity, provider bytes/hash/build ID, mapping base and read-only range, resolved table address/bytes, GOT value, and every target address/symbol. A matching SONAME alone is not proof.

### Managed ownership and rewriting

- `protect-image` and `rehydrate-image` accept an explicit host-only provider input for this family. The provider path and operator pin object are not serialized into semantic snapshots; provider-derived content identity and table facts remain semantic provider facts.
- Keep the nested semantic snapshot at URP-SPS6/version 6 and reject URP-SPS1 through SPS5; do not add historical decoders. Preserve the existing provider-facts-only `SemanticExternalJumpTableExtension` wire representation byte-for-byte so existing provider-only SPS6 records continue to decode. Store the selected consumer/GOT/branch proof in a separate typed `SemanticExternalJumpTableConsumerExtension` with a stable appended discriminator. The companion links to exactly one provider-facts extension by table identity and provider content SHA-256; aggregate validation checks the proof’s provider facts against that record and checks the carrier’s exact `SemanticEntityId.Instruction(branch)` identity, source address, and runtime binding. Provider-only facts remain valid without a consumer companion. Keep the outer Protected Image ABI v1 unless its independent contract truly changes.
- The consumer companion binds the consumer function, complete ordered producer chain, bounds/default edge, undefined dynsym identity, exact non-PLT GLOB_DAT relocation and writable GOT slot. The provider-facts extension binds provider SONAME/build ID/hash, defined object symbol/range/bytes, encoding/base, and each exact provider-local target symbol/range. Enforce count and aggregate-work bounds.
- Application coordinates through an Infrastructure bounded private-file snapshot reader; check the raw provider byte length before allocation and redact paths and raw exception text from read diagnostics. At production and rehydration publication, independently parse both ELF images and rederive the complete relation from their bytes. Compare provider object bytes and target identities, consumer instruction projection, relocation/symbol identity, GOT mapping, control-flow/bounds proof, and serialized owner set. Missing provider input, mismatched bytes, missing/duplicate owner, changed provider object/target, wrong GOT slot, wrong branch identity, or checksum-refreshed semantic tampering fails before publication.
- The table and target functions are external/runtime-owned and remain unchanged. Rewriting applies only to the selected consumer. Its moved GOT-page producer is re-encoded through the existing instruction encoder; no external table clone, local `AddressMap` mapping for provider addresses, veneer, or implicit target translation is allowed. An unselected observer continues to use the same provider table.

### Evidence and explicit non-goals

The bounded source-versus-transformed row now has local retained evidence at
`.artifacts/indirect-control/provider-rollback-native-image-implementation-20261020-4/runtime.indirect-control.external-provider.glibc.host-context-entry`.
It runs source and rehydrated Native Image selected consumer plus an unselected
observer through HostContext on native AArch64/glibc. The independent checker
verifies all four case values and provider target identities, safe-default
behavior, source/transformed process and entry statuses, exact streams, release
ordering, provider/consumer/native-image digests, and provider mapping/GOT/table
relations. The evidence report deliberately remains
`scoped-observation-not-promoted`. Separate source-loader rollback evidence at
`.artifacts/indirect-control/provider-loaded-rollback-ci-validation-20261020T153308Z-18193`
verifies post-provider-acquisition failure cleanup and successful reload; it is
not a substitute for the transformed behavior record. A wrong-provider-SHA
negative remains a pre-publication/no-loader case, and the transformed Native
Image rollback is a separate failure stage. The CI producers/checkers and
unknown fixture/regression row are wired locally, but an official hosted CI run
and branch-protection confirmation remain open.

Nearest negatives include absent provider configuration, missing `DT_NEEDED`
with both configured and unconfigured adapters, same-SONAME wrong-hash provider,
wrong provider symbol/type/size/permissions, altered table entry/target,
consumer dynsym/RELA/GOT mismatch, exact/over aggregate-work limits, provider
tampering between production and rehydration, checksum-refreshed output-range
truncation/overlap, provenance decompression bounds, and post-acquisition
rollback. Each negative must fail at its applicable publication or loader
boundary, retain the actual first failure and leave no partial artifacts.

This slice does not support multiple providers, arbitrary provider DSOs,
provider dependencies, payload paths/search paths, external target code,
non-relative entries, runtime translation, or cross-runtime inference. Musl
and Bionic need distinct provider builds/identities and complete native
source-versus-transformed evidence before any row is promoted.
