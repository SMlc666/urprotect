# Technical design: complete TLS semantic rewrite before runtime promotion

## Design goal

Implement one complete managed TLS semantic/rewrite contract for all five AArch64
TLS access models before promoting any runtime matrix row:

```text
local-exec
initial-exec
local-dynamic
general-dynamic
TLSDESC
```

The runtime matrix is an evidence consumer, not the source of TLS semantics. A
native adapter accepting an unmodified TLS image is never treated as proof that
the managed transformer preserves TLS behavior.

## Non-negotiable invariants

1. **One typed TLS model:** no model is represented only by a string. The model,
   relocation family, symbol/module identity, addend, access expression, source
   instruction sequence, and runtime/profile requirements are typed records owned
   by the existing semantic/planning layers.
2. **One semantic plan:** TLS bindings, instruction fixups, GOT/TLSDESC bindings,
   and PT_TLS facts are carried by the existing immutable semantic rewrite plan
   and current snapshot/artifact extension owner. No second TLS IR or protocol
   grammar is introduced.
3. **One physical writer:** TLS layout/materialization uses the shared
   `ElfLayoutPlanner`, `ElfLayoutMaterializer`, and G2 `ProtectionWorkflow`.
   TLS-specific policies validate placement and metadata; they do not emit a
   parallel raw-byte image.
4. **Loader semantics are explicit:** module-relative, thread-pointer-relative,
   `__tls_get_addr`, and TLSDESC resolver behavior are recorded as semantic
   contracts. Unknown or unrecoverable relationships fail before publication.
5. **Runtime independence:** every model/profile/runtime/lifecycle row has its
   own baseline, transformed output, loader/oracle, lifecycle markers, and hashes.
   `environment-unavailable` is not support and never promotes another runtime.
6. **Current contract only:** Payload Frame v3, HostContext ABI v1, Protected
   Image ABI identifier/version, and G2 publication owners remain current. Extend
   only the sole Protected Image v1 operation grammar with one bounded
   SemanticPlanSnapshot operation (canonical bytes plus digest), reusing
   SemanticPlanSnapshotCodec as the only codec. No migration reader, compatibility
   alias, parallel TLS codec, or fallback writer is added. A transformed TLS plan
   without that operation is incomplete and fails before publication.


## AArch64 encoding boundary and test correction

AsmStone is already capable of encoding the AArch64 instruction families used by the current protection and TLS slices (`ADRP`, `ADR`, `B`, `BL`, conditional branches, `RET`, `BR`, `MRS`, `MOVZ/MOVN/MOVK`, immediate/register `ADD`, and `LDR/STR`). The current gap is UrProtect integration: production currently calls AsmStone for decode and register permutation, but does not call `TryEncodeFields` and still hand-builds multiple instruction words.

The managed architecture therefore uses one project-owned `Aarch64InstructionEncoder` adapter behind `Aarch64Semantics`. Its public contract accepts project-owned registers, widths, offsets, addresses, and instruction-family requests, and returns project-owned encoded words and diagnostics. AsmStone model types and generated field names do not escape this adapter.

The adapter is the only production owner for final instruction encoding. `Aarch64SemanticFixupEncoder`, `TlsSemanticModels`, `ElfLayoutPlanner`, `ElfLayoutMaterializer`, and `FunctionProtectionCodeEmitter` may calculate relocation values, range-check them, preserve non-relocation fields, and select semantic forms, but they delegate final instruction encoding to the adapter. The adapter must round-trip every emitted word through AsmStone decode before returning success.

TLS relocation-aware encoding remains split deliberately:

```text
UrProtect calculates and validates:
  relocation family, symbol/module, addend, GOT/TLSDESC owner,
  source/output address map, target address, page delta, scale, and range

AsmStone encodes and validates:
  the final AArch64 instruction operands and instruction word
```

A TLS model recognizer may use AsmStone-projected operand and register semantics, but it must also validate ELF relocation pairing and loader ownership. AsmStone is not made responsible for `R_AARCH64_TLS*`, PT_TLS, GOT, TLSDESC, `__tls_get_addr`, or runtime lifecycle policy.

The test contract is equally strict. `ElfFixture` and semantic fixture helpers must build instruction words through the adapter or retain a named GNU assembler/linker oracle. Negative fixtures mutate structured fields or relocation records from a valid encoded fixture. Golden instruction values are independent checks, not the implementation mechanism, and must decode successfully through AsmStone. Tests must include at least one production-path differential check for each migrated instruction family and one rejection proving that malformed TLS metadata is rejected by UrProtect even when each individual instruction is encodable by AsmStone.
## Ownership and data flow

```text
StructuralElf
  -> TlsSegmentFacts + TlsDynamicFacts + bounded TLS relocations/symbols
Aarch64Semantics
  -> TLS access-sequence recognition + register/resource ownership
SemanticPlanning
  -> TlsAccessModel + TlsBinding + TlsAddressExpression + TLS fixups
  -> SemanticRewritePlan / SemanticTlsBindingExtension
ElfLayout
  -> PT_TLS/GOT/TLSDESC/relocation preservation and output placement
Application/ProtectionWorkflow
  -> shared plan/materialization/profile validation
Protected Image v1 SemanticPlanSnapshot operation
  -> canonical bytes plus digest via SemanticPlanSnapshotCodec only (no frame/ABI version change)
Infrastructure/native peers
  -> atomic publication and independent runtime evidence
```

### Structural facts

`StructuralElf` owns bounded records for:

- PT_TLS file/virtual ranges, `p_filesz`, `p_memsz`, alignment, flags, template,
  zero-fill, and owning PT_LOAD;
- dynamic TLS tags and relocation-table facts;
- symbol/module identity and bounded symbol-version references;
- TLS relocation target ranges and raw `r_info`/addends;
- overlap, permission, alignment, and lifecycle diagnostics.

The structural layer does not choose a TLS model or runtime support status.

### Typed semantic records

The semantic contract contains at least:

```text
TlsAccessModel
  LocalExec | InitialExec | LocalDynamic | GeneralDynamic | TlsDesc

TlsRelocationFamily
  Tprel | GotTprel | Dtpmod | Dtprel | TlsDesc

TlsBinding
  model
  relocationFamily
  sourceIdentity/sourceRange
  instructionSequence
  symbolIdentity/moduleIdentity
  addend
  relocationSites
  accessSize
  addressExpression
  profileRequirements
  runtimeRequirements
```

`TlsAddressExpression` distinguishes thread-pointer-relative, module-relative,
resolver-returned, and descriptor-mediated values. Sequence records retain
instruction addresses, register inputs/outputs, call/resolver ownership, and
relocation pair membership.

## Five-model semantic coverage

The exact relocation constants are sourced from the project ELF constants and
validated against linker-produced fixtures. The design categories are:

### Local-exec

- executable-local TLS assumptions;
- TPREL immediate/64-bit relocation families;
- profile validation prevents use where executable-local assumptions do not hold;
- output expression remains thread-pointer-relative.

### Initial-exec

- statically allocated module TLS;
- GOTTPREL and TPREL instruction/relocation families;
- loader-owned module offset and per-thread initialization;
- current-thread and registered-worker lifecycle contracts remain separate rows.

### Local-dynamic
The first bounded implementation slice is the exact linker-produced TLSLD sequence recorded in `research/aarch64-tlsld-oracle.md`: adjacent `R_AARCH64_TLSLD_ADR_PAGE21` + `R_AARCH64_TLSLD_ADD_LO12_NC`, an exact `CALL26` to `__tls_get_addr`, then adjacent `R_AARCH64_TLSLD_ADD_DTPREL_HI12` + `R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC`. The slice carries the loader-owned `R_AARCH64_TLS_DTPMOD64` GOT owner and preserves PT_TLS template, zero-fill, dynamic relocation identity, GOT range/permissions, resolver ownership, and register flow. TLSLD MOVW/literal/LDST forms remain rejected until separately evidenced.

- local module identity;
- DTPMOD/DTPREL and TLSLD sequence ownership;
- `__tls_get_addr`/module-base relationship is explicit;
- no conversion to initial-exec by heuristic.

### General-dynamic

- module and symbol resolution through the dynamic TLS access sequence;
- DTPMOD/DTPREL bindings and `__tls_get_addr` call ownership;
- dynamic symbol/module identity remains part of the plan;
- relocation and call sequence are rewritten together.

### TLSDESC

- descriptor address formation;
- TLSDESC GOT/descriptor relocation state;
- resolver call sequence and register contract;
- lazy/immediate binding requirements are explicit and runtime-specific.

Each model must have valid, malformed, inconsistent, unsupported-profile, and
nearest-model-confusion cases. The implementation must not classify a form as
unknown merely because it is table-driven or relative when all required facts
are recoverable.

## Rewrite and layout contract

For every supported sequence:

```text
recognize source sequence
  -> bind PT_TLS/module/symbol/relocation facts
  -> build semantic TLS address expression
  -> map source registers/instructions/relocations to output
  -> emit typed fixups
  -> materialize through shared layout writer
  -> reparse and validate semantic/layout/TLS invariants
```

The first complete semantic contract preserves, unless a typed layout extension
explicitly proves the change:

- PT_TLS template bytes;
- `p_filesz` initialized data;
- `p_memsz - p_filesz` zero-fill;
- PT_TLS alignment and owning load congruence;
- TLS GOT/TLSDESC metadata;
- dynamic relocation ownership and addends;
- module/thread-relative meaning;
- constructor/destructor and worker lifecycle bindings.

A layout candidate that would overlap, orphan, or implicitly move TLS metadata is
rejected before output publication. The materializer never reconstructs TLS
meaning by rescanning unrelated executable bytes.

## Snapshot and artifact contract

The current semantic snapshot codec gains typed TLS serialization through the
existing extension owner:

- canonical model/family tags;
- bounded source sequence and relocation-site lists;
- symbol/module identity and addend;
- address expression and access width;
- profile/runtime requirements;
- deterministic ordering and digest coverage;
- malformed, duplicate, inconsistent, and unsupported extension diagnostics.

Payload Frame v3 layout and version remain unchanged. Protected Image operations
carry only the current operation/artifact contract already owned by G2; no
parallel TLS payload codec is introduced.

## Runtime matrix contract

Runtime evidence begins only after the semantic gate passes. Matrix keys are:

```text
model × profile × runtime × lifecycle
```

Each row records one of:

```text
validated
accepted-and-runs
expected-rejected
unexpected-rejection
unexpected-acceptance
runtime-failure
environment-unavailable
not-applicable
```

A promoted row retains:

- compiler/linker/runtime/loader identity;
- readelf PT_TLS and relocation facts;
- baseline and transformed output/status/streams;
- protected artifact, Native Image, handoff, and record hashes;
- per-thread values and zero-fill observations;
- constructor/destructor/worker/release order;
- first-failure stage and rollback witness;
- profile, ABI, workflow owner, and evidence manifest bindings.

The existing glibc initial-exec and registered-worker rows remain valid runtime
baselines. They are not promoted as complete managed rewrite support until the
five-model semantic gate and transformed-image equivalence pass.

## Failure and rollback matrix

| Condition | Required result |
|---|---|
| PT_TLS range/size/alignment/permission violation | stable structural diagnostic; no plan publication |
| model/relocation/sequence mismatch | stable TLS semantic diagnostic; no output/evidence |
| unresolved module/symbol/TLSDESC ownership | deterministic unresolved diagnostic; no guessing |
| address-map or register-resource conflict | semantic planning failure; no partial artifact |
| TLS metadata/layout overlap | layout failure; no Native Image or role publication |
| snapshot extension malformed/duplicate/inconsistent | bounded decode failure; no rehydration output |
| baseline/transformed TLS value or lifecycle mismatch | behavior-oracle failure; row incomplete |
| runtime/toolchain unavailable | explicit `environment-unavailable`; no promotion |
| worker/TLS teardown or release-order failure | handoff/lifecycle failure; rollback retained |

## Assembly and dependency rules

No new assembly is required initially. Structural, semantic, planning, and layout
TLS records stay in their G1 owners. Native runtime code remains a peer contract
implementation. Runtime scripts own toolchain/evidence orchestration and never
become managed semantic authorities.
