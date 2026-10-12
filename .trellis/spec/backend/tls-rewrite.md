# Managed TLSDESC Rewrite Contract

## Scenario: bounded AArch64 TLSDESC semantic rewrite

### 1. Scope / Trigger

This contract applies when selected-function protection encounters the exact
GNU AArch64 TLSDESC form represented by four adjacent static relocation sites:
`R_AARCH64_TLSDESC_ADR_PAGE21`, `R_AARCH64_TLSDESC_LD64_LO12`,
`R_AARCH64_TLSDESC_ADD_LO12`, and `R_AARCH64_TLSDESC_CALL`. It covers the
managed producer, canonical semantic snapshot, shared layout/materialization,
and output validation. It does not promote glibc, musl, bionic, worker, unload,
or transformed-runtime support.

### 2. Signatures

```text
FunctionProtectionService.Plan(ELF_BYTES, FunctionProtectionOptions)
  -> FunctionProtectionPlanResult

TlsStructuralAdapter.ProjectDescriptorOwner(
  ElfFile, TlsModuleIdentity, TlsSymbolIdentity, addend)
  -> TlsStructuralProjectionResult<TlsDescriptorOwnerBinding>

Aarch64TlsInstructionSemantics.IsSupportedTlsDescWordSequence(
  WORDS[8], TlsDescriptorOwnerBinding, sequenceAddress)
  -> bool

SemanticPlanSnapshotCodec.Create(SemanticRewritePlan)
  -> SemanticPlanSnapshotResult
```

`TlsDescriptorOwnerBinding.DescriptorRange` is the complete 16-byte per-symbol
descriptor. Its `Relocation` is the loader-owned 8-byte
`R_AARCH64_TLSDESC` first-word record. `ResolverPltRange` and `ResolverGotRange`
are separate ranges owned by the paired `DT_TLSDESC_PLT` and `DT_TLSDESC_GOT`
metadata.

### 3. Contracts

- The producer admits only one defined `STT_TLS` symbol/addend identity, four
  ordered adjacent static markers, one dynamic `R_AARCH64_TLSDESC` owner, a
  writable file-backed 16-byte descriptor, paired nonzero
  `DT_TLSDESC_PLT`/`DT_TLSDESC_GOT` tags, and the exact six-word resolver PLT/GOT
  shape. It does not infer a resolver target from `BLR X1`.
- The exact instruction flow is `ADRP X0`, `LDR X1,[X0]`, `ADD X0,X0,#0`,
  `BLR X1`, `MRS X1,TPIDR_EL0`, `ADD X0,X1,X0`, one scalar `LDR/STR [X0]`,
  and `RET`. The `BLR X1` site is a TLSDESC marker, never a `CALL26` site.
- `FunctionAnalysis` permits fallthrough only for `BLR X1` with all four exact
  adjacent TLSDESC markers. Ordinary indirect branches remain unresolved and
  fail closed.
- The emitter admits only the validated TLSDESC ADRP and marker-owned BLR. In
  flattening mode it emits the marker BLR and requires one in-function
  fallthrough block to remain physically adjacent, preserving the eight-word
  sequence for shared layout validation.
- `Aarch64SemanticInstructionProjector`, the semantic fixup encoder, plan
  validator, rehydration, `ElfLayoutPlanner`, and `ElfLayoutMaterializer` must
  classify the four TLSDESC instruction relocations as one typed model. Final
  instruction words flow through `Aarch64InstructionEncoder`/AsmStone.
- Rehydration and materialization preserve PT_TLS template/zero-fill/alignment,
  the descriptor bytes and writable ownership, the dynamic relocation identity,
  resolver PLT/GOT bytes and permissions, and the paired dynamic tag values.
- The sole Protected Image v1 `SemanticPlanSnapshot` operation carries the
  typed descriptor owner. Payload Frame v3, Protected Image ABI v1, and no
  migration or parallel TLSDESC codec remain unchanged.
- The exact managed producer and layout evidence are not runtime evidence. A
  missing glibc, musl, or bionic oracle remains an explicit environment or
  unpromoted result.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| ordinary indirect branch or unmarked `BLR` | `FunctionAnalysisIncomplete` or `ProtectionUnsupportedInstruction`; no artifact |
| missing, duplicated, non-writable, or unmapped descriptor owner | stable TLS binding/metadata diagnostic; no publication |
| missing or mismatched `DT_TLSDESC_PLT/GOT` pair | stable TLS metadata diagnostic; no publication |
| wrong marker order, symbol, addend, register, width, scale, or resolver stub | stable TLS sequence diagnostic; no publication |
| `TLSDESC_CALL` treated as `CALL26` | semantic/layout diagnostic; no output |
| noncontiguous flattened output sequence | `TlsLayoutMismatch`; no Native Image |
| changed descriptor/PLT/GOT/PT_TLS identity or permission | `TlsLayoutMismatch`; no publication |
| malformed snapshot, digest, or missing snapshot operation | bounded snapshot diagnostic; no rehydration output |
| unavailable runtime/toolchain evidence | explicit `environment-unavailable`; no runtime promotion |

### 5. Good/Base/Bad Cases

- Good: the selected GNU-shaped function passes marker-owned CFG analysis,
  emits contiguous TLSDESC words, carries one canonical descriptor owner,
  decodes through the current artifact operation, and passes shared output
  identity checks.
- Base: managed semantic/layout and producer tests pass while transformed
  glibc, musl, and bionic execution evidence is absent; the runtime claim stays
  open.
- Bad: an arbitrary `BLR X1` is admitted, a dynamic descriptor target is
  guessed, a full descriptor is reduced to its first relocation word, or a
  valid AsmStone encoding is treated as proof of TLS ownership.

### 6. Tests Required

- Structural tests assert PT_TLS geometry, descriptor 16-byte extent, dynamic
  owner identity, paired tags, resolver stub mapping, writable/executable
  permissions, truncation, duplication, and nearest malformed mutations.
- Semantic tests assert all four marker sites, register flow, exact `BLR X1`
  ownership, canonical snapshot round-trip, digest/tamper rejection, and
  rejection of relaxed TLSDESC forms.
- Producer tests assert `FunctionProtectionService.Plan` succeeds for the exact
  fixture, emits one `ProtectedImageSemanticPlanSnapshot`, and rejects an
  ordinary indirect branch or broken marker ownership without publishing.
- Layout tests assert contiguous output mapping, AsmStone round-trip encoding,
  descriptor/PLT/GOT/PT_TLS preservation, and transactional failure.
- Native matrix tests remain separate and must retain baseline/transformed
  status, streams, TLS values, lifecycle order, runtime identity, and hashes
  before any TLSDESC runtime row is promoted.

### 7. Wrong vs Correct

```text
Wrong: accept BLR X1 because it resembles a resolver call, copy one 8-byte
       descriptor relocation, and let materialization infer the remaining
       TLSDESC ownership from output bytes.

Correct: require the four ordered markers and exact descriptor/DT tag/stub
         ownership, carry the typed 16-byte descriptor binding in the canonical
         snapshot, keep the BLR fallthrough sequence contiguous, re-encode with
         the AsmStone-backed adapter, and reparse every preserved fact before
         publication.
```
