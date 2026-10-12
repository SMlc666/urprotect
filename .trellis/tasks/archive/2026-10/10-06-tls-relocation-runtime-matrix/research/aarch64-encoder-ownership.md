# AArch64 encoder ownership and fixture correction

## Decision

The current UrProtect task records one explicit correction: AsmStone is the pinned AArch64 instruction decoder/encoder backend, not merely a decoder and register-permutation helper. UrProtect must use a project-owned adapter backed by AsmStone for every final AArch64 instruction word generated or re-encoded by the managed pipeline.

The correction does not move ELF or TLS semantics into AsmStone. UrProtect remains responsible for ELF relocation records, symbols, PT_TLS, GOT/TLSDESC ownership, RELA addends, TLS model classification, sequence recognition, module/thread-relative expressions, address mapping, layout, materialization, reparse, and publication policy. The adapter passes resolved project-owned operands or PC-relative targets to AsmStone and returns project-owned words and diagnostics.

## Capability evidence

The pinned AsmStone tree exposes:

- generated instruction metadata and codecs for `ADRP`, `ADR`, `B`, `BL`, conditional branches, `RET`, `BR`, `MRS`, `MOVZ`, `MOVN`, `MOVK`, `ADD`, `LDR`, and `STR` families;
- object encoding through `AsmStoneApi.TryEncode`;
- raw generated-field encoding through `AsmStoneApi.TryEncodeFields`;
- `TargetOperand` handling that checks PC-relative alignment and signed range before encoding;
- decode/encode round-trip support through the same generated TableGen catalog.

The checked-in project usage now has one project-owned `Aarch64InstructionEncoder`
for final generated/re-encoded words, plus the existing decode projection and
register-permutation surface in `AsmStoneAdapter`. Direct AsmStone encoding is
contained inside those adapter boundaries; semantic, TLS, and layout owners do
not import AsmStone model types. The remaining manual writers are listed below
as migration debt.

AsmStone's intentional boundary excludes text assembly parsing and ELF relocation interpretation. GNU assembler/linker fixtures remain independent ABI/toolchain oracles. They are complementary evidence, not competing managed encoding implementations.

## Manual encoding inventory

The current production migration debt is concentrated in:

- `Application/Protection/FunctionProtectionCodeEmitter.cs`: MOV/CMP/RET and branch construction;
- `SemanticPlanning/Aarch64SemanticFixupEncoder.cs`: branch, ADR/ADRP, literal, ADD low-12, and load/store low-12 construction;
- `SemanticPlanning/TlsSemanticModels.cs`: TLSLD/TLSGD resolver and module pairs, TLSIE PREL19, TLSIE ADRP/LD64, DTPREL fields, and page-immediate construction;
- `ElfLayout/ElfLayoutPlanner.cs` and `ElfLayout/ElfLayoutMaterializer.cs`: duplicated branch construction and raw TLS field transplantation.

Raw masks used only to classify or validate a transition slice are separate from final instruction writers. They must still be paired with AsmStone-projected operand checks, and new recognizers must not duplicate generated instruction catalog knowledge.

## Test correction

Fixture construction follows this order:

```text
AsmStone-backed project builder
  -> valid instruction words
  -> ELF container/relocation metadata built by fixture helper
  -> AsmStone decode round-trip
  -> optional GNU assembler/linker differential oracle
```

Nearest-negative fixtures mutate structured operands, instruction fields, or ELF relocation metadata from a valid fixture. They retain a stable diagnostic and publication-rollback assertion. Golden words remain as independent expected values only when they decode through AsmStone and, for the promoted ABI shape, have an explicitly named GNU oracle or linker-produced comparison.

A valid AsmStone instruction is not evidence of a valid TLS sequence. Tests must separately prove that malformed relocation pairing, symbol/module identity, GOT/TLSDESC ownership, addend, PT_TLS facts, or lifecycle metadata is rejected by UrProtect.

## Current implementation slice

The project-owned adapter is now implemented at
`src/UrProtect.Core/Aarch64Semantics/Aarch64InstructionEncoder.cs`. It accepts
project-owned instruction-family/request/result records, delegates final
operand encoding to AsmStone, and decodes every emitted word again through
AsmStone before returning it. The shared semantic fixup owner
`src/UrProtect.Core/SemanticPlanning/Aarch64SemanticFixupEncoder.cs` routes
Branch26/Call26, conditional/test branches, ADR/ADRP, and literal-load
re-encoding through that adapter. The bounded TLSLD/TLSGD materialization path
also routes resolver CALL26, module ADRP/ADD, and TLSLD DTPREL ADD output
through the same adapter; `TlsStructuralAdapter` uses AsmStone-projected
register/memory/target operands when validating the exact resolver PLT shape.
UrProtect still owns target/addend/address-map calculation and relaxation
decisions.

Focused coverage is in
`tests/UrProtect.Core.Tests/Semantics/Aarch64InstructionEncoderTests.cs` and
`tests/UrProtect.Core.Tests/Semantics/SemanticRelocationTests.cs`. The positive
adapter fixtures are built through the adapter; nearest-negative cases mutate
mapped targets or structured access width/offset requests.

## Remaining migration debt

The following manual production writers remain and are intentionally not used
by the migrated shared semantic PC-relative path:

- `src/UrProtect.Core/SemanticPlanning/Aarch64SemanticFixupEncoder.cs`:
  the shared PC-relative writer migration is complete for Branch26/Call26,
  conditional/test branches, ADR/ADRP, and literal loads. The old local
  bitfield helpers were removed; the remaining `AddImmediateMask` writer is
  still transition debt for low-12 relocation materialization. Owner:
  SemanticPlanning. Replacement follow-up: route ADD low-12 and load/store
  low-12 output through `Aarch64InstructionEncoder` with structured access
  width/scale requests and focused semantic relocation tests.
- `src/UrProtect.Core/SemanticPlanning/TlsSemanticModels.cs`:
  the existing TLSLE/TLSIE immediate/page/low-12 field writers remain transition
  debt. The bounded TLSLD/TLSGD resolver CALL26, module ADRP/ADD, and TLSLD
  DTPREL ADD output paths now delegate final word encoding to
  `Aarch64InstructionEncoder` while retaining relocation-family, GOT/module-owner,
  addend, and sequence validation in UrProtect. Owner: SemanticPlanning TLS.
  Replacement follow-up: route the remaining evidenced TLSLE/TLSIE families
  through `Aarch64InstructionEncoder` with structured access width/scale
  requests and one adapter round-trip plus nearest-negative fixture per family.
- `src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs` and
  `src/UrProtect.Core/ElfLayout/ElfLayoutMaterializer.cs`:
  branch and TLS output-field construction/validation remains transition debt.
  Owner: ElfLayout. Replacement follow-up: consume adapter results from the
  shared semantic fixup decisions and add output reparse tests proving the
  AsmStone round trip before removing raw field transplantation.
- `src/UrProtect.Core/Application/Protection/FunctionProtectionCodeEmitter.cs`:
  MOV/CMP/RET and branch construction remains transition debt. Owner:
  Application/Protection. Replacement follow-up: use the adapter for generated
  pass output and add focused protected-function output decode tests before
  removing local instruction-word construction.

No new production instruction-word writer is permitted while these entries are
open. ELF relocation constants and raw masks used only for bounded recognition
or validation remain UrProtect-owned and are not encoder debt.

## Acceptance gate

The task remains open until:

1. a project-owned AsmStone-backed encoder adapter exists with bounded project types and decode round-trip validation;
2. all newly generated/re-encoded production instructions use that adapter;
3. the current manual production writers are recorded as migration debt and replaced or explicitly bounded with owners and focused tests;
4. positive, nearest-negative, fixture, and golden tests use the adapter or a named GNU oracle;
5. each promoted instruction family has at least one managed-vs-GNU differential check and one UrProtect-specific semantic rejection check.
