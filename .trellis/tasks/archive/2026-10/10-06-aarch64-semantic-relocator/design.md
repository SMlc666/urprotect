# Technical design: AArch64 semantic relocation engine

## Boundary

The child owns semantic instruction modeling, address mapping, fixup creation, branch/call/literal relocation, and AArch64 ELF relocation expression handling. It does not own final program-header placement, native publication, TLS-family implementation, jump-table target resolution, or CFI emission; those consumers attach typed extensions to the shared plan.

## Data model

Add project-owned records near `src/UrProtect.Core/Aarch64/` and `src/UrProtect.Core/Elf/`:

```text
SemanticInstruction
SemanticOperand
SemanticReference
PcRelativeExpression
LiteralReference
RelocationBinding
SemanticTarget
AddressMap
SemanticFixup
SemanticRewritePlan
```

Each instruction retains source `VirtualAddress`, `FileOffset`, raw encoding, decoded project-owned operands, register/flag effects, control-flow kind, source range, and reference annotations. `AsmStoneAdapter` remains the only third-party boundary.

`AddressMap` maps functions, basic blocks, literals, veneers, tables, and relocation sites from source identity to planned output identity. A target is explicitly `Exact`, `BoundedSet`, `RuntimeResolved`, or `Unresolved`.

## Rewrite flow

```text
ElfFile + selected functions
  -> decode and annotate semantic instructions
  -> build source CFG and reference graph
  -> allocate transformed block identities
  -> compute old/new AddressMap
  -> emit symbolic instructions and SemanticFixups
  -> resolve fixup encodings after layout addresses exist
  -> validate every encoded instruction and target
```

The semantic plan contains symbolic target identities and relocation expressions, never final file offsets embedded during analysis. It is serializable into the next Protected Image artifact version without depending on the final ELF layout.

## Initial semantic families

Implement project-owned encoders and validators for:

- `B`, `BL`, conditional branches, and branch-range relaxation;
- internal block/function targets and external call targets;
- `ADR`/`ADRP` with matching low-page expressions;
- literal loads and literal-pool references;
- AArch64 `CALL26`, `JUMP26`, `CONDBR19`, `TSTBR14`, `ADR_PREL_LO21`, `ADR_PREL_PG_HI21`, `ADD_ABS_LO12_NC`, load/store low-12 expressions, and compatible absolute/relative relocation bindings.

External targets retain PLT/GOT/dynamic binding identity. Unsupported expressions remain explicit plan diagnostics until a sibling feature adds the corresponding resolver.

## Integration contracts

- The layout child consumes `SemanticRewritePlan` and supplies final addresses.
- The indirect/jump-table child adds target sets and table references.
- The TLS child adds `TlsReference`/TLS relocation bindings.
- The CFI child consumes the address map and instruction frame effects.
- The workflow child owns artifact ABI, publication, and CLI reports.

## Invariants

- No raw instruction is copied into a relocated region without a semantic annotation or an explicit opaque-preservation contract.
- Every PC-relative target is resolved against the final address map before publication.
- Every relocation write is bounds-checked, alignment-checked, and round-trip decoded.
- Register/flag effects used by control-flow flattening and register permutation remain visible to resource planning.
- Failed resolution leaves no emitted artifact.
