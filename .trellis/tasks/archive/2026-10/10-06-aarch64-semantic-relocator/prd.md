# Build AArch64 semantic relocation engine

## Goal

Create a project-owned semantic rewrite model that relocates transformed AArch64 instructions and ELF relocation records instead of copying raw instruction bytes as the primary operation.

## Requirements

- Annotate decoded instructions with operands, register/flag effects, control-flow targets, PC-relative expressions, literal references, relocation references, and source ranges.
- Maintain old-to-new mappings for functions, basic blocks, literals, veneers, and relocation targets.
- Rewrite and relax direct branches, conditional branches, calls, ADR/ADRP pairs, literal loads, and the relevant AArch64 CALL/JUMP/ADR/LO12/CONDBR/TSTBR relocation families.
- Preserve external PLT/GOT and dynamic relocation semantics where the feature row claims them.
- Integrate with the shared layout plan and Protected Image artifact rather than creating a second writer.
- Expose extension points for indirect targets, TLS bindings, jump tables, and CFI effects owned by sibling children.

## Ordering and dependencies

This child establishes the semantic IR, address-map, and fixup contracts before the indirect-control-flow, TLS, CFI, layout, and workflow children integrate their domains. It emits plans and fixups; it does not own final ELF file placement or CLI publication. Sibling children must consume these contracts rather than introduce parallel raw-byte rewrite models.

## Acceptance criteria
- [ ] Project-owned projector, plan factory, encoder, validator, and snapshot tests cover each promoted PC-relative/call/literal/relocation family plus nearest malformed/range cases.
- [ ] Branch-range, relocation, target-resolution, address-map, snapshot-limit, digest, and post-encode failures produce stable diagnostics without final output bytes.
- [ ] Every final semantic instruction encoding supplied to the validator is decoded at its planned output address and its target expression is checked; final ELF placement is owned by the layout/workflow children.
- [ ] The plan and canonical snapshot distinguish exact, bounded-set, runtime-resolved, deferred, and unresolved targets without guessing.
- [ ] Relocation raw type/info/addend/symbol/PLT/table metadata and typed source/output ranges survive deterministic canonical round-trip.
- [ ] Typed extension points exist for indirect targets, jump tables, TLS bindings, and CFI effects; sibling consumers can bind them without a second semantic model.
- [ ] The old direct writer is not required by the semantic engine; no ELF bytes or CLI publication are owned by this child.
