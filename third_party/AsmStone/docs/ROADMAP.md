# Roadmap

## Delivery strategy

The fastest route to complete current AArch64 coverage is a generated core:

1. Select a redistributable machine-readable ISA source.
2. Normalize instruction encodings, operands, feature requirements, aliases,
   and architectural constraints into an AsmStone schema.
3. Generate decode buckets, encoders, operand codecs, and feature tables.
4. Keep the runtime focused on generated instruction plans, bit operations, IR,
   diagnostics, binary operand codecs, context handling, and relocation/fixup
   mechanics; do not add opcode-specific implementation paths.
5. Validate generated behavior against GNU and LLVM assemblers/disassemblers.

## Milestones

- [x] Repository and .NET 8 solution.
- [x] Complete generated base A64 encoding inventory.
- [x] Stable initial IR and diagnostic types.
- [x] Little-endian word input and bit-field helpers.
- [x] First control-flow/PC-relative/add-sub generated vertical slice.
- [x] Source schema and generator project.
- [x] Complete base A64 integer/control-flow/load-store families.
- [x] Floating-point and AdvSIMD/NEON families.
- [x] Crypto, atomics, RAS, pointer authentication, MTE, and related
      extensions.
- [x] SVE/SVE2 and SME families.
- [x] System registers, barriers, hints, and feature gating.
- [x] Typed operand materialization and binary field/fixup handling.
- [x] Zero-allocation raw and semantic generated decode views.
- [x] Family-specific codecs for SME tile/vector operands and custom
      load/store/system operand classes.
- [x] AdvSIMD modified/floating immediate and move-wide immediate semantic
      codecs.
- [ ] Optional syntax adapter (only if a consumer explicitly requires text
      input/output).
- [x] Exhaustive generated-vector validation and package release.
- [x] Package release metadata and third-party/source-lock notices.
- [ ] Signed publication workflow.

## Non-goals for the first slice

- A32/T32 decoding.
- ELF, Mach-O, or PE object-file rewriting.
- Semantic execution or emulation.
- Treating an external native disassembler as the library implementation.
