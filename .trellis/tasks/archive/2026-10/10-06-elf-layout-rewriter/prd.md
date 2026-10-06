# Build generic ELF layout rewriter

## Goal

Replace the PT_NULL-dependent append writer with a single bounded ELF layout planner/materializer that can place transformed AArch64 code when every program-header slot is occupied.

## Requirements

- Plan program-header table placement/count, segment file offsets, virtual addresses, permissions, sizes, alignment, veneers, and byte edits before writing.
- Support a compatible existing RX `PT_LOAD` extension and a rebuilt/relocated program-header table with a new RX `PT_LOAD`.
- Preserve or explicitly model `PT_LOAD`, `PT_INTERP`, `PT_DYNAMIC`, `PT_TLS`, `PT_GNU_RELRO`, `PT_GNU_STACK`, `PT_GNU_PROPERTY`, `PT_PHDR`, and `PT_NOTE`.
- Include entry trampoline/veneer placement and branch-range decisions in the same plan.
- Remove `TryFindRewriteSlot`/`TryAppendExecutableSegment` as a separate production path; any usable PT_NULL entry is an ordinary plan candidate.
- Publish atomically, reparse with the project parser, validate with readelf, and retain the selected layout strategy and address map in evidence.

## Acceptance criteria

- [x] An occupied-program-header fixture transforms without a PT_NULL slot.
- [x] Existing PT_NULL, RX-extension, and rebuilt-table fixtures use one planner and preserve required load semantics.
- [x] Program-header table metadata, alignment, segment permissions, and section offsets remain structurally valid.
- [x] Branch-range overflow produces a planned veneer or a stable diagnostic with no output.
- [x] Three-runtime behavior remains an explicit parent workflow/runtime-child acceptance gate; this child publishes the bounded layout contracts and evidence without promoting runtime claims.
