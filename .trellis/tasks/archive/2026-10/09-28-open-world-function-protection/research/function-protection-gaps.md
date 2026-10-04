# Function-protection infrastructure research

## Existing implementation

- `src/UrProtect.Core/Aarch64/Aarch64Decoder.cs` has a project-owned AsmStone adapter, but it projects only a small property set and one target address.
- `src/UrProtect.Core/Aarch64/Aarch64Analyzer.cs` performs bounded linear scans from the ELF entry, dynamic symbols, and relocation offsets. It is not a symbol-bounded function analyzer or CFG builder.
- `ElfParser` exposes dynamic symbols but not ordinary `.symtab` function records. The initial selector contract therefore requires section-symbol parsing for non-exported functions.
- `NoOpPipeline` and `ElfPackService` validate, copy, or package bytes. There is no relocation-aware ELF layout planner or writer.
- AsmStone exposes full operand models, semantic operand directions, register classes/constraints, implicit operands, target operands, and encoder APIs through the vendored project. The project adapter should retain those capabilities without exposing AsmStone types outside the adapter boundary.

## Required infrastructure implied by the requirements

1. A merged `.symtab`/`.dynsym` function inventory with source identity, exact range, aliases, and ambiguity diagnostics.
2. A project-owned instruction IR retaining explicit and implicit operands, register views, memory addressing, flags, control-flow targets, PC-relative references, and encoding provenance.
3. Function-bounded CFG construction with direct/conditional edges, call/return boundaries, indirect-control-flow barriers, and code/data uncertainty.
4. A machine-state model covering GPR views, SP/ZR distinction, SIMD/vector classes, NZCV, LR, stack state, call-clobber/preserve rules, and observable memory effects.
5. Register-pressure and spill planning that can reject a selected function before emission when the required state cannot be represented safely; no silent best-effort rewrite.
6. A layout/emission layer that preserves untouched bytes and metadata, adds or relocates transformed code, repairs branches and PC-relative references, and validates output through a second parse/decode pass.
7. Two explicit passes: control-flow flattening first, then register permutation. Each pass must be independently selectable and atomically composable.

## Safety boundary for the first implementation

Only functions with a unique, non-empty symbol range wholly inside one executable load segment and a complete supported CFG/semantic subset are transformable. Any selected function outside that boundary fails the whole operation; unselected functions and opaque ELF records remain untouched.
