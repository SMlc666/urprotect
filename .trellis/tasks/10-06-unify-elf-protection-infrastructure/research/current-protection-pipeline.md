# Repository research: current protection pipeline

## Current production paths

- `protect` enters `FunctionProtectionService.Protect`, resolves explicit `STT_FUNC` selectors, analyzes bounded AArch64 CFGs, emits transformed code, requires a `PT_NULL` program-header slot, appends an RX `PT_LOAD`, patches an entry `B imm26`, reparses the output, and checks unchanged source bytes outside selected ranges and the reserved slot.
- `protect-image` enters `ProtectedImageProducer.Emit`, consumes `FunctionProtectionService.Plan`, emits layout-neutral Protected Image v1 operations, and publishes artifact/role/manifest/stage evidence.
- `rehydrate-image` enters `GenericRehydrationEngine`, validates the Protected Image, materializes the current `outer-execveat` layout by appending an RX segment and applying branch fixups, reparses the Native Image, and publishes rehydration/native-image evidence.

## Current semantic boundary

The existing rewrite service rejects most non-terminal PC-relative instructions, direct calls, indirect branches, and resource-conflicting functions. Protected Image v1 carries `EmitRegion` and `ApplyEntryBranch26` operations only. There is no general CFI/unwind rewrite engine and no complete TLS semantic rewrite engine.

## Existing safety contracts

The parser uses bounded reads and program headers/load maps as runtime authority. Publication is temporary-file, flush, read-back, verify, and atomic-rename based. Stable diagnostics, source/artifact/request hashes, no-partial-output behavior, and native behavior oracles are existing contracts to preserve.
