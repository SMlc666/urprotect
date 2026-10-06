# Implementation plan

## Ordered checklist

1. Add bounded project-owned layout records, strategy/evidence enums, typed file/virtual ranges, and layout limits under `src/UrProtect.Core/Elf/`.
2. Add the shared candidate planner and invariant checks for existing RX extension, an available `PT_NULL` entry, and relocated/expanded program-header tables.
3. Add checked placement helpers for file/virtual alignment, load ordering, metadata preservation, PT_PHDR mapping, sectionless inputs, and output limits.
4. Add branch-placement decisions and typed near-veneer/long-form hooks that consume semantic fixups without synthesizing unknown instruction bytes.
5. Add `ElfLayoutMaterializer` that applies canonical edits, serializes program headers, reparses the output, validates the load map, and returns no bytes on any failure.
6. Replace the `GenericRehydrationEngine` PT_NULL append block with the shared planner/materializer while keeping `RehydrationPublisher` as the atomic publication owner.
7. Add synthetic occupied-table, PT_NULL, RX-extension, rebuilt-table, PT_PHDR, alignment, overlap, malformed, range, and deterministic snapshot fixtures/tests.
8. Add readelf/llvm-readelf structural checks and layout evidence projection without changing the runtime claim layer; update `tests/ContractInventory.md` and the relevant backend spec.
9. Run parent integration checks and publish the layout handoff for the indirect-control-flow, TLS, CFI, and workflow children.

## Validation commands

- `dotnet build UrProtect.sln --configuration Release --no-restore`
- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore`
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`
- `python3 tests/test_regression_matrix.py`
- `git diff --check`
- `readelf -lW -hW OUTPUT` or `llvm-readelf -lW -hW OUTPUT` for promoted ELF fixtures

Native glibc, musl, and bionic baseline/protected behavior commands remain parent/runtime-child gates. A missing native capability is retained as an explicit environment result and is never relabeled as a layout pass.

## Rollback points

- New layout models and planner candidates are additive until `GenericRehydrationEngine` switches to them.
- The old PT_NULL implementation is retained only as a test oracle during migration and is removed from production behavior once planner parity tests pass; no runtime fallback is introduced.
- If any candidate fails post-parse validation, the planner returns diagnostics and the materializer returns no output bytes.
- Protected Image artifact changes remain owned by the workflow child; layout evidence can be omitted from publication without changing the source artifact ABI until the versioned handoff is integrated.
