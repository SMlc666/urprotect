# Implementation plan

## Phase 0: Freeze the migration contract

1. Record current `protect`, `protect-image`, and `rehydrate-image` outputs as migration fixtures and behavior oracles.
2. Add occupied-program-header, long-distance branch, PC-relative, call, literal, indirect, jump-table, TLS, CFI, malformed-CFI, and three-runtime fixture inventory entries before implementation.
3. Define new diagnostic codes, feature-row IDs, artifact ABI versioning, layout-strategy vocabulary, and report fields.
4. Preserve Protected Image v1 as historical migration evidence; define the new versioned operation contract.

## Phase 1: Build shared semantic and layout plans

1. Add project-owned AArch64 semantic IR over `AsmStoneAdapter`.
2. Add old/new address maps, target-resolution modes, semantic fixups, relocation bindings, TLS bindings, and unwind effects.
3. Add `ElfLayoutPlan`, program-header allocation, segment placement, PHDR-table relocation/expansion, alignment checks, and atomic byte emission.
4. Add veneer/long-branch planning and make Branch26 only one fixup form.
5. Add plan-level validation before any output bytes are published.

## Phase 2: Implement semantic domains

1. Relocate PC-relative branches, calls, ADR/ADRP pairs, literal pools, and the agreed AArch64 relocation families.
2. Resolve bounded indirect branches/calls and jump tables; implement the declared runtime target strategy for opaque targets.
3. Add PT_TLS and local/initial-exec/dynamic/TLSDESC relocation models, then exercise them on glibc, musl, and bionic.
4. Add CIE/FDE and `.eh_frame_hdr` parse, remap, regeneration, and recoverable malformed-CFI canonicalization.
5. Require each domain to add positive, nearest-negative, malformed, structural, and runtime evidence before promotion.

## Phase 3: Converge the workflow

1. Implement one Core producer/layout/materializer workflow.
2. Route `protect` through that workflow as a high-level facade.
3. Keep `protect-image` and `rehydrate-image` as explicit stage commands over the same contracts.
4. Remove the direct writer from production behavior; retain only migration tests until final integration review.
5. Align role/stage/native-image/rehydration reports, SHA256SUMS, and failure rollback.

## Phase 4: Three-runtime integration

1. Extend glibc, musl, and bionic fixture builders and loader/handoff oracles for every promoted semantic feature.
2. Retain independent environment/toolchain/image identity and no-fallback evidence for each runtime.
3. Run baseline/protected comparisons for status, streams, signals, TLS values, lifecycle, unwind/exception, and indirect target coverage.
4. Update `fixtures/manifest.json`, `fixtures/runtime-matrix.json`, regression matrix, compatibility report, evidence checkers, and real-sample impact table.

## Validation commands

- `dotnet restore UrProtect.sln --locked-mode`
- `dotnet build UrProtect.sln --configuration Release --no-restore`
- `dotnet test UrProtect.sln --configuration Release --no-build --no-restore`
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`
- `python3 scripts/validate-regression-matrix.py tests/regression-matrix.json`
- `make -C native/urprotect-runtime test`
- `./scripts/run-protection-e2e.sh --tier pr --runtime glibc`
- `./scripts/run-protection-e2e.sh --tier pr --runtime musl`
- `./scripts/run-protection-e2e.sh --tier pr --runtime bionic`
- `./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc`
- `./scripts/run-rehydration-e2e.sh --tier pr --runtime musl`
- `./scripts/run-rehydration-e2e.sh --tier pr --runtime bionic`
- `./scripts/check-evidence.py fixtures/manifest.json --tier pr --execution native-linux`
- `./scripts/check-runtime-matrix-evidence.py pr .artifacts/runtime-matrix/pr .artifacts/bionic/c-termux-bionic-pie`
- `git diff --check`

The musl and bionic rehydration commands are expected to be added or made profile-aware before their validation rows are enabled.

## Risky files and rollback points

- `src/UrProtect.Core/Elf/ElfParser.cs`, `ElfTypes.cs`, `LoadMap.cs`: parser/model contract and address domains.
- `src/UrProtect.Core/Aarch64/`: semantic IR, decoder adapter, CFG, register/resource analysis.
- `src/UrProtect.Core/Protect/`: producer ABI, layout plan, fixups, publisher, and workflow.
- `src/UrProtect.Core/Rehydrate/`: Native Image materializer and metadata publication.
- `src/UrProtect.Cli/CliApplication.cs` and report records: public command/report contract.
- `fixtures/manifest.json`, runtime matrix, native fixtures, and CI workflows: three-runtime evidence contract.

Rollback remains artifact-safe: each stage writes only temporary output, failure removes staged files, and the migration branch can compare against frozen pre-migration fixtures without enabling an alternate production writer.

## Review gates before task start

- Parent PRD, design, and this implementation plan are reviewed and contain no unresolved scope decisions.
- Child PRDs state their ordering constraints and independently verifiable acceptance criteria.
- The new artifact ABI/version, diagnostic vocabulary, runtime matrix, and malformed-input policy are explicit.
- The final planning summary is presented; implementation begins only after a subsequent explicit approval and `task.py start`.
