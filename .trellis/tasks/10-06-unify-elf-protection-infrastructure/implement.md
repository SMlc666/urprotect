# Implementation plan

## Phase 0: Freeze the current contract and purge history
0. Audit and correct the structural-versus-code-analysis boundary: make generic validation/wrapper paths structural by default, remove whole-image instruction scanning as a production prerequisite, and add selected-function/demand-driven analysis regressions.

1. Complete child task `10-06-architecture-boundary-refactor` Gates G0-G2: purge all historical production paths and migration-format data, establish namespace-first ownership, unify the current workflow, and complete HostContext materialization.
2. Add occupied-program-header, long-distance branch, PC-relative, call, literal, indirect, jump-table, TLS, CFI, malformed-CFI, and three-runtime fixture inventory entries for current behavior only.
3. Define current diagnostic codes, feature-row IDs, artifact ABI versioning, layout-strategy vocabulary, and report fields.
4. Use one current Protected Image operation contract; do not retain historical ABI fixtures, decoders, encoders, or migration oracles.

## Phase 1: Establish shared semantic, layout, and workflow seams

1. Consume the architecture-boundary-refactor G0-G2 outputs: one current contract, namespace-first ownership, no historical test/evidence data, one current workflow, and complete HostContext materialization.
2. Add project-owned AArch64 semantic IR over `AsmStoneAdapter`.
3. Add old/new address maps, target-resolution states, semantic fixups, relocation bindings, TLS bindings, and unwind effects required by downstream domains.
4. Add `ElfLayoutPlan`, program-header allocation, segment placement, PHDR-table relocation/expansion, alignment checks, and atomic byte emission.
5. Add veneer/long-branch planning and make Branch26 one fixup form rather than the writer contract.
6. Implement one Core producer/layout/materializer workflow and route `protect`, `protect-image`, and `rehydrate-image` through it.
7. Validate the complete HostContext materialization path and profile-specific native handoff before feature expansion.
8. Add plan-level validation before any output bytes are published.

## Phase 2: Implement semantic domains against the current workflow

1. Relocate PC-relative branches, calls, ADR/ADRP pairs, literal pools, and the agreed AArch64 relocation families.
2. Resolve bounded indirect branches/calls and jump tables; implement the declared runtime target strategy for opaque targets.
3. Add PT_TLS and local/initial-exec/dynamic/TLSDESC relocation models, then exercise them on glibc, musl, and bionic.
4. Add CIE/FDE and `.eh_frame_hdr` parse, remap, regeneration, and recoverable malformed-CFI canonicalization.
5. Require each domain to add positive, nearest-negative, malformed, structural, and runtime evidence using only the current contract before promotion.

## Phase 3: Converge reports, evidence, and publication

1. Align role/stage/native-image/rehydration reports, SHA256SUMS, and failure rollback.
2. Remove any remaining direct-writer or duplicate workflow call sites and enforce one owner per command.
3. Update current fixtures, runtime matrix, regression matrix, compatibility report, evidence checkers, and real-sample impact table.
4. Verify no historical migration path or test/evidence data has re-entered the current contract.

## Phase 4: Three-runtime integration

1. Extend glibc, musl, and bionic fixture builders and loader/handoff oracles for every promoted semantic feature.
2. Retain independent environment/toolchain/image identity and no-fallback evidence for each runtime.
3. Run baseline/protected comparisons for status, streams, signals, TLS values, lifecycle, unwind/exception, and indirect target coverage.
4. Update `fixtures/manifest.json`, `fixtures/runtime-matrix.json`, regression matrix, compatibility report, evidence checkers, and real-sample impact table.

## Native configured-provider candidate preflight boundary

The configured-provider consumer candidate preflight owns a single 8 MiB aggregate
work budget initialized before any candidate program-header or dynamic-tag scan.
Debit it before the program-header walk and each PT_LOAD range lookup, before
iterating dynamic entries, and for bounded `DT_NEEDED` bytes, version traversal,
RELA/PLT/RELR validation, GNU-hash bucket/chain traversal, dynsym work, and
provider-specific consumer checks. Pass the same work object through the
consumer RELA path; never initialize a replacement budget there. In candidate
mode, NEEDED strings are scanned for at most the maximum accepted configured
provider/libc/loader SONAME length plus its terminator, then overlong or unknown
names are rejected. A configured provider must not reject a valid generic
libc/versioned image; without a configured provider, preserve the ordinary
non-provider path. The provider DSO parser retains a separate, independent 8 MiB
budget. Keep exact-limit and one-under candidate tests, bounded long-NEEDED
rejection, early provider version-tag rejection, and configured versioned-libc
positive coverage. This implementation-plan addition does not close any
external-table acceptance criterion or claim parent completion.

Native AArch64/glibc verification, each using a unique isolated build directory:

- `make -C native/urprotect-runtime BUILD_DIR=/tmp/urp-provider-preflight-focused-<unique> clean external-provider-self-test`
- `make -C native/urprotect-runtime BUILD_DIR=/tmp/urp-provider-preflight-full-<unique> clean test`
- `git diff --check`

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

- `src/UrProtect.Core/StructuralElf/ElfParser.cs`, `ElfTypes.cs`, `LoadMap.cs`: parser/model contract and address domains.
- `src/UrProtect.Core/Aarch64Semantics/`: semantic IR, decoder adapter, CFG, register/resource analysis.
- `src/UrProtect.Core/Application/Protection/`: producer ABI, layout plan, fixups, publisher, and workflow.
- `src/UrProtect.Core/Application/Rehydration/`: Native Image materializer and metadata publication.
- `src/UrProtect.Cli/Commands/CliApplication.cs` and report records: public command/report contract.
- `fixtures/manifest.json`, runtime matrix, native fixtures, and CI workflows: three-runtime evidence contract.

Rollback remains artifact-safe: each stage writes only temporary output, failure removes staged files, and a failed slice is reverted at its commit boundary without reintroducing an alternate production writer or historical test data.

## Review gates before task start

- Parent PRD, design, and this implementation plan are reviewed and contain no unresolved scope decisions.
- Child PRDs state their ordering constraints and independently verifiable acceptance criteria.
- The new artifact ABI/version, diagnostic vocabulary, runtime matrix, and malformed-input policy are explicit.
- The final planning summary is presented; implementation begins only after a subsequent explicit approval and `task.py start`.
