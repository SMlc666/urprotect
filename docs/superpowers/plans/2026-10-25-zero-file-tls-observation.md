# Bounded Zero-File PT_TLS Observation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retain bounded ownerless zero-file PT_TLS markers with either zero or nonzero virtual addresses as structural facts, while keeping semantic TLS projection fail-closed without a unique PT_LOAD owner.

**Architecture:** Narrow the ownerless zero-file exception in `ElfTlsParser.ParseSegments` only by removing the zero-virtual-address restriction. Preserve all existing shape/bounds checks and the ownerless marker (`-1`); do not change `TlsStructuralAdapter` or downstream TLS behavior. Pin the behavior with a parser regression that also proves projection still rejects.

**Tech Stack:** .NET 8, C#, xUnit; existing shell/Python CI fixture checks.

**Spec:** `docs/superpowers/specs/2026-10-25-zero-file-tls-observation-design.md`

## Global Constraints

- PT_TLS metadata remains bounded and fails closed on malformed sizes, ranges, permissions, and alignment.
- Empty templates do not allocate or read file bytes; their file offset must still be inside the bounded source image.
- TLS semantic module projection requires exactly one owning PT_LOAD; no owner is synthesized for a structural observation.
- Do not infer native TLS support from parser acceptance or fixture execution.
- Run Python test commands with ambient `PYTHONPATH` unset.

## Review Focus

- A zero-file marker with a nonzero virtual address must retain `OwningLoadProgramHeaderIndex == -1` and remain unusable by managed TLS projection (Task 1 regression).
- An ownerless zero-file marker with an out-of-bounds file offset must still be rejected (existing `RejectsOwnerlessZeroFileTlsWithAnUnboundedFileOffset`).
- A nonzero-file PT_TLS still needs its unique file/virtual PT_LOAD owner and matching mapping (Task 1 `RejectsOwnerlessNonZeroFileTlsTemplate` plus the existing mapped-template test).
- Checked virtual-range overflow and invalid alignment/permissions must still fail before a structural fact is retained (existing malformed PT_TLS tests).

---

### Task 1: Preserve bounded ownerless zero-file TLS observations

**Files:**
- Modify: `tests/UrProtect.Core.Tests/Structural/ElfParserTests.cs`
- Modify: `src/UrProtect.Core/StructuralElf/ElfTlsParser.cs`

**Interfaces:**
- Consumes: `ElfParser.Parse(ReadOnlyMemory<byte>)`, `TlsSegmentFacts.OwningLoadProgramHeaderIndex`, and `TlsStructuralAdapter.CreateImageModule(ElfFile)`.
- Produces: ownerless zero-file PT_TLS facts for structural observation only; the semantic adapter retains its existing `TlsBindingUnresolved` rejection for those facts.

- [x] **Step 1: Change the nonzero-virtual-address regression to require structural acceptance and semantic rejection.**

  Rename `RejectsOwnerlessZeroFileTlsWithNonZeroVirtualAddress` to `PreservesOwnerlessZeroFileTlsWithNonZeroVirtualAddressForStructuralObservation`. Preserve its fixture mutation that leaves no PT_LOAD owner, `p_filesz == 0`, and a bounded `p_offset`. Assert parse success, `OwningLoadProgramHeaderIndex == -1`, zero file size, the expected nonzero virtual address and memory size; then assert `TlsStructuralAdapter.CreateImageModule` fails with `TlsBindingUnresolved`. Add `RejectsOwnerlessNonZeroFileTlsTemplate` by mutating the candidate PT_LOAD virtual address in `ElfFixture.TlsPie` so the file-backed TLS range has no unique owner; assert the parser still returns `TlsMetadataMalformed`.

- [x] **Step 2: Run the focused regression and verify it fails for the current parser.**

  Run: `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --no-restore --filter FullyQualifiedName~Ownerless`

  Expected: only the changed zero-file/nonzero-address acceptance test fails because the parser returns `TlsMetadataMalformed`; the unbounded-offset and nonzero-file owner negatives pass.

- [x] **Step 3: Broaden only the structural-observation predicate in `ElfTlsParser.ParseSegments`.**

  In `src/UrProtect.Core/StructuralElf/ElfTlsParser.cs`, keep the existing requirements `owners.Length == 0`, `header.FileSize == 0`, and `reader.Contains(header.Offset, 0)`, but remove `header.VirtualAddress == 0`. Update the comment to describe a bounded zero-file PT_TLS structural observation rather than naming a single linker.

- [x] **Step 4: Run the focused and complete structural test suites.**

  Run: `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --no-restore --filter FullyQualifiedName~ElfParserTests`

  Expected: PASS, including the new observation/projection regression and the existing malformed/out-of-bounds TLS cases.

- [x] **Step 5: Verify checks and commit the parser change.**

  Run: `git diff --check`

  Expected: exit 0. Commit only the design, plan, parser, and structural test files with message `fix: retain bounded ownerless zero-file TLS facts`.

- [x] **Step 6: Verify hosted fixture evidence.**

  Push fast-forward to `feat/indirect-control-runtime-evidence`, then explicitly dispatch the full workflow with `gh workflow run ci.yml --ref feat/indirect-control-runtime-evidence` because push events skip nightly lanes. Expected: `fixture-nightly` succeeds, including `zig-musl` baseline and no-op output status/stream equality. Keep separate results for the existing unrelated external sample acquisition failure; do not mark the overall CI gate green from the fixture lane alone.

  Hosted result (run `40226790546` on code commit `9ff0c80`): `fixture-nightly`, `bionic-native-arm64`, `musl-container-smoke`, and `runtime-matrix-native-arm64` succeeded. The uploaded `zig-musl` artifact confirms baseline/output status 0, equal stdout/stderr, and byte-identical source/no-op copy; the nightly evidence gate passed. The overall workflow correctly remains failed because `real-sample-matrix` could not acquire the locked Node.js archive (HTTP 404); the Alpine libarchive download succeeded. Therefore this fixture result is not an overall CI pass.
