# Bounded Zero-File PT_TLS Observation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retain bounded ownerless zero-file PT_TLS markers with either zero or nonzero virtual addresses as structural facts, while keeping semantic TLS projection fail-closed without a unique PT_LOAD owner.

**Architecture:** Narrow the ownerless zero-file exception in `ElfTlsParser.ParseSegments` only by removing the zero-virtual-address restriction. Preserve all existing shape/bounds checks and the ownerless marker (`-1`); do not change `TlsStructuralAdapter` or downstream TLS behavior. Pin the behavior with a parser regression that also proves projection still rejects.

**Tech Stack:** .NET 8, C#, xUnit; existing shell/Python CI fixture checks.

**Spec:** `docs/superpowers/specs/2026-10-25-zero-file-tls-observation-design.md`

## Global Constraints

- PT_TLS metadata remains bounded and fails closed on malformed sizes, ranges, permissions, and alignment.
- Empty templates do not allocate or read file bytes; their file offset must still be inside the bounded source image, including the exact EOF offset for a zero-length range.
- TLS semantic module projection requires exactly one owning PT_LOAD; no owner is synthesized for a structural observation.
- Do not infer native TLS support from parser acceptance or fixture execution.
- Run Python test commands with ambient `PYTHONPATH` unset.

## Review Focus

- A zero-file marker with a nonzero virtual address and `p_offset == EOF` must retain `OwningLoadProgramHeaderIndex == -1` and remain unusable by managed TLS projection.
- An ownerless zero-file marker with an out-of-bounds file offset must still be rejected (`RejectsOwnerlessZeroFileTlsWithAnUnboundedFileOffset`).
- A nonzero-file PT_TLS still needs its unique file/virtual PT_LOAD owner and matching mapping (`RejectsOwnerlessNonZeroFileTlsTemplate` plus the existing mapped-template test).
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

  Rename `RejectsOwnerlessZeroFileTlsWithNonZeroVirtualAddress` to `PreservesOwnerlessZeroFileTlsWithNonZeroVirtualAddressForStructuralObservation`. Preserve its fixture mutation that leaves no PT_LOAD owner, `p_filesz == 0`, and set `p_offset` to the exact bounded EOF. Assert parse success, `OwningLoadProgramHeaderIndex == -1`, the retained EOF file offset, zero file size, expected nonzero virtual address and memory size; then assert `TlsStructuralAdapter.CreateImageModule` fails with `TlsBindingUnresolved`. Add `RejectsOwnerlessNonZeroFileTlsTemplate` by mutating the candidate PT_LOAD virtual address in `ElfFixture.TlsPie` so the file-backed TLS range has no unique owner; assert the parser still returns `TlsMetadataMalformed`.

- [x] **Step 2: Run the focused regression and verify it fails for the current parser.**

  Run: `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --no-restore --filter FullyQualifiedName~PreservesOwnerlessZeroFileTlsWithNonZeroVirtualAddressForStructuralObservation`

  Expected: the new acceptance test fails because the parser returns `TlsMetadataMalformed`. Observed before the parser fix; the test output identified the ownerless PT_TLS containment diagnostic.

- [x] **Step 3: Broaden only the structural-observation predicate in `ElfTlsParser.ParseSegments`.**

  In `src/UrProtect.Core/StructuralElf/ElfTlsParser.cs`, keep the existing requirements `owners.Length == 0`, `header.FileSize == 0`, and `reader.Contains(header.Offset, 0)`, but remove `header.VirtualAddress == 0`. Update the comment to describe a bounded zero-file PT_TLS structural observation rather than naming a single linker.

- [x] **Step 4a: Run ownerless TLS acceptance and negative regressions.**

  Run: `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --no-restore --filter FullyQualifiedName~Ownerless`

  Result: PASS, 3/3; this includes the exact-EOF positive, the out-of-bounds empty-file offset rejection, and the nonzero-file owner rejection.

- [x] **Step 4b: Run the complete structural parser test group.**

  Run: `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --no-restore --filter FullyQualifiedName~ElfParserTests`

  Result: PASS, 42/42, including the new observation/projection regression and existing malformed/out-of-bounds TLS cases.

- [ ] **Step 5: Verify the final diff and commit the Task 3 follow-up slice.**

  Run `git diff --check`; include the design, plan, parser, and structural test changes in the separately committed runtime follow-up fixes. The original source-branch parser fix was commit `9ff0c80`; this stacked PR carries the reviewed patch relative to the migrated base rather than importing the old branch history.

- [x] **Step 6: Record the earlier hosted fixture evidence without promoting support.**

  On the original source branch, full workflow run `40226790546` for code commit `9ff0c80` passed `fixture-nightly`, `bionic-native-arm64`, `musl-container-smoke`, and `runtime-matrix-native-arm64`. The uploaded `zig-musl` artifact confirms baseline/output status 0, equal stdout/stderr, and byte-identical source/no-op copy; the nightly evidence gate passed. The overall workflow remained failed because `real-sample-matrix` could not acquire the locked Node.js archive (HTTP 404); the Alpine libarchive download succeeded. This is historical fixture evidence, not a fresh check on the stacked PR and not a TLS-support claim.
