# Integrate latest AsmStone and unify AArch64 instruction encoding

## Goal

Update the vendored AsmStone snapshot from the GitLab upstream and eliminate the
remaining dual-track AArch64 instruction-word generation in UrProtect. Every
generated or re-encoded final AArch64 instruction word must cross one
project-owned `Aarch64InstructionEncoder` boundary backed by AsmStone.

The task improves encoder correctness, keeps instruction legality owned by the
generated AsmStone catalog, reduces duplicated opcode knowledge, and makes
future AArch64 instruction-family additions reviewable at one boundary. It does
not move ELF/TLS relocation semantics into AsmStone.

## Background and confirmed facts

- The AsmStone upstream is
  `https://gitlab.com/ursafe/AsmStone`.
- UrProtect currently vendors AsmStone at
  `477e07eb58f26c6c05960a3f5e55a2f3798df8cb`.
- GitLab `main` currently points to
  `ff961cff17c833f404cc6d9cb49065bd99278ecb`, whose merge title is
  `Refactor generated catalog for lazy compilation`.
- The upstream update preserves the existing object-level encode/decode APIs,
  adds stable `A64InstructionCode` and typed descriptor metadata, and changes
  generated catalog compilation to lazy materialization.
- The latest upstream snapshot was independently verified in a temporary clone:
  locked restore, Release build, and `AsmStone.Tests` all pass.
- UrProtect already has a project-owned
  `src/UrProtect.Core/Aarch64Semantics/Aarch64InstructionEncoder.cs`, but
  production code still creates final words manually in:
  `FunctionProtectionCodeEmitter.cs`,
  `ElfLayoutPlanner.cs`,
  `ElfLayoutMaterializer.cs`,
  `Aarch64SemanticFixupEncoder.cs`, and
  `TlsSemanticModels.cs`.
- Recognition and bounded validation masks are valid transition mechanisms.
  Final opcode/immediate assembly and final word patching are the migration
  target.
- The current workspace contains unrelated uncommitted TLS and evidence work.
  This task must start from a clean task base after that work is committed or
  isolated; it must not overwrite or reset those changes.

## Requirements

### R1. Vendor the verified upstream snapshot

- Replace the vendored AsmStone source with the exact upstream commit
  `ff961cff17c833f404cc6d9cb49065bd99278ecb`.
- Preserve the upstream license, notices, source-lock metadata, generated
  catalog provenance, and the existing UrProtect project-reference layout.
- Verify whether `spec/source-lock.json` changes. If it does not change, retain
  the existing locked LLVM/AARCHMRS inputs and record that fact in the task
  evidence.
- Do not fetch an unpinned branch, use a package feed, or silently substitute a
  different AsmStone revision.

### R2. Strengthen the project-owned encoder adapter

- Keep AsmStone model types and generated field names inside
  `Aarch64InstructionEncoder` and its adapter implementation.
- Use stable AsmStone instruction codes and typed descriptors where they improve
  construction or validation; do not expose them through StructuralElf,
  SemanticPlanning, ElfLayout, CLI, or public artifact contracts.
- Extend the project-owned encoding-family/request surface for every final word
  required by current production writers, including:
  - Branch26 and Call26;
  - ConditionalBranch19 and TestBranch14;
  - ADR/ADRP and literal loads;
  - ADD-immediate and unsigned LDR/STR;
  - MOV wide immediate;
  - MOV register;
  - CMP/SUBS-immediate form used by the dispatcher;
  - RET and any other generated control-flow guard form required by the
    current emitter.
- Require source/template decode, family validation, AsmStone encode, AsmStone
  decode round-trip, and UrProtect decoder round-trip for every successful
  result.
- Return zero/no word on failure. Callers must not retain a source word or
  apply a local bitfield fallback after an adapter failure.
- Keep relocation target, addend, page, scale, width, GOT/TLSDESC ownership,
  PT_TLS facts, and address-map calculations in UrProtect.

### R3. Migrate all final production instruction writers

- Route protection dispatcher generation in
  `FunctionProtectionCodeEmitter.cs` through the adapter, including MOV,
  register moves, CMP, unconditional/conditional branches, and RET guards.
- Route layout direct-branch and near-veneer branch generation in
  `ElfLayoutPlanner.cs` through the same adapter.
- Remove the duplicate branch encoder used by
  `ElfLayoutMaterializer.cs`; output validation must validate the planned
  adapter-produced bytes rather than regenerate them through a second writer.
- Route ADD and load/store low-12 materialization in
  `Aarch64SemanticFixupEncoder.cs` through structured adapter requests.
- Route TLSIE literal-load and ADRP/LD64 output generation in
  `TlsSemanticModels.cs` through the adapter.
- Route TLSDESC marker re-encoding and remaining TLS output word generation
  through the adapter.
- Replace source/output mask-merging code that produces final words with
  adapter requests carrying explicit templates and preserved semantic
  operands. Raw masks may remain only for recognition and invariant checks.
- Keep raw source words byte-preserved when no rewrite is required; copying an
  existing word is not a new encoding operation.

### R4. Preserve current ELF/TLS and artifact contracts

- Do not change Payload Frame v3, HostContext ABI v1, Protected Image ABI v1,
  SemanticPlanSnapshot operation meanings, CLI report contracts, or runtime
  evidence schema.
- Preserve all existing TLS model recognition, relocation ownership, PT_TLS
  template/zero-fill, GOT/TLSDESC descriptor bindings, addends, and output
  reparse behavior.
- Adapter failures must map to the existing stable semantic/layout diagnostics.
- Native runtime claims remain independent of this encoder migration. This task
  must not promote a runtime based only on managed encoder tests.

### R5. Add regression and architecture enforcement

- Add focused tests for every new adapter family and every migrated production
  path, including nearest invalid operand/range/width/scale cases.
- Add differential checks for positive words against AsmStone round-trips and
  named GNU assembler/linker oracles where existing fixtures provide them.
- Add a production architecture check that rejects new final AArch64 word
  writers outside the project-owned adapter while allowing bounded recognition
  masks, ELF field serialization, and byte copying.
- Record any intentionally remaining manual encoder with owner, reason,
  replacement slice, and focused test. No remaining writer may gain a new
  instruction family during this task.

## Out of scope

- Parsing GNU assembler text or adding a text assembler frontend.
- Moving ELF relocation, TLS model, GOT, PT_TLS, symbol, or loader semantics
  into AsmStone.
- Adding a second instruction IR, second artifact codec, migration reader, or
  compatibility writer.
- Changing Protected Image ABI, Payload Frame ABI, HostContext ABI, CLI schema,
  or runtime matrix promotion policy.
- Adding non-AArch64 backends.
- Rewriting unrelated C# architecture boundaries that do not generate or
  validate AArch64 instruction words.
- Claiming transformed musl or bionic runtime support from this encoder work.

## Acceptance criteria

- [x] The vendored AsmStone tree and `COMMIT` file match upstream commit
  `ff961cff17c833f404cc6d9cb49065bd99278ecb`; `LICENSE` is retained and
  `spec/source-lock.json` remains unchanged.
- [x] AsmStone locked restore, Release build, and upstream tests pass.
- [x] UrProtect's project-owned adapter supports every final instruction family
  required by the migrated production writers and performs both AsmStone and
  project decoder round-trips.
- [x] Protection dispatcher output no longer uses manual opcode/bitfield
  writers for generated MOV, register move, CMP, branch, conditional branch,
  or RET words.
- [x] Layout branch planning/materialization has one adapter-backed writer and
  no duplicate branch encoder.
- [x] Semantic and TLS output words no longer use local opcode/bitfield
  assembly; relocation and TLS ownership decisions remain in UrProtect.
- [x] Positive and nearest-negative adapter, dispatcher, layout, semantic
  relocation, and TLS tests pass, including malformed and publication-failure
  paths.
- [x] Existing Protected Image, TLS snapshot, layout reparse, CLI, fixture,
  Python, regression, and native contract suites remain green.
- [x] An architecture regression check detects new final-word writers outside
  the adapter and records any explicitly retained transition debt.
- [x] No ABI, report, runtime-evidence, or compatibility claim changes without
  an independently justified contract update.
- [x] The task is implemented in an isolated worktree with clean diff checks
  and can be rolled back without restoring a second production writer.

## Ordering and task boundary

This child task is planning-only until explicitly started. It should begin from
a clean base after the active TLS task's overlapping changes are committed or
isolated. Its implementation consumes the current TLS semantic/layout contracts;
it does not reopen the five-model TLS scope or runtime evidence decisions.
