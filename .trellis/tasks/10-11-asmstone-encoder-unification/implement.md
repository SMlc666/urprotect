# Implementation plan

## Preconditions and review gate

- [x] The active TLS task's overlapping changes remain isolated in the original
      worktree; this task uses a clean worktree based on committed HEAD.
- [x] The task was approved and activated with `task.py start` before implementation.
- [x] Upstream commit `ff961cff17c833f404cc6d9cb49065bd99278ecb` is reachable,
      `third_party/AsmStone/LICENSE` is retained, and
      `third_party/AsmStone/spec/source-lock.json` is unchanged from the prior
      pinned LLVM/AARCHMRS inputs.
- [x] The adapter, writer inventory, test inventory, and architecture allowlist
      are recorded in the task design and the AArch64 boundary checker.

## Phase 1: Vendor and baseline

1. Create an isolated task branch/worktree from the clean current base.
2. Update `third_party/AsmStone` to exact upstream commit
   `ff961cff17c833f404cc6d9cb49065bd99278ecb`.
3. Verify `COMMIT`, `spec/source-lock.json`, license files, project references,
   generated catalog provenance, and no untracked source inputs.
4. Run:
   ```sh
   dotnet restore third_party/AsmStone/AsmStone.sln --locked-mode
   dotnet build third_party/AsmStone/AsmStone.sln --configuration Release --no-restore
   dotnet run --project third_party/AsmStone/tests/AsmStone.Tests/AsmStone.Tests.csproj --configuration Release --no-build
   ```
5. Run the existing UrProtect adapter tests and record any compatibility issue
   before changing the adapter.

Rollback point: revert only the vendor commit if the baseline compatibility
check fails.

## Phase 2: Adapter expansion

1. Add project-owned request/result coverage for MOV wide, MOV register,
   CMP/SUBS immediate, RET, and any exact template re-encode operation required
   by current production writers.
2. Internally use AsmStone instruction codes and typed descriptors where useful.
3. Implement bounded operand projection and stable diagnostic mapping.
4. Require AsmStone and UrProtect decoder round-trips on every success.
5. Add focused tests for:
   - valid construction and re-encoding;
   - source/template family mismatch;
   - invalid registers and widths;
   - immediate scale and range;
   - branch alignment/range;
   - backend/round-trip failure;
   - zero word on all failures.

Rollback point: revert adapter-only commit while leaving the vendor snapshot
available for investigation.

## Phase 3: Dispatcher migration

1. Replace `EncodeMovW`, `EncodeMovX`, and `EncodeCmpW` in
   `FunctionProtectionCodeEmitter.cs` with adapter-backed requests.
2. Replace placeholder and final branch/conditional-branch bit assembly with
   structured branch patches finalized through the adapter.
3. Replace the hard-coded RET guard with adapter-backed RET construction.
4. Preserve label resolution, block ordering, register permutation semantics,
   branch range diagnostics, and TLSDESC fall-through adjacency.
5. Add production-path tests for flattened and non-flattened functions,
   register permutation, conditional states, invalid-state guard, and
   out-of-range branches.

Rollback point: revert dispatcher migration if CFG flattening or TLS sequence
contiguity changes.

## Phase 4: Layout and semantic migration

1. Move direct branch and near-veneer encoding in `ElfLayoutPlanner.cs` to
   the adapter.
2. Remove the duplicate branch encoder from `ElfLayoutMaterializer.cs`;
   validate plan bytes by decoding/comparing, never by independently assembling.
3. Move ADD and LDR/STR low-12 encoding from
   `Aarch64SemanticFixupEncoder.cs` to adapter requests.
4. Add focused semantic fixup tests for source-template preservation, width,
   scale, alignment, range, and backend failure.
5. Keep absolute ELF field serialization and non-instruction metadata writers
   unchanged.

Rollback point: revert layout/semantic migration if plan/materializer byte
identity or relocation diagnostics change.

## Phase 5: TLS migration

1. Migrate TLSIE literal-load output encoding.
2. Migrate TLSIE ADRP/LD64 pair output encoding.
3. Migrate TLSLD/TLSGD ADRP/ADD/CALL26 and DTPREL output encoding where the
   current model supports those forms.
4. Migrate TLSDESC ADRP/LD64/ADD marker validation and output generation.
5. Replace local-exec field insertion in current materialization paths with
   adapter-backed template requests, while retaining semantic validation of
   relocation masks and addends.
6. Preserve cross-symbol-table matching, linked retained-reloc validation,
   GOT/TLSDESC ownership, PT_TLS equivalence, and canonical snapshots.
7. Add nearest malformed and publication-rollback tests for each migrated form.

Rollback point: revert one TLS family at a time; do not add a fallback writer.

## Phase 6: Architecture gate and documentation

1. Add or update a production architecture scan that identifies final
   AArch64 word writers outside `Aarch64InstructionEncoder.cs`.
2. Define the narrow allowlist for recognition masks, ELF serialization, and
   unchanged-byte copying.
3. Record any remaining manual writer with owner, replacement scope, and test;
   reject new families in those writers.
4. Update backend quality/error-handling specs and task research with the final
   inventory.
5. Run the full verification matrix.

Verified implementation evidence:

- AsmStone `COMMIT` is `ff961cff17c833f404cc6d9cb49065bd99278ecb`; locked restore,
  Release build, and `AsmStone.Tests` pass. `spec/source-lock.json` did not
  change and `LICENSE` remains vendored.
- The project adapter owns Branch26/Call26, ConditionalBranch19,
  TestBranch14, ADR/ADRP, literal, ADD, unsigned LDR/STR, MOV wide, MOV
  register, CMP/SUBS-immediate, and RET families. Every successful result
  performs AsmStone and project decoder round trips; failures return zero.
- Dispatcher, layout branch planning/materialization, semantic low-12 fixups,
  TLSIE literal/pair paths, local-exec field paths, and existing dynamic/TLSDESC
  paths use adapter-backed requests. Raw masks remain only for recognition and
  invariant checks; binary writes only serialize adapter-produced words or ELF
  metadata.
- `scripts/check-aarch64-encoding-boundary.py` plus
  `tests/test_aarch64_encoding_boundary.py` enforce the production boundary and
  reject a deliberate opcode/immediate writer fixture.

## Required verification

### Focused

- AsmStone locked restore/build/tests.
- `dotnet test UrProtect.sln --configuration Release --no-restore --filter`
  for adapter, semantic relocation, dispatcher, layout, and TLS tests.
- GNU assembler/linker differential fixture checks where applicable.
- Architecture scan for final AArch64 word writers.
- `git diff --check`.

### Full managed and repository

```sh
dotnet restore UrProtect.sln --locked-mode
dotnet build UrProtect.sln --configuration Release --no-restore
dotnet test UrProtect.sln --configuration Release --no-build --no-restore
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
python3 tests/test_protected_image_evidence.py
```

### Native and evidence

```sh
make -C native/urprotect-runtime test CC=aarch64-linux-gnu-gcc
make -C native/urprotect-launcher test CC=aarch64-linux-gnu-gcc
python3 ./.trellis/scripts/task.py validate 10-11-asmstone-encoder-unification
git diff --check
```

Verification record:

- AsmStone locked restore/build and `AsmStone.Tests` passed; the vendored
  snapshot is `ff961cff17c833f404cc6d9cb49065bd99278ecb`, with license and
  source-lock inputs unchanged.
- UrProtect Release restore/build passed with zero warnings and errors; all
  385 managed tests passed.
- The AArch64 boundary checker, architecture boundary checker, and their
  deliberate-negative fixtures passed.
- Fixture validation covered 13 PR cases; regression validation covered 20
  cases; protected-image evidence tests passed 9/9; Python discovery passed
  296 tests with 7 environment-gated skips.
- The native runtime Makefile test passed with
  `CC=aarch64-linux-gnu-gcc`. The native launcher Makefile test passed on the
  AArch64 host, including static-PIE checks, launcher self-test, and payload
  handoff integration.
- No ABI, runtime-evidence, or compatibility claim was promoted by this
  encoder task. Musl and bionic runtime claims remain owned by the TLS task
  and their existing environment gates.

Required runtime evidence remains owned by the TLS task and must not be
reclassified by this task. Run applicable native checks only to ensure the
encoder migration does not regress them.

## Review gates

- Vendor snapshot review: exact upstream commit, provenance and license.
- Adapter review: no AsmStone types leak into project-owned contracts.
- Writer review: no final opcode/bitfield writer remains outside the adapter
  unless explicitly documented transition debt.
- Semantic review: relocation/TLS policy remains UrProtect-owned.
- Regression review: output bytes, diagnostics, snapshots, and publication
  behavior remain stable.
- Final quality review: clean build, focused tests, full tests, architecture
  scan, task validation, and diff hygiene.

## Commit sequence

1. `vendor: update AsmStone to ff961cff`
2. `refactor: expand project-owned AArch64 encoder adapter`
3. `refactor: route protection dispatcher through AsmStone encoder`
4. `refactor: route layout and semantic fixups through encoder`
5. `refactor: route TLS materialization through encoder`
6. `test/docs: enforce one final AArch64 encoding boundary`

Each commit must build and pass its focused gate. Do not commit unrelated
current TLS task changes.
