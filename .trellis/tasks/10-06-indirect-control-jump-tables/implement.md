# Implementation plan

## Ordered checklist

### Phase 0: Correct the analysis boundary first

1. Change generic `NoOpPipeline`/CLI validation to structural validation by default; make instruction analysis explicit rather than a wrapper prerequisite.
2. Isolate or retire the legacy whole-image `Aarch64Analyzer` from wrapper validation, packing, layout, rehydration, and protection publication.
3. Update `NoOpPipelineTests`, CLI/report tests, and decoder-failure tests to prove unrelated executable bytes and decoder availability do not affect structural validation.
4. Preserve selected-function `Aarch64FunctionAnalyzer` behavior and add an explicit scope contract for any remaining observation-only analysis.

### Phase 1: Demand-driven resolver contracts

5. Add a bounded `ElfStructuralIndex` projection over existing `ElfFile` facts; do not create a second ELF parser or whole-image disassembler.
6. Add typed indirect-expression, value-range, ownership, and target-resolution records using the shared semantic plan/snapshot extension contracts.
7. Add an affine expression normalizer for selected-function producer chains ending in indirect branches/calls.
8. Add bounded value-set evaluation for index/range proofs and exact/bounded target classification.

### Phase 2: Jump-table discovery and rewriting

9. Recognize the first compiler-generated relative/absolute table patterns from selected-function data-flow, including ADRP/LDRSW/ADD/BR and equivalent forms.
10. Model table base, entry width, signedness, scale/addend, bounds, default target, ownership, and rewrite policy.
11. Resolve private selected tables, shared tables, external tables, and runtime-owned tables through separate preservation/copy/retarget strategies.
12. Rewrite table entries and table references through `AddressMap` and semantic fixups; keep original addresses or install typed stable veneers when a target is not movable.
13. Add typed runtime-target translation bindings without implementing an implicit runtime fallback; promotion requires the workflow/runtime evidence contract.

### Phase 3: Integration and evidence

14. Attach indirect target and jump-table extensions to the existing `SemanticRewritePlan` and canonical snapshot; do not add a parallel raw-byte model.
15. Pass only resolved/preserved/deferred contracts to the shared ELF layout planner/materializer; rehydration must not rediscover code semantics.
16. Add positive fixtures for bounded switches, relative/absolute tables, function-pointer tables, selected/unselected targets, shared-table copy/retarget, and stable veneers.
17. Add nearest-negative fixtures for missing bounds, malformed entries, ambiguous ownership, external tables, out-of-range targets, oversized target sets, and missing runtime bindings.
18. Add target-selection evidence fields and independent glibc/musl/bionic runtime rows through the parent workflow, without promoting one runtime from another.

## Bounded evidence slice: compiler-shaped jump table and negative proof

This slice does not complete the child or promote indirect calls, other table encodings, musl, or bionic. It owns only the existing private signed-32-bit relative table row and its workflow evidence.

- [x] Extend the native fixture to select all four bounded targets in a deterministic in-function order, accumulate the exact results `17, 103, -7, 91`, and return status `91` only after the complete ordered trace matches.
- [x] Add a workflow-level nearest-negative fixture that writes architectural `X0`/`W0` after `CMP`/`B.HI` and before `LDRSW`; retain the existing malformed/out-of-closure table negative.
- [x] Retain source/transformed handoff JSON and actual baseline/target stdout/stderr bytes; store hashes and handoff-bound results, then independently recompute comparisons in the evidence checker.
- [x] Parse the negative producer JSON and bind the stable diagnostic family/message and actual failed producer stage; require no Protected Image, Native Image, or loader artifacts.
- [x] Add refreshed-manifest tampering tests for equality, stream hash/content, status, fake diagnostic, and missing negative artifact mutations.
- [x] Update the backend evidence contract, fixture/regression evidence inventory, and child acceptance artifacts without completing this child.
- [x] Run focused/full managed tests, native jump-table E2E and checker, Python evidence/full suite, fixture/regression and architecture/encoding checks, and `git diff --check`.

### Validation record for this slice

- `dotnet build UrProtect.sln --configuration Release --no-restore` — passed, zero warnings/errors.
- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-build --no-restore --filter 'FullyQualifiedName~RelativeJumpTable'` — passed, 4 tests.
- `dotnet test UrProtect.sln --configuration Release --no-build --no-restore` — passed, 456 tests.
- `make -C native/urprotect-runtime jump-table-fixture jump-table-index-clobber-fixture` — passed.
- `scripts/run-indirect-control-e2e.sh --tier pr --artifact-root .artifacts/indirect-control/slice-20261015-final` — passed; native glibc producer, rehydration, handoff, four-case behavior oracle, and both negatives.
- `python3 -m unittest discover -s tests -p 'test_rehydration_evidence.py' -v` — passed, 13 tests.
- `python3 -m unittest discover -s tests -p 'test_*.py'` — passed, 366 tests.
- Fixture, regression matrix, architecture boundary, AArch64 encoding boundary, and `git diff --check` commands passed.

This slice leaves the child in progress: indirect calls, other table encodings/ownership families, and musl/bionic runtime rows remain open.

### Per-target output address evidence follow-up (2026-10-15)

This follow-up closes only the evidence gap for the existing private signed-32-bit relative jump-table row; it does not complete the child.

- [x] Add typed planner-derived per-entry bindings to the existing `ElfLayoutPlan` / `ElfLayoutEvidence` contract. Each binding records table and entry identity/index/source range, source target and base, unique layout-map-derived output target and base, encoding parameters, and source/output encoded values.
- [x] Validate source bytes and address relationships during planning/materialization; fail closed for missing or ambiguous address-map decisions, target mappings outside file-backed executable PT_LOAD ranges, and missing/duplicate/mismatched entry bindings.
- [x] Version the additive layout-evidence contract to schema 2. Protected Image ABI and semantic-snapshot wire version are unchanged.
- [x] Extend the evidence checker to recompute each output target/base from retained layout mappings, verify source ELF symbols/table rows/bytes, compare rewritten edits and Native Image table bytes, and reject refreshed-checksum tampering of target VAs, entry index/offset, map ranges, and missing/duplicate bindings.
- [x] Add focused layout materializer positives/negatives and Python nearest-negative checksum-refreshed cases.

Validation for this follow-up:

- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore --filter 'FullyQualifiedName~UrProtect.Core.Tests.Layout.ElfLayoutTests' --logger 'console;verbosity=minimal'` — passed, 13 tests.
- `python3 -m py_compile scripts/check-indirect-control-evidence.py tests/test_rehydration_evidence.py && python3 -m unittest discover -s tests -p 'test_rehydration_evidence.py' -v` — passed, 23 tests.
- Retained `.artifacts/indirect-control/slice-20261015-final` rehydration checker — passed; the root remains read-only.
- Retained indirect-control checker — correctly rejected the old schema-1 evidence because it predates required schema-2 per-target bindings; the root was not modified. The stale `.artifacts/indirect-control/pr` root was not used.

### Bounded evidence slice: project-built GLOB_DAT imported indirect call (2026-10-16)

This slice records one behaviorally necessary AArch64 glibc HostContext imported call and its successful GenericRehydrationEngine publication. It does not complete the child or promote arbitrary indirect calls, other import/owner families, or non-glibc runtimes.

- [x] Make `getpid` necessary to the fixture result: `urp_entry` passes zero through an ADRP/GOT-LDR/BLR (`x9`) sequence and returns 97 only when the imported call yields a positive PID; otherwise it returns 96. Preserve the caller LR across the non-leaf call.
- [x] Build/copy the project fixture and independently parse Source Image and Native Image PT_LOAD/PT_DYNAMIC/GNU-hash/dynsym/DT_RELA facts. Bind selected `urp_entry` to dynsym index 3 (VA/file offset `0x1d8`, size 60), undefined `getpid` to dynsym index 2, and its sole non-PLT `R_AARCH64_GLOB_DAT` (type 1025) to the aligned writable 8-byte GOT at VA `0x1fff8` / file offset `0xfff8`.
- [x] Retain the native AArch64 glibc HostContext source and transformed handoff JSON, stream bytes and hashes, runtime identity, Source/Protected/Native Image digests, producer/rehydration records, readelf output, and a closed SHA256SUMS manifest. Both actual handoffs release successfully and report entry/process status 97; source and transformed stdout/stderr are byte-identical and empty.
- [x] Exercise the typed semantic import-owner snapshot contract through `DynamicImportOwnerWorkflowTests`: successful project fixture -> producer -> snapshot -> Protected Image -> GenericRehydrationEngine Native Image publication, independent source dynsym/RELA/GOT binding, plus checksum-refreshed call/GOT/RELA/dynsym/address-map/owner-edge/producer-order tampering rejection.
- [x] Retain an actual corrupted Protected Image rehydration negative. Flipping only its final digest byte returns process status 5 with `ProtectedImageIntegrityMismatch` at rehydration; the failed record says entry `not-run`, and no Native Image or loader handoff is published. The evidence checker validates the negative from retained command/record/exit status/files rather than trusting a generic success witness.
- [x] Add a dedicated bounded evidence parser/runner and checksum-refreshed tamper/truncated-ELF tests. The checker requires the source oracle plus exact source/native import facts, independent process/handoff/stream comparisons, producer/rehydration bindings, negative rollback, and a closed SHA256SUMS manifest.
- [x] Keep the retained report's embedded `acceptanceState=scoped-observation-pending-independent-review` unchanged as historical metadata; after the checker-only runtime-identity remediation, a scoped fresh review passed (details below). No broader runtime or generic-feature acceptance is claimed.

Validation and retained evidence:

- `scripts/run-dynamic-import-e2e.sh --tier pr --artifact-root .artifacts/dynamic-import/recovery-glibc-20261018d` — passed on native AArch64 / glibc 2.43. Its fixture `make` stage verified the completed build was up to date (`Nothing to be done`); the end-to-end run produced both source/transformed handoffs and the observed integrity-failure negative.
- `.artifacts/dynamic-import/recovery-glibc-20261018d/runtime.host-context.dynamic-import.glibc.host-context-entry/dynamic-import-evidence.json` — retained checked report. Source SHA-256 `844546d3561ff89113c960b1ef18f6b668b1375f0efff656bef9b21a52515bea`; Protected Image `849cf17432b927d93f3e818b72722e8aec3813e9c722d1c439459c59324626ee`; Native Image `76d6a405f5810ee3b57f9f8906c2c554c7bdb9ffce008c99f7b692767e73871b`.
- Source handoff SHA-256 `b6d7926b5f2b020065acf7febe4cdc85b1f3ba643e95da35344f91bb3bb7e6bb`; transformed handoff `d697bb5b0bc2e6f239c966ca917928ed1b59f7f2c83c2eb1ebc43be6a1a70e01`. Both handoffs report passed/release passed/status 97. All four captured source/target stdout/stderr files are 0 bytes with SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Negative record SHA-256 `48aadf5e81ee9deecd52dc45878e2b63e8bf7267c32ec8e1270631d0e91efdc4`; checked report SHA-256 `27a23fcb8340dcad98241f0ce48d736374176d27b5af944ebdfc47e71d4294ed`; closed manifest SHA-256 `b690b7489bd94e5898e255d8c140ba7c29c217df0f37a6468635c97010037468`.
- `python3 -m unittest discover -s tests -p 'test_dynamic_import_evidence.py' -v` — passed, 5 tests after the runtime-identity regression; `test_rehydration_evidence.py` — passed, 23 tests; `DynamicImportOwnerWorkflowTests` — passed, 14 cases.
- Fixture (13 cases), regression matrix (24 cases), architecture-boundary production/self-test and unit tests, AArch64 encoding-boundary production/self-test and unit tests, evidence checker, and `git diff --check` passed.

### Fresh-review P1 remediation: GLOB_DAT runtime identity (2026-10-18)

- [x] The dynamic-import checker now invokes `tls_runtime_identity.verify_identity(..., verify_current_process=True)`, which validates the recorded libc/loader file digests and compares all identity fields with the current native AArch64 glibc runtime. It fails closed if native verification is unavailable; the portable `verify_artifact_identity` API and TLS-matrix policy are unchanged.
- [x] The Python regression keeps a valid identity positive control, then changes only its version to `glibc 2.99`, recomputes `identitySha256`, updates the evidence report, and refreshes the closed manifest. The real producer verifier is exercised while only its `identify_native_glibc` measurement boundary is mocked; unchanged libc/loader facts cannot make the false version pass.
- [x] The retained evidence root remains read-only. Its `runtime-identity.json` SHA-256 is `55f09ac44518ee6db91fd290d9b2743007d8dc82d4d1ed5db9c3421fef7700cb`; `dynamic-import-evidence.json` SHA-256 is `27a23fcb8340dcad98241f0ce48d736374176d27b5af944ebdfc47e71d4294ed`; `SHA256SUMS` SHA-256 is `b690b7489bd94e5898e255d8c140ba7c29c217df0f37a6468635c97010037468`.

Validation for this remediation:

- `python3 -m unittest discover -s tests -p 'test_dynamic_import_evidence.py' -v` — passed, 5 tests.
- `python3 scripts/check-dynamic-import-evidence.py .artifacts/dynamic-import/recovery-glibc-20261018d/runtime.host-context.dynamic-import.glibc.host-context-entry --tier pr` — passed natively; ran without `--write-report`, and the three retained-root hashes above were unchanged.
- `python3 -m py_compile scripts/check-dynamic-import-evidence.py tests/test_dynamic_import_evidence.py` — passed.
- `git diff --check` — passed.
- Fresh independent review returned a scoped PASS for this runtime-identity remediation. The parent reran all five focused Python tests and the retained checker; runtime-identity/report/SHA256SUMS hashes remained unchanged. The reviewer did not rerun native E2E, which the checker-only change did not affect.

The child remains in progress. The later static-callback section addresses the bounded function-pointer mapping criterion; additional indirect-call/table-owner families, refreshed jump-table Native Image target-binding evidence, independent musl/bionic evidence, and the final child report remain open.

### Bounded nearest-negative slice: out-of-range relative table target

This follow-up closes only the open out-of-range target negative for the existing private signed-32-bit relative table. It does not complete the indirect-control child or parent requirements.

- [x] Add a bounded fixture mutation of one signed 32-bit table entry; retain the byte-exact pre-mutation input ELF, mutated source ELF, table/base/index/value report, and source hashes.
- [x] Independently parse the retained ELF symbols, PT_LOAD ranges, table entry and relative base; recompute a target that lies outside every PT_LOAD memory image and executable file-backed range. Keep the malformed/out-of-closure control pointed at a distinct executable in-image function outside `urp_entry`, and preserve the checked-index-clobber control.
- [x] Require the actual `protect-image` producer invocation to fail at `protected-image-producer` with `IndirectTargetUnresolved` and the stable out-of-executable-PT_LOAD message, retaining exact command, stdout/stderr, structured stage, and process status; reject all protected/native/loader publication artifacts.
- [x] Add checksum-refreshed semantic tampering tests for forged relative entry values, computed target/range facts, diagnostic claims, and publication claims.
- [x] Reuse the independently accepted schema-2 four-case positive evidence without rerunning its native source/transformed execution. Bind its copied bytes, evidence-root manifest hash, child manifest, and outer root manifest.
- [x] Update only the child PRD/implementation plan and the owning backend evidence-spec entry; keep the child and parent in progress.
- [x] Run focused managed/Python evidence checks, exact native producer flow, source/load-range inspection, architecture boundary, and diff hygiene.

Validation for this follow-up:

- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore --filter 'FullyQualifiedName~RelativeJumpTable' --logger 'console;verbosity=minimal'` — passed, 7 tests.
- `python3 -m unittest discover -s tests -p 'test_rehydration_evidence.py' -v` — passed, 29 tests, including checksum-refreshed out-of-range entry/value/target, diagnostic, and publication tampering cases.
- `python3 -m py_compile scripts/check-indirect-control-evidence.py scripts/mutate-indirect-jump-table.py tests/test_rehydration_evidence.py && bash -n scripts/run-indirect-control-e2e.sh` — passed.
- `make -C native/urprotect-runtime jump-table-fixture jump-table-index-clobber-fixture` — passed on native AArch64.
- `scripts/run-indirect-control-e2e.sh --tier pr --artifact-root .artifacts/indirect-control/out-of-range-negative-20261015T192633Z-22010 --reuse-positive-root .artifacts/indirect-control/check-final-20261015T142238Z-13922` — passed; reused the independently accepted schema-2 four-case positive without rerunning it, and executed all three actual failed producer negatives.
- `python3 scripts/check-indirect-control-evidence.py .artifacts/indirect-control/out-of-range-negative-20261015T192633Z-22010 --tier pr --unit runtime.indirect-control.jump-table.glibc.host-context-entry` — passed; outer SHA256SUMS is `8bc8133424b174debedd894c3bd898f680b72a468750aa258c959e6654c8cf7d`.
- Producer out-of-range row: input SHA-256 `bf5f9266255bfb8382455cb298534361cb1abb2690938098f9b1e254df996d06`; mutated source SHA-256 `a15d6121abe4ae14846731f8b4861db13702342d8e4f34a55f583c7f082c3fbf`; mutation report `6d792f9d6303c1de179dcfd689d11fdc22cdb53d692c460ef46a954bc8b99e4c`; producer command `a23ae625e8b2efded784fd9befdd3a3a9eb3862eb7fa6211f97bfef41aa2669e`; producer JSON `d787512bbb60ac7a9d33feee6d233b59d91ecd500c0ec5af39d81c4f44803283`; stage record `92553ba97f1a989742b5f785dc2afc311c2d31927e487ee69da6710441254389`; exit-status file `7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d`. The entry is index 0 at table VA/file offset `0x330`; target base is `0x2d8`; signed value changes from 0 to `0x7fffffe0`, independently recomputing `0x800002b8`, outside every PT_LOAD memory range. Actual producer exit is 4, first failure is `protected-image-producer`, and the diagnostic is `IndirectTargetUnresolved: A signed relative jump-table entry resolves outside an executable PT_LOAD range.` No Protected Image, Native Image, or loader handoff artifact exists.
- Independent positive origin `.artifacts/indirect-control/check-final-20261015T142238Z-13922` remains unchanged; its inner manifest SHA-256 is `844433bc16fc954c3de7c2fd85be08c6a2c25d4bb2561c59bbaf5698265da6b2`, Native Image SHA-256 `33766fb3d7dcd4778ce78f1f9a2d13a7525b9a6d44c1dff765921bdc2d4db681`; copied-file equality passed. Its independent review result is retained in `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/5e435ba8-1890-4171-ab5c-a054c49b67b2_trellis-check_output.md` (SHA-256 `6aeafe36f4b3884bcb220edd5991cbc8fcc1e60b8c2fd44285a7ae9f322c3053`).
- `python3 scripts/check-architecture-boundaries.py` and `--self-test`, `python3 scripts/check-aarch64-encoding-boundary.py` and `--self-test`, and their 7 focused unit tests — passed. `git diff --check` — passed; no files staged.

This closes only the out-of-range nearest-negative evidence item. The child remains in progress; the bounded static-callback mapping slice is recorded later, while other indirect-call/table-owner families, broader runtime rows, and the final report remain open.

### Bounded nearest-negative slice: externally imported jump table (2026-10-15)

This slice adds only a source-built fail-closed negative. It does not implement external-table support, change indirect-call admission, claim any runtime behavior for the imported table, or complete the child/parent task.

- [x] Add `host_context_external_jump_table_fixture.S` with a bounded `CMP W0,#3` / `B.HI` guarded GOT acquisition, indexed signed `LDRSW`, relative target-base `ADR`/`ADD`, and `BR`; link its undefined dynamic `STT_OBJECT` import through one exact non-PLT `R_AARCH64_GLOB_DAT` slot. Existing positive/malformed/out-of-closure/out-of-range/index-clobber fixtures and accepted evidence roots were not edited.
- [x] Run the actual `protect-image` producer on the built source before recording the expected result. It exits 4 at `protected-image-producer` with `IndirectTargetUnresolved: The selected instruction does not match the promoted relative jump-table family.` and publishes no Protected Image, Native Image, rehydration, or handoff.
- [x] Add an independent bounded PT_DYNAMIC/dynsym/GNU-hash/DT_RELA/PT_LOAD/instruction-dataflow parser to the evidence checker. It binds the selected dynamic function, imported symbol identity, non-PLT relocation and symbol index, unique writable file-backed GOT pointer slot, index guard, GOT-slot load, signed indexed read, relative target expression, and BR. It explicitly records no Source Image table-payload range and does not mistake the GOT slot for table storage.
- [x] Integrate a separate `negative-external-table` through the existing actual-producer/closed-manifest runner and checker. The retained source, producer argv/hash/exit/stdout/stderr/stage/diagnostic, dynamic-symbol/relocation report, independently recomputed owner facts, and no-publication facts are bound in the fresh root.
- [x] Add checksum-refreshed tampering coverage for imported dynsym identity, relocation owner/type, GOT address and instruction link, indexed-read/BR dataflow, diagnostic, and failure stage. Keep all existing negative evidence paths distinct.
- [x] Update only the child progress statement, the owning backend evidence contract, fixture evidence inventory, and regression artifact inventory. The child and parent remain in progress.

Validation for this follow-up:

- Actual fixture build: `make -C native/urprotect-runtime external-jump-table-fixture` — passed. The retained ELF is ET_DYN/EM_AARCH64; `.dynsym[2]` is undefined `OBJECT GLOBAL DEFAULT` `urp_external_jump_table` (`st_value=0`, size 0); `.dynsym[4]` is defined global default `FUNC urp_entry` at VA `0x2d0`, size 72. `.rela.dyn` contains the sole exact non-PLT `R_AARCH64_GLOB_DAT` (`r_offset=0x1fff8`, `r_info=0x200000401`, symbol index 2, addend 0). The 8-byte GOT pointer slot maps to file offset `0xfff8` in a writable PT_LOAD. The checked dispatch instructions at `0x2d0..0x2ec` prove W0 bound 3, ADRP/LDR of that exact slot into X9, `[X9,W0,UXTW #2]` LDRSW, ADR base `0x2f0`, ADD into X1, and BR X1.
- Actual producer hypothesis probe — passed as an observed negative, exit 4, `firstFailureStage=protected-image-producer`, exact diagnostic above, source SHA-256 `c3584835e47f6a1bdd9c17f62bb83a145f7aa9af2ec6c5be877e2508f436f442`; CLI build SHA-256 `27cf73829c698da9b9614e7e8c41163e4bb88ce0451df5d993b0916a9b0efb50`.
- Fresh retained run `.artifacts/indirect-control/external-table-negative-final-20261015T230806Z-c521ea55` reused `.artifacts/indirect-control/check-final-20261015T142238Z-13922` through the existing copy/hash gate without rerunning positive execution or writing the origin; the origin inner `SHA256SUMS` remained `844433bc16fc954c3de7c2fd85be08c6a2c25d4bb2561c59bbaf5698265da6b2`. The fresh outer manifest SHA-256 is `e4084d4e1971f84e68f8e3f6156bef76812515898ed4636cf500dd3fc134aedf`.
- `scripts/run-indirect-control-e2e.sh --tier pr --artifact-root .artifacts/indirect-control/external-table-negative-final-20261015T230806Z-c521ea55 --reuse-positive-root .artifacts/indirect-control/check-final-20261015T142238Z-13922` — passed; the checker accepted the existing schema-2 positive copy and all four actual producer negatives.
- `python3 scripts/check-indirect-control-evidence.py .artifacts/indirect-control/external-table-negative-final-20261015T230806Z-c521ea55 --tier pr --unit runtime.indirect-control.jump-table.glibc.host-context-entry` — passed; external row exit 4 and no Protected Image, Native Image, rehydration, or loader/handoff artifact.
- Refreshed-manifest tampering tests independently reject changed import identity, relocation symbol/type, GOT slot, GOT-load/read/BR links, diagnostic and failed stage.

Open: external-table support and provider/runtime resolution remain unimplemented; ambiguous tables, imported function-pointer support, indirect-call admission, musl/Bionic runtime evidence, and broader parent TLS/CFI gaps remain open. No task status was changed and no files were staged or committed.

## Validation commands

- `dotnet build UrProtect.sln --configuration Release --no-restore`
- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore`
- `python3 -m unittest discover -s tests -p 'test_*.py'`
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`
- `python3 tests/test_regression_matrix.py`
- `git diff --check`
- `./scripts/run-protection-e2e.sh --tier pr --runtime glibc`
- `./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc`

Native musl/bionic target-selection rows are parent/runtime-child gates and must retain explicit environment/toolchain evidence. The local architecture-boundary tests must pass before any semantic-domain implementation is enabled.

## Risky files and rollback points

- `src/UrProtect.Core/Pipeline/NoOpPipeline.cs`, `src/UrProtect.Cli/CliApplication.cs`, and `src/UrProtect.Core/Aarch64/Aarch64Analyzer.cs`: first correction boundary; preserve structural validation and report compatibility while removing the global scan prerequisite.
- `src/UrProtect.Core/Aarch64/FunctionAnalysis.cs`, `Aarch64SemanticPlanFactory.cs`, `SemanticPlanSnapshot.cs`: selected-function and canonical handoff contracts.
- `src/UrProtect.Core/Protect/FunctionProtectionService.cs`: selected-function integration and protection closure.
- `src/UrProtect.Core/Elf/ElfLayout.cs`: physical table/code/veneer placement only; no semantic target guessing.
- `src/UrProtect.Core/Protect/ProtectedImageV1.cs` and workflow artifacts: versioned operation/evidence evolution remains a parent workflow boundary.

Rollback order:

1. revert indirect resolver/table changes while retaining the analysis-boundary correction;
2. keep structural validation decoder-independent;
3. never restore the whole-image scanner as a silent production fallback;
4. publish no artifact when a required target/preservation contract is invalid.

## Start gate

Do not run `task.py start` or implement product code until the parent architecture correction and this selected-function/demand-driven design are explicitly reviewed and approved.

### Fresh independent review remediation: external-table bounds edge (scoped PASS)

A fresh independent review accepted the source-byte safe-default proof and checksum-refreshed unsafe-branch regression for this bounded fail-closed evidence slice. This does not accept external-table support, ambiguous ownership, imported function pointers, other runtimes, or the child/parent task. Child and parent task statuses remain unchanged and in progress.

- [x] Require the source-derived `B.HI` destination to equal the selected function's final bounded two-instruction default-return block, after the indexed-read/relative-dispatch chain; verify retained bytes decode exactly as the fixture's `MOV W0, #-1; RET`, leaving no control path from that block back into the chain.
- [x] Add a checksum-refreshed raw-ELF regression that rewrites the actual `B.HI` immediate to target the indexed `LDRSW`, refreshes dependent source/fact/producer/manifest claims, and asserts rejection for the unsafe bounds destination rather than stale hashes.
- [x] Add the retained out-of-range negative result to `tests/regression-matrix.json` and state the safe-default/bypass requirement in backend evidence guidance.
- [x] Update the four-negative PRD acceptance criterion after the scoped external-row proof was independently accepted; keep ambiguous ownership and external-table support open.
- [x] Independent reviewer accepted the strengthened bounds-edge proof with a scoped PASS.

The retained fixture's final default block is `MOV W0, #-1; RET`; `MOV W0, #91; RET` is case 3 immediately before it. The checker follows the source ELF and preserves that distinction. No native positive evidence was rerun or altered; the accepted positive origin and fresh external-negative root remain read-only.

Validation for this remediation:

- `python3 -m unittest tests.test_rehydration_evidence.IndirectControlEvidenceTests -v` — passed, 28 tests, including the intact evidence-positive control and checksum-refreshed raw-ELF `B.HI`-to-`LDRSW` rejection.
- `python3 -m py_compile scripts/check-indirect-control-evidence.py tests/test_rehydration_evidence.py` and regression-matrix JSON parsing — passed.
- `python3 scripts/check-indirect-control-evidence.py .artifacts/indirect-control/external-table-negative-final-20261015T230806Z-c521ea55 --tier pr --unit runtime.indirect-control.jump-table.glibc.host-context-entry` — passed read-only without write-report mode. Fresh-root manifest SHA-256 remained `e4084d4e1971f84e68f8e3f6156bef76812515898ed4636cf500dd3fc134aedf`; positive-origin manifest and Native Image hashes remained `2cadb273de236fc1f3fc011166924d378071952b50de7ec7440ff44bd6b129b0` and `33766fb3d7dcd4778ce78f1f9a2d13a7525b9a6d44c1dff765921bdc2d4db681`.
- `python3 scripts/validate-regression-matrix.py tests/regression-matrix.json --tier pr` — passed; `python3 tests/test_regression_matrix.py` — passed, 5 tests; `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr` — passed, 13 fixture cases.
- `git diff --check` — passed; `/tmp/urprotect-external-review-block-20261015T232505Z` remains present and unchanged; no files staged.

The bound run handoff is `external-table-checker-guard-remediation-handoff.md` in the caller-designated output location. No native E2E ran, and no native positive evidence was rerun or altered. External-table support/provider execution, indirect-call admission, imported function-pointer support, non-glibc runtime evidence, and other open child/parent requirements remain out of scope.

### Fresh independent review remediation gates (2026-10-19)

This scoped remediation addresses only the two BLOCK findings in the fresh review report `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/897eb6f8-7ccf-49b4-83df-a8198f9bc079_trellis-check_output.md`. Preserve all previously accepted slices, the read-only accepted evidence roots, unrelated dirty worktree state, outer Protected Image ABI v1, and active task status.

1. **Section-linked RELA owner proof gate.** For every owner relocation used to claim a shared table, derive the function/site owner only when `SHT_RELA.sh_info` is a bounded exact match for the owner function's `st_shndx`, the real owner section is executable and file-backed, the full function range is contained in that section, and the relocation instruction plus four-byte width remains inside both the function and section. Any malformed, mismatching, or ambiguous candidate discards the complete ownership proof. Carry typed function-section identity and header bounds through the current `URP-SPS3` snapshot; canonical snapshot validation checks target/owner section identity and VA/file containment, while `GenericRehydrationEngine` independently binds every carried owner row to source section headers, linked RELA rows, and function symbols before publication. Keep the nested snapshot single-version (no dual decoder).
2. **Observer behavioral provenance gate.** Retain each observer helper invocation's actual process status in explicit process-status evidence, and bind the captured stdout/stderr bytes and process status in behavior evidence with checksums. The shared checker validates source/transformed image digests, exact HostContext loader identity, passed/release state, release ordering, absence of failure stage, process/entry status agreement, and all four stream observations (including the fixture's expected empty streams). Add self-contained checksum-refreshed mutations for observer image/process/loader/release-order fields, observer-source stdout, and a valid-index `sh_info`/target-section mismatch with coordinated metadata where possible; each must fail for the semantic inconsistency, not a stale manifest.
3. **Verification gate.** Run focused managed owner/snapshot/publication tests; focused and full Python suites; Release managed build and full Release tests; fixture/regression/architecture/encoding checks; `git diff --check`; fresh native shared-table E2E/checker in a new artifact root; and the rehydration evidence checker. Keep generated caches cleaned, report infrastructure failures without switching protocols, do not stage/commit/change task status, and request a fresh independent review rather than claiming acceptance.

Remediation remains scoped to these two gates; no other table encodings, external-table support, imported function-pointer support, runtime rows, or parent TLS/CFI criteria are promoted.

### Validation record for the review remediation (2026-10-19)

- [x] Add resolver, URP-SPS3, snapshot-validation, and publication-boundary checks for exact section-linked RELA owner proof; add focused managed positives, source `sh_info` mismatch fail-closed coverage, snapshot mismatch rejection, and a forged self-reported section fact rejected by rehydration against the parsed source ELF.
- [x] Extend observer evidence with helper process exit status, process-status files, captured stream hashes/sizes, exact image hashes, and strict loader/status/release checks; add checksum-refreshed observer image/process/loader/release-order/stdout mutations and a coordinated source-ELF `sh_info`/metadata mutation. All four focused Python tests pass.
- [x] `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore --filter 'FullyQualifiedName~SharedJumpTableOwnerWorkflowTests|FullyQualifiedName~RelativeJumpTable' --logger 'console;verbosity=minimal'` — passed, 12 tests.
- [x] `dotnet test UrProtect.sln --configuration Release --no-restore --logger 'console;verbosity=minimal'` — passed, 466 tests.
- [x] `python3 -m unittest tests.test_shared_jump_table_evidence -v` — passed, 4 tests; `python3 -m unittest discover -s tests -p 'test_*.py'` — passed, 396 tests.
- [x] Fixture matrix (13 cases), PR regression-matrix validation, architecture boundary and self-test, AArch64 encoding boundary and self-test, shell syntax, focused Python compile, and `git diff --check` passed.
- [x] Fresh native AArch64/glibc shared-table E2E and both evidence checkers passed in `.artifacts/indirect-control/review-remediation-final-20261019T170000Z/runtime.indirect-control.shared-table.glibc.host-context-entry`. SHA256SUMS: `696793bb9674f9bd6c21540383cf8ebf36ff7068dd16c6fc176d78a7de38d5bf`; Source Image: `138e96724ef11294ada8e96803ca45cd02d3d038708134ffff8e8aaacf9fd473`; Native Image: `908a454354be3f6dcd6614b06704e2d17ac04ead1fe0491b30a8f99446217a42`.
- [x] A fresh independent read-only `trellis-check` returned scoped PASS for the two prior blockers only; full report: `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/998f37d9-0bb2-4d4e-8c70-6fba8605ede1_trellis-check_output.md`. It independently verified section-linked RELA owner facts through URP-SPS3/source ELF, semantic rejection of raw `sh_info` and snapshot tampering before publication, and checksum-refreshed observer process/image/loader/release-order/stdout tampering. It recomputed every retained manifest hash and passed both exact-root checkers, Release build plus 466 managed tests, 396 Python tests, fixture/regression/architecture/encoding checks, and diff hygiene. It did not rerun native E2E; that remains the implementation-produced artifact at the root above. Retained accepted roots remain read-only; no task status transition, staging, or commit was performed. This PASS is scoped to the named fixture only.

## Completed scoped Phase 2.10–12 slice: shared-table copy-and-retarget

This scoped execution is authorized against the active child task. It replaces the unsupported private/in-place assumption with one source-built, bounded signed-32-bit relative shared-table path. It does not complete the broader child or parent task.

### Ordered contracts and implementation steps

1. **Ownership proof before policy.** Extend the bounded structural ELF model with section-linked relocation/symbol facts needed by the controlled fixture. Derive `Shared` only from a validated second reference outside the selected function; a global/default-visible symbol alone, missing sections/relocations, or incomplete owner inventory remains `Ambiguous`. The selected resolver records exact table-base producer addresses and owner facts. The current fixture’s unproven `SelectedFunctionPrivate`/`InPlace` claim must be removed.
2. **Canonical semantic handoff.** Add typed owner evidence and complete table-reference producer/site records to the jump-table extension. Advance only the nested snapshot to `URP-SPS2/v3`; v1/v2 are rejected and there is no dual decoder. Protected Image ABI stays v1. Snapshot validation rejects ambiguous/missing/conflicting ownership or producer sites for a copy policy.
3. **Layout copy contract.** Carry source range, distinct planned clone range, reference bindings, entries, and policy into layout planning/evidence. Allocate one file-backed read-only clone (not W/X), map it through the planned address map, leave original table bytes intact, encode copied signed-32-bit entries from unique mapped targets and output target base, and validate exact clone/edit/source-reference relationships before publication.
4. **Selected reference retargeting.** Re-encode only the selected function’s persisted table-base producer chain to the clone. Every generated AArch64 word is emitted and round-tripped through `Aarch64InstructionEncoder`; unsupported page/low-12 placement or mapping fails before publication. Unselected observer references remain unchanged at the original table.
5. **Native fixture and observed proof.** Build one shared-table ET_DYN fixture with selected `urp_entry`, unselected `urp_observer`, and both references tied to one bounded four-entry signed-relative table. Execute both functions in source and transformed images; retain actual stage/results/handoffs/streams, assert source bytes are unchanged, selected clone/targets are mapped, and observer still uses the original.
6. **Independent validation and nearest negatives.** Extend the independent evidence checker to parse source table/owner references, clone range/permissions, one selected reference edit, output target mappings, and native bytes/behavior. Add checksum-refreshed focused fail-closed cases for invalid/missing clone placement and retarget bounds; external-table behavior remains the existing independent fail-closed negative.
7. **Focused and full verification.** Run Release build and relevant managed tests, full managed suite if feasible, focused/full Python suite, fixture/regression/architecture/encoding gates, fresh native AArch64/glibc source-versus-transformed E2E and exact checker in a new root, and `git diff --check`. Never mutate retained accepted evidence roots; do not stage, commit, or change task status.

If a prerequisite prevents the complete vertical slice, stop at a verified backward-safe milestone and report the exact remaining boundary. Do not widen support or claim unrelated ownership, function-pointer, external-table, runtime, TLS, CFI, or task criteria.

## Next bounded slice: exact static function-pointer call preservation

**Change boundary:** The current selected-function analyzer accepts narrowly proven HostContext callbacks and typed loader-owned GLOB_DAT calls, but does not resolve compiler-shaped BLR through a statically relocated same-image function pointer. Add only one exact static call mode. Transform urp_entry; preserve one same-image, non-preemptible local callback at its source VA; do not admit arbitrary BLR, move the callback, synthesize veneers, or claim cross-runtime support. The existing getpid row remains a separate runtime-owned import control.

### Ordered implementation and acceptance

1. **Version authority (resolved).** Before this slice, source canonicalization was URP-SPS3/version 3 and runtime-compatibility.md contained stale URP-SPS2 wording. The typed static-call owner is a nested schema change: the current contract is URP-SPS4/version 4 with one strict decoder rejecting v1-v3 (no historical/dual decoder); Protected Image ABI v1 remains unchanged. Runtime and quality guidance plus contract inventory now identify this single current schema.
2. **Build the bounded source fixture.** Add a compiler-built AArch64 ET_DYN fixture with selected exported urp_entry, unselected exported urp_observer, and one hidden/local STT_FUNC callback target. urp_entry stores a volatile pointer to that function, reloads it, invokes via BLR, and returns 97 only for the expected callback result (otherwise 96). Retain static relocations with the pinned fixture command. Confirm final linked ELF/symbol/relocation bytes independently; do not rely on compiler source shape alone.
3. **Resolve only the exact static shape.** Extend selected-function analysis to accept a BLR only if bounded same-basic-block reaching definitions prove the ADRP+ADD -> exact stack-slot store/load -> target-register chain with no clobber, merge, or intervening control-flow ambiguity. Require the corresponding section-linked relocation pair and an exact defined non-preemptible STT_FUNC identity; prove the target VA equals the decoded address expression and is executable/file-backed. Preserve the existing aggregate-work bounds and fail-closed behavior for all other indirect branches.
4. **Carry typed static ownership.** Add a canonical static-call owner extension distinct from SemanticDynamicImportCall and RuntimeResolved. It binds call/register, complete ordered producer chain, section-header/table identity (sh_link/sh_info), relocation pair/site/type/addend/symbol index, exact symbol-table row/properties, target source range, and explicit preserve-original identity mapping. Canonical sort/uniqueness/limits and tamper validation are required.
5. **Revalidate at publication.** GenericRehydrationEngine independently re-decodes selected source instructions and re-derives the call's reaching chain, section-linked relocation rows, target symbol identity/range, and mapping policy from the source ELF. Require complete per-BLR owner coverage and reject missing snapshot/owner, omitted/forged owner, altered ADRP/ADD or stack chain, wrong sh_link/sh_info, symbol/relocation mismatch, and a forged/missing identity map before Native Image publication. Bound aggregate validation work.
6. **Emit safely.** Keep the callback target unselected and fixed at source VA. Re-encode the selected caller's ADRP producer to that original target from the output instruction PC with Aarch64InstructionEncoder; preserve the validated low-12 ADD and stack round-trip. Keep BLR as a returning call with mapped fallthrough. Any absent target-map decision or out-of-range ADRP must fail before publication; no manual bitfield fallback.
7. **Native behavior evidence.** Add a row-specific runner/checker for the compiler fixture. Execute source and transformed urp_entry and urp_observer under native HostContext; bind exact source/protected/native hashes, source symbol/section/relocation facts, selected target/mapping, process/entry statuses, streams, release, and runtime identity. Require status 97 and measured source/transformed equivalence; prove the observer and callback remain at their original source locations. Retain a closed manifest at a fresh artifact root. Do not mutate existing accepted roots.
8. **Nearest-negative set.** The following matrix is the bounded static-callback negative set. Each source-ELF theory case first proves the mutated ELF still parses, then asserts no callback resolution, the exact `IndirectTargetUnresolved` proof-boundary diagnostic, and failure before Protected Image role/bytes can be published. Snapshot/rehydration cases refresh the nested snapshot digest and outer artifact digest before asserting no Native Image publication. No native loader is invoked for failing publication paths.

   | Required boundary | Exact mutation / test | Boundary evidence |
   | --- | --- | --- |
   | Missing relocation row | `missing-relocation-row` in `StaticLocalCallbackProofRejectsEachNearestUnsafeInputBeforePublication` | Move ADD RELA `r_offset` off its exact producer site; static owner proof reports the incomplete pair. |
   | Malformed relocation pair | `malformed-relocation-pair` in the same theory | Duplicate the ADD row at the ADRP site; reject non-unique pair/site ownership. |
   | Relocation section `sh_link` | `sh-link` | Retarget linked symbol table to `.dynsym`; no section-linked static owner is accepted. |
   | Relocation section `sh_info` | `sh-info` | Retarget relocation target section away from caller `.text`; exact pair/owner validation rejects it. |
   | Relocation symbol index | `symbol-index` | Forge the ADD symbol index while retaining other row fields; pair cannot identify one exact target. |
   | Relocation type | `relocation-type` | Replace `R_AARCH64_ADD_ABS_LO12_NC` with the ADRP relocation type. |
   | Relocation addend | `addend` | Change only the ADD addend from zero to one. |
   | Symbol owning section | `target-owning-section` | Change only the local target symbol's section index. |
   | Non-function target class | `non-function-target` | Change the relocation target type from `STT_FUNC` to `STT_OBJECT`. |
   | Undefined target | `undefined-target` | Clear the target symbol's section index to `SHN_UNDEF`. |
   | Preemptible target | `preemptible-target` | Change binding/visibility to global/default-visible. |
   | Out-of-range target | `out-of-range-target` | Move the function range across `.text` end while keeping the VA inside executable file-backed `PT_LOAD`; test asserts those independent range facts. |
   | Unmapped target | `unmapped-target` | Keep the function within executable `.text` but split its bytes out of every file-backed executable `PT_LOAD`; test asserts section-valid but unmapped. |
   | Changed ADRP expression | `changed-adrp-expression` | Re-encode ADRP to another page without changing its relocation identity. |
   | Changed ADD expression | `changed-add-expression` | Change only ADD's low-12 expression while retaining the same instruction/relocation site. |
   | Target-register clobber | `target-register-clobber` | Replace the expected load with `MOVZ X1,#0`, then retain `BLR X1`; assert exact decoded clobber/call sequence. |
   | Altered stack slot | `altered-stack-slot` | Change LDR from the exact spill slot `SP+40` to `SP+48`; assert the changed load operand. |
   | Conflicting CFG branch | `conflicting-control-flow-branch` | Insert `B.EQ +8` so ADD has a predecessor bypassing ADRP; reject conflicting reaching definitions. |
   | Arbitrary runtime pointer | `arbitrary-runtime-pointer` | Replace ADRP/ADD with `MOV X1,X0`/NOP while keeping the later spill/reload/BLR; reject absent source owner provenance. |
   | Missing executable sections | `without-sections` | Clear section-table authority; reject before the caller is treated as one bounded executable source range. |
   | Forged owner section identity | `RehydrationRejectsRefreshedSnapshotWithForgedTargetSectionIdentity` | Re-encode snapshot and Protected Image digests, then reject before Native Image publication. |
   | Omitted owner | `RehydrationRejectsOmittedStaticCallbackOwnerWithRefreshedSnapshotAndArtifactDigests` | Re-encode refreshed snapshot/artifact digests; completeness revalidation rejects before Native Image publication. |
   | Forged callback identity map | `RehydrationRejectsRefreshedForgedCallbackIdentityMapBeforeNativePublication` | Forge map identity and matching owner/indirect-target identities, refresh snapshot/artifact digests, then source-ELF revalidation rejects. |
   | Missing callback identity map | `RehydrationRejectsMissingCallbackIdentityMapWithRefreshedSnapshotAndArtifactDigests` | Remove the map row from canonical bytes and refresh nested snapshot plus outer artifact digests; decode rejects before Native Image publication. |
   | Missing map at snapshot authoring | `SnapshotRejectsMissingCallbackIdentityMapBeforeProtectedImageEncoding` | `SemanticPlanSnapshotCodec.Create` refuses an incomplete identity map before encoding any Protected Image operation. |
   | Output ADRP encoding failure | `OutputStaticCallbackAdrpEncodeFailurePreventsProtectedImagePublication` | Inject an encoder returning `TargetOutOfRange` for the emitted callback ADRP; assert failure/no Protected Image role or artifact bytes. |

   The existing positive `StaticLocalCallbackFlowsThroughStrictSnapshotAndPublicationRevalidation` and the ordinary unresolved-BLR fail-closed coverage remain in force. This matrix is specific to the fixed local callback; it does not broaden support for moved callees, generic tables, external/runtime pointers, or veneers.

   **Observer-evidence semantic tamper matrix.** An intact copied-evidence positive passes. Every negative refreshes the synthetic evidence `SHA256SUMS` before checking semantic rejection.

   | Required observer contract | Tests | Exact negative coverage |
   | --- | --- | --- |
   | Process-status files bind both handoffs | `test_observer_source_process_status_file_mismatch_is_rejected_after_manifest_refresh`; `test_observer_target_process_status_file_mismatch_is_rejected_after_manifest_refresh` | Source or transformed status file disagrees with its own handoff. |
   | Process/entry status is expected 97 and summary-bound | `test_observer_process_entry_mismatch_is_rejected_after_manifest_refresh`; `test_observer_entry_status_must_be_exact_contract_status_after_manifest_refresh`; `test_observer_summary_process_status_is_bound_to_status_files_and_handoffs`; `test_observer_summary_entry_status_is_bound_to_handoff` | Reject handoff process/entry disagreement, jointly forged non-97 status, or source/native summary status detached from the retained handoff and status file. |
   | Source/native hashes bind retained bytes | `test_forged_observer_source_image_hash_is_rejected_after_manifest_refresh`; `test_forged_observer_native_image_hash_is_rejected_after_manifest_refresh` | Reject checksum-refreshed source or Native Image hash forgery. |
   | Release contract exactness | `test_observer_release_status_must_be_passed_after_manifest_refresh`; `test_observer_summary_release_status_is_bound_to_handoff`; `test_observer_release_order_is_rejected_after_manifest_refresh`; `test_transformed_observer_release_order_is_rejected_after_manifest_refresh`; `test_observer_failure_stage_is_rejected_after_manifest_refresh` | Require passed release, source/native release order, null first failure stage, and matching summary values. |
   | Exact HostContext loader | `test_observer_loader_identity_is_exact_after_manifest_refresh` | Reject an alternate transformed-observer loader identity after handoff/summary hash refresh. |
   | Single-artifact stream mutations (stale summary digest) | `test_each_nonempty_observer_stream_is_rejected_after_manifest_refresh` | Mutate one source/transformed stdout/stderr file at a time and refresh the outer `SHA256SUMS` only; the corresponding summary stream hash remains stale, so these cases prove the empty-stream check runs before digest consistency but are not coherent-pair coverage. |
   | Coherent paired stdout mutation | `test_coherent_nonempty_observer_stdout_pair_is_rejected_after_manifest_refresh` | Set source and transformed stdout to identical non-empty bytes, update `sourceStdoutSha256` and `nativeStdoutSha256`, regenerate the complete `SHA256SUMS`, prove `CHECKER.verify_manifest(root)` passes, then require semantic rejection because source stdout must be empty. |
   | Coherent paired stderr mutation | `test_coherent_nonempty_observer_stderr_pair_is_rejected_after_manifest_refresh` | Set source and transformed stderr to identical non-empty bytes, update `sourceStderrSha256` and `nativeStderrSha256`, regenerate the complete `SHA256SUMS`, prove `CHECKER.verify_manifest(root)` passes, then require semantic rejection because source stderr must be empty. |

   These tests supplement the selected-entry contract checks and intact positive copy; they do not rewrite or regenerate the accepted older evidence root.
9. **Verification.** Run focused analyzer/snapshot/owner/publication/emitter tests, full Release managed suite, focused and full Python suites, fixture and regression validation/tests, architecture and AArch64 encoding boundaries/self-tests, shell syntax, source readelf/disassembly checks, fresh native AArch64/glibc E2E plus exact-root checker, rehydration checker, and git diff --check. Request a fresh independent read-only review after the implementation handoff. No staging/commit/task-status changes.

**Explicit non-goals:** selected/moved static callees, dynamic R_AARCH64_RELATIVE pointer objects, generic function-pointer arrays, arbitrary/external runtime pointers, imported-table support, veneer/runtime translation, TLS/CFI evidence expansion, musl/bionic evidence, and parent/child completion.

### Implementation progress (acceptance remains incomplete)

The following implementation and review notes record the contract state at their original dates; the P1 remediation recorded below is the current nested snapshot contract.

- Reconciled the nested semantic snapshot contract to URP-SPS4/version 4 with one strict decoder rejecting versions 1-3. Protected Image ABI v1 and the Python evaluator's opaque bounded-snapshot contract are unchanged.
- Implemented a distinct typed static local callback owner, bounded ADRP/ADD/stack-store/load/BLR owner proof, section-linked RELA and exact symbol/section checks, canonical v4 encode/decode/validation, source-ELF ownership revalidation, logical-output/final Native Image publication checks, and preserve-original-VA ADRP emission. The callback target remains outside the selected function patch.
- Added the compiler-built AArch64 ET_DYN fixture, source relocation/symbol/disassembly checks, static callback integration/tamper tests, strict rejection tests for v1-v3, Python checker unit tests, and a dedicated native E2E runner/checker with selected entry plus unselected observer handoffs. The focused static-owner suite now passes 28/28, including the complete step-8 nearest-negative matrix.
- Fresh native AArch64/glibc entry+observer E2E and both independent evidence checkers pass in `.artifacts/static-function-pointer/2026-10-16-static-callback-05/compat.protection-host-context-fixture.glibc.static-function-pointer-local-callback`. The checker follows the Native Image `urp_entry` B stub to the physical emitted region (VA `0x20150`) and independently decodes its live ADRP/ADD/stack/BLR chain at `0x20168`/`0x20178`; it does not accept the unreachable original-VA BLR as transformed code. Entry and observer source/transformed process/entry statuses are 97, and the callback remains at VA `0x1e0` with identical bytes. Source/Protected/Native SHA-256 values are `7a57790609c5cd7ced64a8e1fcd4f4f311fd779bf121cdefb0b1533fb886ef57`, `b70beb04468fecdbd86b8131912e93a8fa468c46b6d896e0c2cc0c314e15e699`, and `f6268726e93cd87ac5e705e7318a107fd3076529c2017575b53b8d4186748f3d`; closed SHA256SUMS is `05921593304a5aeedfb36a3282fbbb02477de2ca1866f6d7dc23624279afc246`.
- Broad validation before the final coherent-pair stream regressions: focused managed owner suite 28/28; full Release managed suite 496/496; focused Python evidence suite 21/21; full Python suite 417/417; full Release solution build (0 warnings/errors); fixture matrix (13 cases), PR regression-matrix validation and tests (5), architecture and AArch64 encoding boundary checks/self-tests plus 7 focused unit tests, Python compilation, shell syntax, and `git diff --check` passed. These counts predate the two coherent-pair stream tests.
- Follow-up after those two tests: the implementer reported the focused Python evidence suite at 23/23. The fresh reviewer inspected both tests and the checker validation order and returned a scoped PASS, but did not rerun the suite, broader suites, or native E2E. Do not attribute the earlier 21/417 results to the post-addition test state.
- The accepted static callback root was checked read-only with `--verify-manifest`; inner `SHA256SUMS` remains `05921593304a5aeedfb36a3282fbbb02477de2ca1866f6d7dc23624279afc246`. The read-only checker independently accepts source/native hashes, callback VA `0x1e0`, entry/observer status 97 and empty streams. No native E2E was run in this remediation, no accepted artifact root was modified, and no files were staged.
- The static same-image callback slice's identified observer-evidence blocker is closed by the final scoped review, and the PRD's bounded static/runtime mapping criterion is recorded as satisfied using this row plus the independently checked GLOB_DAT/getpid row. The child and parent remain in progress: ambiguous/incomplete table ownership, external-table support, other table families, cross-runtime rows, broader TLS/CFI evidence, and the final reports remain open. No broader feature support or task completion is claimed.

### Narrow ownership-confidence and publication-revalidation follow-up (2026-10-16)

- Closed only the narrow safe-default gap: `SemanticJumpTableExtension` now defaults omitted ownership to `Ambiguous`, never `SelectedFunctionPrivate`. Added a constructor regression for that default. Existing explicit factory classification remains authoritative.
- For a proven bounded in-image table and exact selected ADRP/ADD use with incomplete ownership inventory, preserve `Ambiguous`, retain the read-only clone-and-retarget path, and leave source table/unselected references unchanged. Global/default-visible binding/visibility and missing/stripped owner metadata do not prove `Shared`, private, external, or runtime ownership. Malformed/conflicting selected-site RELA evidence fails before Protected Image publication.
- Rehydration/publication now independently decodes selected source-function instructions and re-resolves each jump table, comparing the derived range, entries, ownership, selected producer chain, and owner references with the carried v4 snapshot. It checks the selected source instruction/reference relation and rederives carried owner evidence; an encoded snapshot alone cannot assert those facts. Aggregate decoded-instruction, table-entry, owner-reference, and relocation/function validation work remains bounded. At that follow-up, no snapshot wire change was made; a later review identified that the current enum values had changed historical wire meanings while retaining SPS4. The P1 remediation below supersedes that state by preserving v4 ownership ordinals and advancing only the nested contract to URP-SPS5/v5; Protected Image ABI v1 remains unchanged.
- Focused regressions cover global/default-visible table with selected-owner-only evidence (retains `Ambiguous`, clones, preserves original/observer bytes, selected use targets clone), stripped section/owner evidence (same safe clone behavior), conflicting selected-site relocation (publication rejected), tampered selected ADD producer (rehydration rejected), omitted owner evidence (rehydration rejected), and omitted constructor ownership (defaults `Ambiguous`).
- Verification after the final code edit: focused Release managed filter `SharedJumpTableOwnerWorkflowTests|RelativeJumpTable|SemanticPlanSnapshotTests` passed 41/41; Release solution build passed with 0 warnings/errors; full Release solution tests passed 502/502. Focused shared-table Python evidence tests passed 4/4 and full Python suite passed 419/419. Fixture manifest validation passed (13 cases); regression matrix validation and tests passed (5 tests); architecture-boundary production/self-test and AArch64-encoding-boundary production/self-test passed; shared-table runner shell syntax and `git diff --check` passed.
- Fresh native AArch64/glibc shared-table E2E plus both exact-root checkers passed at `.artifacts/indirect-control/owner-revalidation-final-20261016T101841Z/runtime.indirect-control.shared-table.glibc.host-context-entry`. Both read-only rehydration and shared-table checkers also passed against the previously accepted `.artifacts/indirect-control/review-remediation-final-20261019T170000Z/runtime.indirect-control.shared-table.glibc.host-context-entry`; that accepted root was not modified.
- Scope remains deliberately incomplete: external/imported tables, other encodings, generic function pointers, other runtimes, and parent/child task completion remain out of scope. PRD acceptance and task statuses are unchanged; no stage/commit/push was performed.

### P1 remediation: preserve v4 enum ordinals and reject prior snapshot contract

- Restored the original serialized `SemanticJumpTableOwnership` values exactly: `SelectedFunctionPrivate=0`, `Shared=1`, `External=2`, and `RuntimeOwned=3`; appended `Ambiguous=4` without shifting any legacy value.
- Advanced the nested canonical snapshot to strict URP-SPS5/version 5. The decoder continues to accept only the current magic/version and rejects v1-v4; no compatibility decoder or migration path was added. Protected Image ABI v1 and ambiguity-safe clone behavior remain unchanged.
- Added focused assertions for every legacy ordinal and appended ambiguity, a current SPS5 jump-table round-trip, and a real shared-table payload relabeled as its prior SPS4/v4 header to prove it is rejected rather than reinterpreted.
- Validation: focused managed snapshot/shared-table filter passed 46/46; `dotnet clean UrProtect.sln --configuration Release && dotnet build UrProtect.sln --configuration Release --no-restore` passed with 0 warnings/errors; full Release `dotnet test UrProtect.sln --configuration Release --no-build --no-restore` passed 506/506; full Python suite `python3 -m unittest discover -s tests -p 'test_*.py'` passed 419/419. Fixture manifest validation (13 cases), PR regression-matrix validation and tests (5), architecture-boundary production/self-test, AArch64-encoding-boundary production/self-test, and `git diff --check` passed. The task remains in progress; no task status, staging, commit, or push was performed. The retained shared-table root was not regenerated or edited.

### External provider DSO positive — staged implementation plan

The user selected a project-built provider DSO as the way to close the provider-contract ambiguity. This work remains scoped to one AArch64 provider DSO and one external signed-relative table family. The external-table acceptance criterion stays open until all managed and native stages, independent review, and evidence checks pass.

#### Slice A — provider fixture and explicit HostContext identity contract

1. Build a dependency-free AArch64 `ET_DYN` provider with an exact `DT_SONAME`, a 16-byte file-backed read-only defined `STT_OBJECT` containing four signed-32 relative offsets, and four bounded provider-local executable target functions. Build a consumer/observer fixture whose undefined object import resolves through one exact non-PLT GLOB_DAT slot and whose guarded dispatch uses the table pointer as the relative base.
2. Add explicit trusted-provider configuration to the native adapter: host-supplied path plus expected SONAME, GNU build ID, and SHA-256. Snapshot a bounded no-follow regular file, compare SHA-256 before ELF parsing, then load provider and consumer from sealed descriptors into one fresh isolated glibc link-map namespace with local visibility. Reject pre-existing same-SONAME mappings by policy; a different-SONAME global symbol collision must not affect isolated binding. Retain provider ownership until consumer release. Never obtain path or identity from the image or environment, and do not rely on base-namespace check-then-load for binding correctness.
3. Extend native preflight only for a consumer that declares exactly one configured provider SONAME. Reject missing, extra, duplicate, or mismatched provider dependencies and the exact table-symbol GLOB_DAT import when its provider dependency is absent, before memfd or loader activity. Immediately after parsing and classifying `DT_NEEDED`, reject provider-dependent consumers carrying any of `DT_VERSYM`, `DT_VERNEED`, `DT_VERNEEDNUM`, `DT_VERDEF`, or `DT_VERDEFNUM` with `URP_STATUS_UNSUPPORTED`, before generic symbol-version traversal or provider-specific RELA accounting; retain the RELA-side version-tag rejection as defense-in-depth. This provider-only precheck must not change the accepted non-provider libc version-requirement path. Compare the undefined consumer `STT_OBJECT` by name/type/binding/visibility/undefined identity, not by requiring nonzero `st_size`: GNU ld may emit `st_size == 0`; the verified provider definition and runtime mapping establish the 16-byte table range. Enforce one aggregate 8 MiB work budget before load-range lookups, GNU-hash traversal, dynsym iteration, and bounded string comparisons; use an indexed PT_LOAD set rather than rescanning headers per symbol. Keep existing libc singleton/pair rules intact; reject arbitrary dependencies, RPATH/RUNPATH, and nonempty `LD_LIBRARY_PATH`, `LD_PRELOAD`, or `LD_AUDIT`. No provider-dependent image may reach consumer memfd creation without a matching trusted provider contract.
4. Add source/observer native HostContext fixture tests and nearest negatives for missing configuration; byte-mutated missing `DT_NEEDED` with configured and unconfigured adapters; wrong provider hash/SONAME; malformed provider/table ownership; exact and one-under aggregate-work limits; and namespace collisions. Assert rejection negatives leave memfd and loader-attempt counters unchanged. Prove an unrelated different-SONAME global same-symbol DSO does not replace the isolated provider, while retaining the same-SONAME collision policy. Retain actual statuses, streams, provider identity/mapping, GOT/table bytes, and target trace. This slice proves native source-loader behavior only; it does not claim managed transformation or matrix promotion.
5. Update backend runtime compatibility, native runtime README, and child design/implementation documentation for the exact provider identity, dependency, namespace/lifetime, environment, st_size, work-budget, and glibc-only contracts. Run a clean Release native build, native AArch64/glibc `make -C native/urprotect-runtime test`, provider self-test, readelf/relocation/permission inspection, missing-dependency and exact/over-budget regressions, and `git diff --check`. Keep native loader evidence separate from managed transformation evidence and request independent review; do not change task status or promote the child.

#### Native Slice A implementation and verification handoff

The native adapter slice now implements the bounded host-pinned provider path described above. SHA-256 is checked before provider parsing; provider/consumer loading uses sealed descriptors and a fresh isolated glibc namespace; provider mapping, read-only table bytes, consumer namespace/link-map, and GOT binding are verified before handle publication. The provider parser uses an aggregate 8 MiB work budget and indexed PT_LOAD ranges. The consumer import is rejected unless exactly one configured provider SONAME is present; undefined consumer `STT_OBJECT.st_size == 0` is accepted because the provider's defined object and runtime binding establish its 16-byte range.

Verification completed on native AArch64/glibc 2.43:

- `make -C native/urprotect-runtime clean && make -C native/urprotect-runtime -j2 test` — passed, including the external-provider self-test and the complete native runtime suite.
- `readelf -d -Ws -l -r` confirmed the provider has no dependencies or relocations, exact SONAME, a 16-byte read-only table definition, and bounded executable targets. Consumer inspection confirmed exactly one provider `DT_NEEDED`, one non-PLT `R_AARCH64_GLOB_DAT`, and an undefined `STT_OBJECT` with `st_size == 0`.
- The provider self-test passed exact-budget acceptance and one-under-budget fail-closed checks; SHA mismatch did not invoke provider parsing; a byte-mutated missing-`DT_NEEDED` consumer was rejected for both configured and unconfigured adapters while a different-SONAME same-symbol object was globally preloaded, with unchanged memfd/loader counters. Same-SONAME collision rejection passed, and the different-SONAME global definition did not displace the isolated provider.
- `git diff --check` — passed.

This is native source/loader evidence only. Managed external-table production/rehydration, independent review, and the external-table acceptance criterion remain open; do not mark the child or parent complete or change task status.

The validation-order follow-up rejects provider consumers with each version-tag variant (`DT_VERSYM`, `DT_VERNEED`, `DT_VERNEEDNUM`, `DT_VERDEF`, and `DT_VERDEFNUM`) immediately after dependency classification and before generic version traversal or provider RELA accounting. The focused self-test asserts `URP_STATUS_UNSUPPORTED`, zero generic version-parser and provider-RELA calls/work, no provider parse, and unchanged memfd/loader-attempt counters; the unmodified positive provider consumer and generic libc version path remain covered.

Validation for the follow-up on native AArch64/glibc 2.43:

- `make -C native/urprotect-runtime clean && make -C native/urprotect-runtime -j2 test` — passed from a removed build directory. The provider positive still dispatched all four targets plus the default; all native runtime tests passed, including `HostContext libc symbol-version self-test: PASS`.
- `make -C native/urprotect-runtime external-provider-self-test` — passed the exact provider regression executable; all five version-tag mutations were rejected before generic version parsing, provider RELA accounting, provider parsing, memfd creation, or loader attempts. Its self-test summary reported `failClosedNegatives:18`.
- `make -C native/urprotect-runtime test` — passed again after updating the self-test summary count.
- `git diff --check` — passed after the implementation and documentation edits.

This remains native source/loader evidence only; the external-table acceptance criterion and managed transformation/rehydration stages remain open. No task status or retained evidence root was changed.

#### Slice B — managed provider semantics and publication

6. Add an explicit provider-file input to `protect-image` and `rehydrate-image`; bind provider content identity and symbol/table/target facts into a typed `SemanticExternalJumpTable` extension. Advance the nested snapshot strictly to URP-SPS6/version 6 with one decoder rejecting v1-v5; preserve the outer Protected Image ABI v1.
7. Recognize only the exact bounded consumer sequence, exact undefined object, one non-PLT GLOB_DAT relocation/GOT slot, and provider-local signed-32 table/target family. Keep provider addresses in their own identity domain; do not create fake source-image address-map rows or clone the provider table.
8. Reparse consumer and provider at rehydration/publication; independently bind dynamic metadata, symbol rows, provider hash/build-id/SONAME, read-only table range/bytes, entries, targets, bounds/default edge, full producer chain, and selected output mapping. Reject missing/duplicate/changed/tampered facts and bound aggregate work.
9. Re-encode only the moved selected consumer GOT-page producer using the existing AsmStone-backed encoder; preserve provider table/target bytes and prove an unselected observer still uses the provider object.

##### Current bounded implementation boundary (proof-only)

Implement only a demand-driven selected-function proof query on the existing jump-table resolver, with explicitly supplied verified provider facts. Reuse current structural ELF, dynamic-binding, selected-function CFG, bounded-range, and instruction-decoder owners; add only minimal immutable typed proof input/output in the architecturally correct namespaces. Prove the exact selected `BR` consumer, safe bounded compare/default path, ordered ADRP/GOT-LDR/LDRSW/ADD/BR producer chain, unique undefined-object/GLOB_DAT/writable-GOT relation, allowed direct provider dependency, and provider content/table identity. Provider addresses remain in provider identity space. This seam must not add CLI provider options, snapshot serialization, protect/rehydrate admission, production pipeline wiring, or a second resolver/parser; existing external-table production remains rejected until later publication/emitter work. Add one deterministic four-entry signed-32 positive and nearest fail-closed proof negatives for metadata, dependency/provider identity, bounds/default safety, register clobbers, width/scale, and range. Leave acceptance boxes and task status unchanged.

#### Slice C — evidence and acceptance

10. Run a fresh native AArch64/glibc source-versus-transformed HostContext positive for selected entry and observer, all four cases plus safe default; retain provider/consumer/protected/native hashes, runtime identity, loader mapping, GOT/table/target facts, status, streams, and release observations.
11. Add provider, symbol, table, relocation, bounds, publication, and runtime-identity tamper negatives with checksum-refreshed checker tests; require failure before the relevant artifact/loader publication.
12. Run focused and full Release managed tests, full Python suite, fixtures/regression matrix, architecture and AArch64 encoding checks, exact-root evidence checkers, and `git diff --check`; obtain fresh independent read-only review before updating the external-table criterion. Do not promote musl/Bionic from glibc evidence and do not close the child/parent by status shortcut.

Rollback boundaries: keep the existing external-table negative intact; if provider proof fails, remove only the new provider positive path and retain current fail-closed behavior. Never revert existing in-image shared-table support or widen general dependency/indirect-call admission.

### Existing-path evidence closure checkpoint — direct execution

- Scope: repair ordinary indirect-control schema-3 clone evidence validation and
  TLSDESC source-call publication ownership; no external-provider wiring, new
  runtime/profile admission, acceptance/status changes, staging or commit.
- The ordinary checker now verifies the source table, preserved original bytes,
  PF_R clone placement/policy, exact-integer ownership ordinals, each source/output
  target/base/entry binding and edit, and the selected consumer reference chain.
  Its unchanged retained root
  `.artifacts/indirect-control/existing-path-closure-20261019T052614Z-21660`
  passes, including all four fail-closed negative rows.
- TLSDESC BLRs are distinguished from ordinary calls only after source TLS
  carriers and a freshly projected module/descriptor/full decoded sequence
  agree with the snapshot. Static-callback completeness recognizes canonical
  table/index/VA function identities as well as existing exact-range name
  identities. Ordinary missing-call-owner negatives still pass.
- Fresh native glibc TLSDESC positive:
  `.artifacts/tls-runtime/direct-tlsdesc-20261019T104943Z-15079/tlsdesc.host-context-entry.glibc.current-thread`.
  Both source and transformed entry/process statuses are 43, streams match,
  release passes, and Protected Image/rehydration/TLS row checkers pass.
  Retained consumer build SHA-256 matches the current Core assembly
  (`18d4ca5840e74b03dc39dc3c872c335f3e45cca281fb2f15d1f1e6ecb17d6fed`).
- Failed matrix subprocesses now retain bounded stage diagnostics, process
  status, both streams and per-file hashes in `failures/ROW` before temporary
  work cleanup; tests cover empty stderr, truncation, symlinks, overwrite and
  path-escape refusal. This does not manufacture a successful matrix.
- Gates: Release build 0 warnings/errors; focused managed TLS/static-callback/
  dynamic-import/Protected Image/generic rehydration tests 156/156; related
  Python evidence suites 74/74; architecture, Python compilation, task context
  validation and diff checks passed. Task context validation still warns about
  existing oversized manifest entries. Verification was performed directly by
  the main assistant as requested, not by an independent child review.
- Remaining: the minimal eight-word synthetic TLSDESC fixture still fails the
  existing output-word `TlsLayoutMismatch` gate after source ownership passes;
  its regression explicitly retains that separate rejection. The real-linker
  native positive above does not promote arbitrary layouts. Full TLS aggregate,
  musl/Bionic runtime evidence, canonical CI-root gates, and external-provider
  production remain open. No successful unrelated producer or complete matrix
  was rerun, and no old artifact was modified.

### TLS aggregate closure follow-up — direct execution

- Ran the complete PR matrix in a new root. The first aggregate passed its
  matrix-specific checker but exposed a retention gap on direct generic child
  review: the collector copied only a partial tree, and stage paths referred
  to removed temporary work. Preserve that first root as an observation only:
  `.artifacts/tls-runtime/aggregate-closure-20261019T110041Z-23111`.
  Do not describe its children as independently validated publication roots.
- Minimal same-script fix: generate promoted rows directly under the new
  durable aggregate root, retain the complete original publication trees,
  add matrix facts, close each child inventory, and run both generic child
  gates before returning the positive row. Add child SHA256SUMS to row
  evidencePaths and the outer inventory. No role/path/hash rewriting or
  source/runtime admission changes were introduced.
- Fresh corrected evidence:
  `.artifacts/tls-runtime/complete-aggregate-20261019T110431Z-27457`.
  All 60 registry rows validate: 4 accepted-and-runs (native AArch64/glibc
  IE/LD/GD/TLSDESC, HostContext current-thread), 20 environment-unavailable,
  36 not-applicable. Four source/transformed entry/process pairs return 43
  with equal actual streams and successful releases. All eight independent
  invocations of the two generic child checkers pass, and all 363 outer
  checksum entries validate. This is local producer evidence, not a CI run
  and not 60 native executions.
- Tests: related Python suites 75/75 (matrix contract 11/11), including
  complete-child inventory closure before validation, original metadata
  preservation, failed checker propagation and symlink refusal. Python
  compilation, architecture and diff checks pass. Core production code did
  not change in this follow-up; the prior Release and 156 managed-test
  results still apply.
- This supersedes only the prior open TLS-aggregate item. Musl/Bionic
  execution, canonical CI-root gates, synthetic output layout and external
  provider production remain open. No staging/commit/task-status changes;
  the candidate worktree index hash remains
  `dbd0df747258b85df369390f44ece3684d5d23e6b3fde2c2780e0c5e68504263`.

### Whole-batch pre-commit gate — blocked on existing evaluator registry pin

- Release build passes with zero warnings/errors; full managed suite 680/680.
- Full Python discovery runs 426 tests, with 22 failures and one error. All
  23 failing/error blocks stop at the same evaluator registry hash mismatch;
  do not report this full gate as passed or stage/commit the batch yet.
- The only mismatched registry is `fixtures/manifest.json`: current and HEAD
  SHA-256 are both
  `85fb7495ff95dab5d110f451293ec9cb4d4e6686f27c0ed2459836f268b8b038`,
  while `fixtures/evaluator/compatibility-corpus.json` retains
  `7640d3e7836d017dcd9cf8fadc685e1578684a1cb0a145218c3eaeacbd611ff1`.
  Both files and the evaluator validator are unchanged by this ten-file slice;
  the inconsistency is already present in HEAD 61b51ce. The other four
  retained registry digests match. This proves the static input mismatch is
  pre-existing, not that tests behind that first-failure gate are healthy.
- Logs retained in
  `.artifacts/precommit/indirect-tls-20261019T111554Z-9637/{build,managed,python}.log`.
- Stop for scope confirmation before changing the evaluator's current registry
  binding. Do not bypass the hash gate, rewrite historical immutable baselines,
  or silently include an eleventh file in the previously proposed batch.

### Registry synchronization and final evidence recheck — direct execution

- User approved continuing with the existing evaluator registration repair.
  The prior registry-pin blocker above is now resolved: synchronize the current
  fixture-matrix retained-registry digest in compatibility-corpus.json, then
  synchronize its new digest in evaluator-protocol.json. These are exactly two
  current registration fields; no validator, corpus rows, fixed-row metadata,
  baseline reference, historical baseline artifact, or support status changed.
- Rechecked baseline-reference.json and its frozen baseline-zero artifact against
  their pre-edit SHA-256 values; both remain byte-identical. Live manifest
  validation still reports baseline-zero and baseline-not-calibrated.
- Final direct diff review reproduced an over-broad new ADD-immediate decoder:
  replacing the transformed consumer ADD with ADDG (0x91800021) and refreshing
  image/evidence hashes was incorrectly accepted. Tighten opcode bit 23 and add
  that nearest-negative to the Native Image tamper test. It now fails for the
  dispatch chain, not a stale digest. No production encoding/admission changed.
- Gates: evaluator-focused tests 22/22 and positive-baseline-v2 tests 7/7;
  final full Python discovery after the opcode fix 426/426. Original indirect
  evidence and its four negatives pass; the existing complete TLS aggregate
  passes all 60 rows and all eight generic child checks. No native producers or
  historical artifact roots were rerun or rewritten. Prior Release build
  (0 warnings/errors) and 680/680 managed tests remain applicable: C# files
  have not changed since those runs.
- Final architecture, regression-matrix metadata, task-context validation and
  diff checks pass. Existing context-injection truncation warnings remain.
  Logs: `.artifacts/precommit/indirect-tls-registry-20261019-YOgHjn/`.
  Preserve two corrected CLI invocation errors in that root separately from
  the successful evidence/regression gates; neither was a product failure.
- Current batch contains twelve modified tracked files, with an empty staged
  index. No commit, push, task archive, or acceptance/status change was made.
  Local native glibc evidence does not promote musl/Bionic, external-provider
  production, arbitrary layouts, or canonical CI execution.
