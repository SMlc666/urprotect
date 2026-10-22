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

6. Add an explicit host-only provider input to `protect-image` and `rehydrate-image`; route file reads through Infrastructure’s bounded private-snapshot adapter. Keep the nested snapshot at URP-SPS6/version 6 and reject v1-v5. Preserve the provider-facts-only `SemanticExternalJumpTableExtension` bytes exactly; carry selected consumer/GOT/branch proof in a separate typed `SemanticExternalJumpTableConsumerExtension` with its own stable appended discriminator, linked by provider table identity and content hash. Cross-validate its exact proof facts and the `SemanticIndirectTargetExtension.SourceInstruction` identity/runtime binding; preserve outer Protected Image ABI v1.
7. Recognize only the exact bounded consumer sequence, exact undefined object, one non-PLT GLOB_DAT relocation/GOT slot, and provider-local signed-32 table/target family. Keep provider addresses in their own identity domain; do not create fake source-image address-map rows or clone the provider table.
8. Reparse consumer and provider at rehydration/publication; independently bind dynamic metadata, symbol rows, provider hash/build-id/SONAME, read-only table range/bytes, entries, targets, bounds/default edge, full producer chain, and selected output mapping. Reject missing/duplicate/changed/tampered facts and bound aggregate work.
9. Re-encode only the moved selected consumer GOT-page producer using the existing AsmStone-backed encoder; preserve provider table/target bytes and prove an unselected observer still uses the provider object.

##### Historical implementation boundary (proof-only; superseded for Slice B)

The following paragraph records the earlier proof-query-only checkpoint, not the current execution limit. After the independent review identified the conflict, the user explicitly approved continuing the managed integration (conversation §109, in reply to the scope approval question in §108). The current authorized boundary is Slice B steps 6–9: host-only all-or-none provider CLI flags, byte-compatible SPS6 provider facts plus a typed consumer companion, selected-consumer emission, protection publication, rehydration validation, and managed positive/negative tests. Reuse the existing proof query and bounded owners; do not add a second resolver/parser. Missing or mismatched trusted provider input remains fail-closed. Native/runtime support, Slice C evidence execution and acceptance promotion, arbitrary dependencies, and musl/Bionic remain outside this iteration. Leave task status and PRD acceptance boxes unchanged. Complete independent managed review, then synchronize specs; do not stage or commit without a separate commit step.

Historical checkpoint:

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

### Slice B managed blocker checkpoint — source-bound GOT producer publication

- Reproduced independent review `c846c816-d982-4a80-b93c-612fb529b37f` without changing its regression: the checksum-refreshed selected ADRP target/expression forgery published a Native Image (1 failed / 0 passed). Retain `.artifacts/managed-provider-remediation/before-fix-regression.log`; the unchanged regression now passes 1/1 (`after-fix-regression.log`).
- The external publication owner now projects the independently analyzed source through the existing semantic factory/canonical codec and requires exact instruction/fixup facts, including unique source VA/file/range, original encoding, kind, target, expression and relaxation. In-consumer GOT/page mappings must remain identity mappings; each producer's logical source/output/file/VA binding and contiguous emitted five-instruction chain must agree with the source proof. Source/fixup disagreements fail with `SemanticPlanSnapshotMalformed` and the `source-derived projection` message; logical chain/map disagreements use the `GOT output mapping` message.
- Retain the complete independently rederived `Aarch64FunctionAnalysis`—not only its proof—across materialization. Before Native Image publication, use the planner's physical placement, output `LoadMap`, shared encoder/decoder, and actual output bytes to re-emit the entire selected consumer and compare every byte and producer offset. Recheck the source entry branch, unique live BR binding, exact ADRP/GOT-LDR/LDRSW/ADD/BR chain, decoded effective GOT slot, unchanged pointer bytes, and exact parsed GLOB_DAT/dynsym owner. A self-consistent map pointing at an appended dead copy is rejected by the final emission check. This remains bounded to the existing selected external-consumer family (at most 65,536 emitted instructions); no provider-domain addresses become local mappings.
- Added 38 nearest-negative managed cases: seven new valid-canonical fixup forgeries plus existing semantic-owner rejection of eight structurally invalid assertions; eight mapping mutations; five emitted producer mutations; missing instruction+fixup together; appended dead-chain mapping; and eight independently mutated final-ELF chain/GOT/entry cases. The original review regression is preserved. Existing safe provider reads/FIFO tests, duplicate-RELA fixture correction, target entry order/null guards, partial CLI flags, and provider-only SPS6 wire-byte compatibility are unchanged.
- Final validation (logs under `.artifacts/managed-provider-remediation/`):
  - `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore --filter 'FullyQualifiedName~ExternalJumpTableProviderPublicationTests' --logger 'console;verbosity=minimal'` — 54/54 (`provider-suite-final.log`).
  - `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-build --no-restore --filter 'FullyQualifiedName~RehydrationRejectsAnExternalGotPageFixupThatNoLongerTargetsItsProvenGotSlot' --logger 'console;verbosity=minimal'` — 1/1 (`after-fix-regression.log`).
  - `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-build --no-restore --filter 'FullyQualifiedName~SemanticPlanSnapshotTests|FullyQualifiedName~CliApplicationTests|FullyQualifiedName~ProtectionCliOwnershipTests|FullyQualifiedName~Aarch64ExternalJumpTableConsumerProofTests|FullyQualifiedName~SemanticExternalJumpTableProviderReaderTests|FullyQualifiedName~LinuxSafeFileInputTests' --logger 'console;verbosity=minimal'` — 218/218 (`focused-managed.log`).
  - `dotnet build UrProtect.sln --configuration Release --no-restore` — zero warnings/errors (`release-build.log`); `dotnet test UrProtect.sln --configuration Release --no-build --no-restore --logger 'console;verbosity=minimal'` — 743/743, no skips (`full-managed-suite.log`).
  - `python3 scripts/check-architecture-boundaries.py` and `--self-test`; `python3 scripts/check-aarch64-encoding-boundary.py` and `--self-test`; `python3 -m unittest discover -s tests -p 'test_architecture_boundaries.py' -v` (4/4); `python3 -m unittest discover -s tests -p 'test_aarch64_encoding_boundary.py' -v` (3/3) — passed (`boundary-checks.log`).
  - `git diff --check` and explicit whitespace checks of the untracked validator/publication-test files — passed; staged index remains empty.
- This was a managed fix/validation checkpoint, not task acceptance, native/runtime evidence, or a support claim. At that checkpoint native runtime/E2E had not run and full Python discovery was not rerun (only the two boundary suites). No version bump, provider wire-format edit, dependency, publication, staging/commit, status/acceptance update, or spec synchronization was performed then; the later independent review and spec synchronization are recorded below.

### Fresh independent review — managed Slice B accepted; Slice C pending

- Independent review `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/502d25a1-3a49-4a59-9267-1fe5ec472597_trellis-check_output.md` accepted the managed provider-publication slice after fixes. Its review confirmed full source-derived reanalysis, complete final-emission byte/producer-offset comparison, selected entry and dependency checks, and the existing same-descriptor safe-file boundary. No production safe-file change was required.
- Final accepted Linux/AArch64 managed gates recorded under `.artifacts/managed-provider-review/`: Release build with zero warnings/errors; provider-publication suite 64/64; original GOT-fixup, legacy SPS6-byte-compatibility and safe-file checks 9/9; focused managed gate 340/340; full managed solution 754/754 with no skips; architecture/encoding checks and self-tests; and 7 boundary unit tests. The independent report includes the command/log details. Full Python/evidence discovery was not rerun beyond the boundary suites. These are managed validations, not native transformed execution.
- Safe-file execution was on Linux/AArch64. Linux/x64 and unsupported-host behavior was statically reviewed only. The native provider self-tests remain source-loader evidence; no fresh managed source-versus-transformed Native Image run was performed. Slice C still needs an exact-root provider-aware runner/checker and evidence for selected entry plus unselected observer at four target indices and safe default, measured provider pins/mappings/GOT/table/target-symbol relations, statuses/streams/release ordering, and checksum-refreshed rollback/tamper negatives. Do not promote glibc or infer musl/Bionic.
- Code-spec synchronization updates the external-consumer, quality, error-handling, runtime-compatibility and backend index contracts plus `tests/ContractInventory.md`. This checkpoint does not change PRD acceptance, task status, evidence roots, or runtime claims.

### Slice C continuation authorization — provider-aware evidence and exact-root validation (execution boundary recorded before edits)

The managed Slice B iteration boundary above is complete: its independent review passed and the applicable backend specifications were synchronized. Under the user's continuing authorization for the overall active task, implementation now proceeds through the already-planned Slice C steps 10–12. This entry records a new execution boundary only; historical slice notes, acceptance records, reviewed outputs, and immutable artifact roots remain unchanged. This is the pre-edit checkpoint for the current Slice C execution; no runtime promotion, task-status transition, PRD acceptance, registry edit, or historical evidence rewrite is implied.

- Produce a fresh native AArch64/glibc source → `protect-image` → `rehydrate-image` → Native Image HostContext run for the configured provider. Exercise selected `urp_entry` and unselected `urp_observer` at indices 0–3 plus the safe default; retain exact provider identity, source/protected/native hashes, commands/stages, each measured handoff/status/stream/release, runtime/libc/loader file identity, provider mapping, GOT and table bytes, all four target-symbol relations, and the observer's original provider-table binding.
- Reuse the existing configured-provider adapter, project fixture, semantic proof/ELF parser owners, HostContext handoff utilities, and bounded evidence helpers. Do not add another resolver/parser, provider search-path/dependency admission, runtime target translation, or fake source-image mapping for provider addresses.
- Add a closed exact-root Python checker that opens only root-contained bounded evidence files and validates exact integer types, byte-derived ELF/runtime facts, command/artifact hash chain, both target selection lanes, release ordering, status/stream bytes, and symbol/table/GOT/mapping relations. Add checksum-refreshed semantic negatives for provider identity/bytes, symbols/table, relocation/GOT, bounds/default, output/publication, and runtime identity; each must be rejected for an independently recomputed semantic mismatch rather than stale hashes or claim flags. Keep the existing external-table nearest-negative unchanged.
- If provider loading/publication fails, require rollback of handles/descriptors and relevant pre-publication counters. Do not weaken the managed validator to make evidence pass. Retain any failed producer/run observations with bounded stage data; report a production defect outside this evidence boundary instead of broadening admission.
- Run exact source/readelf checks, fresh positive producer and checker in a new `.artifacts` root, focused/new tests, Release build/full managed suite, full Python suite, and fixture/regression/architecture/encoding gates as budget permits. Keep the native row deferred and request fresh independent review before any acceptance/spec promotion. No PRD acceptance, runtime registry, task status, staging, commit, push, merge, or archive changes are authorized here.

### Slice C adversarial remediation checkpoint (2026-10-20)

This continuation addresses only the fresh independent re-review's full-output `PT_LOAD` mapping blocker and retained-provenance decompression/resource-bound finding. It does not promote Slice C or close native post-provider-acquisition rollback, CI/registry/docs, or other runtime gates.

#### Remediation and regression coverage

- The independent checker proves the emitted `urp_entry` output range as a whole (92 bytes in this fixture), not the 40-byte source symbol prefix: exactly one file-backed `PT_LOAD` must map the entire output VA range to the claimed exact file offset; the range must be read-only executable. Every emitted instruction and decoded live branch target is also required to remain executable, uniquely file-backed, and within this emitted mapping, with ELF range and arithmetic bounds checked.
- The refreshed-root regression truncates the relevant Native Image `PT_LOAD` `p_filesz` and `p_memsz` so the source-sized first 40 bytes remain mapped while the final 52 emitted bytes—including the state-0 branch target at output+64—are unmapped. It refreshes the nested rehydration/layout/native-role/command/report/handoff image claims and the outer closed manifest, asserts the semantic map failure, and deliberately does not invoke the HostContext handoff helper with the malformed Native Image.
- The retained provenance reader caps the complete gzip-expanded tar stream at `MAX_PROVENANCE_EXPANDED_BYTES` (64 MiB) before `tarfile` receives it. It accepts only one integrity-checked gzip member, rejects trailing/concatenated or truncated streams, scans bounded tar headers and PAX metadata before `tarfile`, bounds total headers/members/extensions/metadata and each member, rejects repeated hidden PAX extensions and unsupported member types, then retains the existing closed regular-file-only member set and exact byte provenance. The compressed-input limit remains 128 MiB.
- Added focused cases cover compressed-small/expanded-over-limit PAX data with a patched 4 KiB bound and an assertion that `tarfile.open` is never reached, repeated hidden PAX headers, malformed/truncated gzip, concatenated gzip members, and the checksum-refreshed Native Image output-map truncation. The focused suite now runs 18 tests (14 existing plus 4 added); no existing provider/semantic checks were weakened.

#### Validation and immutable prior roots

- `python3 -m py_compile scripts/check-external-provider-evidence.py tests/test_external_provider_evidence.py` — passed.
- Four new adversarial regressions run against copies made from the prior `-final` root — 4/4 passed; the source root was read-only.
- Read-only checker on the older `-04` and prior remediation-final roots — both passed. Their retained manifest/report/provenance digests remained unchanged:
  - `-04`: `SHA256SUMS` `34e55c8a1d68ebcee5989792738bc85c09671ff8a70373160c66d33b67dbd394`; report `5171534d790c7be44c5e0fcf16f12cd78afd5502cde699ba31153a16111deabf`; provenance `7a864e93f973d8a8f006589faee0679b722e24156e3e687df6b7d517bc7202d9`.
  - Prior `-final`: `SHA256SUMS` `10b7e013b8b3f35023af0ed92edfe70242ea718e30d364bf46f8e5a14307babf`; report `58c86da35c0422b30969c06e2645d4f6f1830987085903ca3179a4afa69afd43`; provenance `c43eb3e8e4d6e0c55840933c9c5263a36c641eb7bfd0a7644f6a3768e4608660`.
- Fresh direct-native AArch64/glibc 2.43 E2E, not emulated, passed in the unique root `.artifacts/indirect-control/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291/runtime.indirect-control.external-provider.glibc.host-context-entry`. The runner's root-bound focused suite passed 18/18 and its independent exact-root checks passed. Provider identity: SONAME `liburprotect-jump-table-provider.so.1`, build ID `a82d6ab982fab000f733cb631639b28f16f0bdb6`, SHA-256 `30efdbcd717c30a518bc7c83851ed3b43ba57a9e130064be04d176d0764e1746`. Source/Protected/Native Image SHA-256: `2dd8122e8a07aad02db477fc1928c61969785aa049a11c6c9b0a5300c46f41fa` / `b1eb4bc73792e69e4bb306eb24f082dc88a8d136b6cc750061a409588beff73a` / `196dcb608ebcb1a87ae7280b2bee77a5e6f4c69c8135ac95e9476e5066cfc74a`. The report remains `scoped-observation-not-promoted`.
- Fresh root digest evidence: `SHA256SUMS` `d55e3c18ae9553ae927be51e52d99a8f9abc126250a1f8e6451f7f9f804388e7`; `external-provider-evidence.json` `2c84d821ffb1fd196ee7149e1ee7d2e9c0813d8ea361184c0f659fc5f421ef70`; `build-provenance.tar.gz` `04a40e56b536a7c7726c97a2272b75c2c6ed2509b6eebbc0c9b97b34f3d3b2cf`. The retained provenance is 15,574,851 compressed bytes and 41,164,800 expanded tar bytes under the 67,108,864-byte expanded bound.
- `URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT=<fresh unit root> PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v` — passed once: 444 tests in 169.168 seconds, zero skips. Raw stdout/stderr/status and parsed count are retained beside the root at `.artifacts/indirect-control/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291.python-discovery.{stdout.log,stderr.log,raw.log,exit-status,summary.json}`. The historical `/tmp/pi-bash-5761ae2863c5a423.log` remains unchanged and unresolved: it records 432 tests, one failure and one skip, with `test_staged_merge_rejects_directory_symlink_type_conflicts` subcase `symlink-over-directory` receiving empty stderr. The fresh suite did not reproduce it; this green rerun does not explain or close the historical failure.
- `git diff --check` and explicit trailing-whitespace checks of the checker/test files — passed. No files were staged.

#### Changed files and remaining gates

- Changed: `scripts/check-external-provider-evidence.py`, `tests/test_external_provider_evidence.py`, and this checkpoint in `.trellis/tasks/10-06-indirect-control-jump-tables/implement.md`. Detailed command outputs are retained in `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291.md`; raw E2E runner logs are `.artifacts/indirect-control/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291.runner.{stdout.log,stderr.log,exit-status}`.
- Still outstanding: a native oracle that passes provider preflight/acquires the provider, then fails the consumer loader/binding path and verifies provider reference/mapping/FD rollback plus successful subsequent reload; required CI E2E/checker gate; appropriate fixture/regression registry and documentation synchronization. No CI, registry, docs/spec, PRD, or promotion edits were made in this continuation. Continue to report provider-loaded rollback as code-reviewed but not native-oracle-validated, and keep runtime acceptance deferred.

### Slice C PT_LOAD overlap correction (2026-10-20; pending independent review)

This narrowly closes the concrete partial-memory-overlap bypass in the selected external-provider Native Image checker. It preserves the already accepted full-output truncation and PAX/resource-bound fixes above. It is a checker-only correction plus focused regressions; it does not promote the provider runtime row or address any other open lifecycle/CI/registry/documentation gate.

#### Physical-map rule and regressions

- `scripts/check-external-provider-evidence.py:604-665` adds a bounded selected-code owner check. For each query it uses checked unsigned-64 half-open endpoints (an exclusive endpoint equal to `2^64` is valid; overflow is rejected), finds exactly one `PT_LOAD` whose file-backed VA interval contains the complete queried range, then rejects every other `PT_LOAD` whose memory interval intersects any byte of that range. This includes partial file-backed overlaps, conflicting permissions/translations, interior subranges, duplicate identical full owners, and BSS-only memory overlap. Zero-sized segment intervals do not intersect. The check is limited to the 92-byte emitted `urp_entry` dispatcher and the live four-byte entry B stub; it is not whole-image code analysis.
- The independent exact-root regressions in `tests/test_external_provider_evidence.py:612-790` clone the current accepted root read-only, mutate only the copied Native Image program-header table, refresh all downstream image/rehydration/native-role/command/report/handoff claims and the closed SHA256SUMS, verify the manifest, then require the semantic physical-map diagnostic. Cases cover the reproduced one-byte PF_R overlap at `outputVA+1`, a PF_RX interior instruction subrange, a duplicate full PF_RX owner, BSS-only overlap, and a one-byte overlap of the live entry stub. No mutated image is handed to HostContext. The positive control includes half-open segments adjacent before/after the emitted range, a nonintersecting segment, and a zero-sized interior PT_LOAD; the regenerated exact-root report/checksum set remains valid. A direct boundary regression accepts `[U64_MAX, 2^64)` and rejects an overflowing interval.
- The prior live-dispatch tampering test now also refreshes malformed-output evidence without rerunning the HostContext helper (`rerun_handoffs=False`), so the checker regressions do not load malformed Native Images or execute a forged helper binary. The existing truncation regression and PAX/gzip regressions remain present and unchanged in behavior.

#### Verification record

- Exact retained root (read-only): `.artifacts/indirect-control/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291/runtime.indirect-control.external-provider.glibc.host-context-entry`.
- Exact-root checker passed before and after implementation. The retained root's SHA256SUMS digest remained `d55e3c18ae9553ae927be51e52d99a8f9abc126250a1f8e6451f7f9f804388e7`; no retained evidence file was edited.
- `PYTHONPYCACHEPREFIX=/tmp/urprotect-provider-overlap-pycache python3 -m py_compile scripts/check-external-provider-evidence.py tests/test_external_provider_evidence.py` — passed.
- Focused overlap/boundary/truncation/live-dispatch regressions: `URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT=.artifacts/indirect-control/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291/runtime.indirect-control.external-provider.glibc.host-context-entry PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_external_provider_evidence.ExternalProviderClosedRootTamperingTests.test_refreshed_pt_load_code_overlaps_are_rejected_and_adjacent_ranges_remain_valid tests.test_external_provider_evidence.ExternalProviderClosedRootTamperingTests.test_checked_code_load_intervals_accept_u64_endpoint_and_reject_overflow tests.test_external_provider_evidence.ExternalProviderClosedRootTamperingTests.test_refreshed_native_output_pt_load_truncation_is_rejected_before_handoff tests.test_external_provider_evidence.ExternalProviderClosedRootTamperingTests.test_refreshed_native_entry_and_live_dispatch_bypasses_are_rejected_semantically` — passed, 4 tests.
- Complete provider evidence suite: `URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT=.artifacts/indirect-control/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291/runtime.indirect-control.external-provider.glibc.host-context-entry PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_external_provider_evidence.py' -v` — passed, 20 tests, zero skips.
- Full Python suite, run once with the exact retained root and no skips: `URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT=.artifacts/indirect-control/external-provider-slice-c-remediation-rereview-20261020T102935Z-16291/runtime.indirect-control.external-provider.glibc.host-context-entry PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'` — passed, 446 tests, zero skips. This does not explain or close the earlier recorded 432-test run with one failure/one skip (`test_staged_merge_rejects_directory_symlink_type_conflicts`, `symlink-over-directory`, empty stderr). The separate historical Bionic staged-merge failures recorded in `.trellis/tasks/10-06-indirect-control-jump-tables/research/current-gap-audit.md:121` are also untouched and unresolved; neither historical record is explained by this green rerun.
- `git diff --check` — passed; `git diff --cached --quiet` — passed (index empty). No managed suite, native runtime suite, or fresh native E2E was rerun.

#### Scope and remaining gates

- Changed for this correction: `scripts/check-external-provider-evidence.py`, `tests/test_external_provider_evidence.py`, and this task checkpoint. No implementation/spec/CI/registry/docs/PRD/runtime-promotion changes were made; no task status changed.
- The byte-granular partial-overlap bypass is closed in the implementation and checksum-refreshed regression, pending fresh independent review. Prior accepted truncation and compressed-PAX bounds remain preserved.
- Still open: native provider-acquired consumer-loader/binding failure rollback evidence (provider reference/mapping/FD rollback and successful reload); required CI E2E/checker gate; fixture/regression registry and documentation gates. Provider runtime acceptance remains deferred; do not infer musl/Bionic support or claim broader runtime promotion.

### Slice C provider-loaded consumer-failure rollback oracle (2026-10-20)

This bounded native source-loader slice closes the previously open post-provider-acquisition rollback observation for one project-built AArch64 provider/consumer pair. It does not promote the external-provider runtime row or complete managed producer/rehydration behavior, CI, registry, documentation, or other runtime gates.

#### Implementation and evidence

- A new private test-only build defines `URP_HOST_ADAPTER_TEST_PROVIDER_BINDING_FAILPOINT` alongside native diagnostics. The compile-time guard rejects use without test diagnostics or outside glibc; production `host_adapter.o` contains no failpoint or observation API. The one-shot injection is consumed only after provider acquisition, consumer `dlmopen`, and the existing real link-map/provider-table/consumer-GOT verification succeed, and before image-handle publication.
- The test adapter retains the exact provider/consumer descriptor numbers and real load/GOT addresses, cleanup return values, bounded lifecycle events, provider registry/reference/descriptor counts, image registry/handle state, and `/proc/self/fd` counts. The helper observes the injected first-load rejection and verifies mappings/FDs/references are gone before attempting index-0 dispatch through the same adapter a second time; the retry enters both `urp_entry` and `urp_observer`, then releases the image and provider.
- The dedicated exact-root runner retains provider/consumer fixture bytes, all relevant native source/header inputs, compiled objects/helper, evidence-checker sources, compiler/assembler/linker bytes and version outputs, exact build/loader stdout/stderr/status, native JSON record, and a closed SHA256SUMS. The checker derives fixture/provider identities and GOT/table virtual addresses from the retained ELF bytes, enforces exact JSON integer/schema/property contracts, checks native AArch64/glibc identity, mapping-base equations, table/GOT bytes and permissions, exact lifecycle ordering, cleanup results, descriptor/reference/handle counters, and the successful retry/release. The new tests refresh the manifest after tampering and reject event-order, provider mapping, cleanup-status, and boolean-schema-version forgeries.
- `external-provider-self-test` now runs the new native oracle target as part of the native provider self-test. No CI configuration, registry, spec, documentation, PRD acceptance, task status, or runtime-promotion claim changed.

#### Validation record

- Fresh native AArch64/glibc 2.43 evidence root (read-only): `.artifacts/indirect-control/provider-loaded-rollback-20261020T152000Z`. The independently recomputed report is `accepted`; exact lifecycle trace has 21 events. First load rejects with `URP_STATUS_UNSUPPORTED` (`-2`) after provider binding verification, publishes no handle, unmaps both objects, closes both consumer descriptors and the provider descriptor, releases one provider reference, and restores baseline open-descriptor count (4). A subsequent fresh load dispatches entry/observer status 17, observes read-only provider table and GOT mappings, then release returns mappings/descriptors/references to baseline.
- Retained SHA256SUMS digest: `89f5fe38e08486aa17a7a85bb523a2a44a50b084442c5455035c1bdb15a4a83c`; report digest: `fa3d2a2c6d1e5c9fbf03380f43ffd15b8122064aa02d49688bcafe88353be6b0`; provider SHA-256: `30efdbcd717c30a518bc7c83851ed3b43ba57a9e130064be04d176d0764e1746`; consumer SHA-256: `2dd8122e8a07aad02db477fc1928c61969785aa049a11c6c9b0a5300c46f41fa`.
- `scripts/run-external-provider-rollback-oracle.sh --artifact-root .artifacts/indirect-control/provider-loaded-rollback-20261020T152000Z` — passed; it rebuilt the forced native target, executed the oracle, independently validated and sealed the exact root.
- `make -C native/urprotect-runtime test` — passed, including the provider preflight self-test and integrated provider-loaded rollback oracle plus the complete native runtime suite.
- `URP_PROVIDER_ROLLBACK_EVIDENCE_ROOT=.artifacts/indirect-control/provider-loaded-rollback-20261020T152000Z PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_external_provider_rollback_evidence` — passed, 5 tests, zero skips.
- Python compile checks for the rollback checker/tests, `bash -n scripts/run-external-provider-rollback-oracle.sh`, `git diff --check`, and `git diff --cached --quiet` — passed; no files are staged.

#### Remaining gates and scope

- This is native adapter/source-loader evidence only. No managed Source Image -> Protected Image -> Native Image provider execution was added or rerun here. The CI E2E/checker gate, fixture/regression registry and documentation synchronization remain deliberately open. Provider runtime acceptance remains deferred pending the required full workflow and fresh independent review; the row is native AArch64/glibc only, with no musl/Bionic or general provider/indirect-control promotion implied.
- The earlier Slice C PT_LOAD-overlap and provenance-bounds root was not modified. The preliminary rollback roots `provider-loaded-rollback-20261020T135500Z` and `provider-loaded-rollback-20261020T145000Z` remain unchanged as historical iterations; the accepted current root is the read-only 20261020T152000Z root above, which also binds the retained provider-parser dependency sources.

### Required provider CI and registry integration checkpoint (2026-10-20)

This checkpoint wires the already-existing transformed provider producer/checker and the independent source-loader rollback producer/checker into the required build-and-test lane. It is an integration/verification checkpoint, not PRD completion, runtime-row promotion, or a task-status change.

#### CI wiring and provenance behavior

- `.github/workflows/ci.yml` runs both producers and both exact-root checks in the required build-and-test job for PR, nightly, and release events. Producer and checker steps use `if: always()` so an earlier failure cannot silently suppress the evidence attempt; the job has no conditional `if` and workflow triggers have no path filters. The existing external-provider runner performs the single managed `protect-image`/`rehydrate-image` build/run, four target indices plus safe-default source/transformed HostContext observations, transformed Native Image rollback observation, exact-root checker, and provider-evidence root-bound regressions. CI invokes that producer once and invokes the independent checker against the exact unit directory; it does not add a duplicate native E2E.
- The source-loader rollback remains a separate fresh producer and exact-root checker. Its CI unit test receives only `.artifacts/indirect-control/provider-loaded-rollback/current` through `URP_PROVIDER_ROLLBACK_EVIDENCE_ROOT`; the transformed-provider root tests receive only the exact external-provider unit root. Each producer writes a run-keyed root marker plus command/status/log files. Each checker verifies the producer statuses and exact root marker before checking evidence, retains its own log/status, and propagates both checker and `tee` failure statuses. Paths are repository-relative; no machine-local `/root` or `/tmp` path is persisted in the registry.
- `.artifacts/indirect-control/provider-ci-logs/` is included in the CI upload inventory. `include-hidden-files: true` is placed immediately after the artifact name so the existing upload regression observes it within its bounded block read. The option was already present earlier in the block; the first full Python run failed only because `tests/test_protected_image_workflow.py` examines its first 900 characters. The option was moved, and the failure plus successful rerun are both retained in the precommit validation log directory.
- `tests/test_fixture_matrix.py` now binds the exact external-provider and source-loader current roots from the workflow to the still-unknown feature row, requires exact-root checker invocations, root markers, run-keyed checker logs/statuses, required rollback root tests, hidden-file upload, and a coherent evaluator digest chain. `tests/test_regression_matrix.py` binds the two required provider cases to those same exact roots and their evidence/log artifacts. The pre-existing fixture row remains `status: unknown` with `nextEvidence`; no status is changed or promoted.

#### Registry/evaluator digest chain

The checked-in `fixtures/manifest.json` already contains the bounded external-provider observation as unknown, and `tests/regression-matrix.json` already contains required E2E and source-loader rows. Their generated paths agree with the two CI `current` roots. The following dependent registry digests were refreshed and independently verified; the immutable baseline artifact itself was not changed:

| Artifact | SHA-256 |
| --- | --- |
| `fixtures/manifest.json` | `e378d276fdc887b4448a1d599352e1e452ecdb4445a7499d3068f6287930764f` |
| `fixtures/evaluator/compatibility-corpus.json` | `be0911389fbe76848756b51577ffce110ef4fae17868328ecb81ad3c9e17c659` |
| `fixtures/evaluator/evaluator-protocol.json` | `825dc9ef667dce0638d0206275d626411a82db47e6f7474e6b559e084ceab929` |
| `fixtures/evaluator/baseline-reference.json` (unchanged) | `3290389f3c28778131b6a633143f17432cc3ffc807d3e38907e941495636b44c` |
| `fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json` (unchanged) | `3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2` |

#### Native evidence used for local root-bound validation

- Existing managed transformed-provider evidence was checked read-only at `.artifacts/indirect-control/provider-rollback-native-image-implementation-20261020-4/runtime.indirect-control.external-provider.glibc.host-context-entry`. Its closed `SHA256SUMS` is `aa4a5725f2797b5b5115ac701ee0a2de7c9653fd02a2c025fffdc574f1bd5abb`; `external-provider-evidence.json` is `06f746508dd091032bc40e8e5f8647f75b35c3b312fffc63b1453f61018fc037`; `commands.json` is `caf450b56509ce93e5b352b0181765f80423ca52798cf843b79eb3c4f9a8486f`; `native-build.json` is `b4d2a746e920af4e15ef4c63a52778aa3148703f60db42dbf90619bb5822087b`; `build-provenance.tar.gz` is `d0a9b5129f8b4de86589d6b23188b1587b26f3dacac53040142f5f8ef5b02819`. The embedded acceptance remains `scoped-observation-not-promoted`; the observed Native Image is `196dcb608ebcb1a87ae7280b2bee77a5e6f4c69c8135ac95e9476e5066cfc74a`, and provider SHA-256 remains `30efdbcd717c30a518bc7c83851ed3b43ba57a9e130064be04d176d0764e1746`.
- A fresh source-loader rollback root was generated and accepted using a temporary isolated source/build workspace, leaving the repository's existing native `build/` outputs and historical roots untouched: `.artifacts/indirect-control/provider-loaded-rollback-ci-validation-20261020T153308Z-18193`. The checked report status is `accepted`, with 21 ordered lifecycle events; first-load cleanup returned mappings/descriptors/references to baseline, successful reload dispatched entry and observer, and release again returned to baseline. Its `SHA256SUMS` is `1e386bcd644adfb8e5024cb86504191fecccddd82f3a8902562488a2bb18c38e`, report is `fa3d2a2c6d1e5c9fbf03380f43ffd15b8122064aa02d49688bcafe88353be6b0`, `native-build.json` is `d3bbad4e5116e969643d81dc0f5a0a8fe5a9270e981cb0dda759c7b9ee1d0d7d`, and `rollback-record.json` is `c729cc43de4ea901a5edb58589f8fe9a7af66cd4db3e3450ff61722cad70d3ce`. It binds provider SHA-256 `30efdbcd717c30a518bc7c83851ed3b43ba57a9e130064be04d176d0764e1746` and consumer SHA-256 `2dd8122e8a07aad02db477fc1928c61969785aa049a11c6c9b0a5300c46f41fa`.
- The fresh rollback root is not copied to a registered `current` path and is not a substitute for the next CI run. The previous source-loader root whose retained checker hash differed from the current checker was not rewritten or used as a green current-parser root. The supplied `trellis-check` output artifact `2dd0515a-7233-480a-9636-8ab960043348_trellis-check_output.md` (SHA-256 `9d2084b9266228dd4448c12c4080eacae1c7b085137e0c82628b07926ed0982e`) reported scoped PASS for the retained transformed Native Image rollback evidence and all 26 root-bound external-provider regressions. It explicitly did not rerun native E2E; this integration does not claim that it did.

#### Validation record

- `dotnet build UrProtect.sln --configuration Release --no-restore` — passed, 0 warnings and 0 errors (`.artifacts/precommit/provider-ci-integration-20261020/managed-build.log`). `dotnet test UrProtect.sln --configuration Release --no-build --no-restore` — passed, 754/754 (`managed-tests.log`). No managed production code was changed by this CI integration.
- `make -C native/urprotect-runtime test BUILD_DIR=<per-run isolated temporary directory>` — passed using a unique temporary build directory; complete native HostContext/TLS/dependency/provider self-test suite returned exit 0 (`native-runtime-suite.log`). The host-specific temporary path is intentionally omitted from durable task/registry records; the shared `native/urprotect-runtime/build` tree was not mutated.
- `URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT=<existing exact transformed-provider unit root> URP_PROVIDER_ROLLBACK_EVIDENCE_ROOT=<fresh source-loader rollback root> PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v` — passed, 458 tests, zero skips; this includes 26 external-provider evidence tests and 5 source-loader rollback tests. The exact environment/command and full output are retained in `full-python-tests-final.command` and `.log`.
- Provider registry/evaluator tests — passed, 39 tests (`tests.test_fixture_matrix`, `tests.test_regression_matrix`, `tests.test_evaluator_schema`). Fixture validator passed for 13 cases; regression matrix validator passed for 27 cases; evaluator manifest validator passed. Exact commands and statuses are in the same precommit log directory.
- Architecture production/self-test and AArch64 encoding production/self-test checks passed. Their 7 unit tests passed. The self-test's intentionally detected forbidden fixture diagnostics are expected and the self-test command itself exits 0.
- Extracted all four provider CI `run:` blocks from the workflow and `bash -n` passed on each. PyYAML parsed `.github/workflows/ci.yml`; `actionlint` is not installed on this host. `task.py validate .trellis/tasks/10-06-indirect-control-jump-tables` passed (with only the existing oversized context-file injection warnings). The final `git diff --check` and `git diff --cached --quiet` both passed.
- The first complete Python suite attempt failed one static upload assertion because `include-hidden-files: true` appeared after byte 900 of the upload step, while the test reads only its first 900 characters. After moving the already-existing option earlier, the complete suite passed as above. The initial failure log is retained for this provenance chain.

#### Remaining task scope / risks

- The PRD remains open: the provider row is still unknown/non-promoted; ownership policy for insufficient section/inventory evidence and other table families remain open; independent native musl and Bionic rows are not supplied by this glibc evidence; and the final general indirect-control report criterion remains unchecked. This checkpoint does not complete the child or its parent.
- The historical Bionic staged-merge failure recorded in `.trellis/tasks/10-06-indirect-control-jump-tables/research/current-gap-audit.md` remains unexplained and unchanged. The clean 458-test rerun does not establish a cause or close that historical risk. The earlier source-loader retained-checker hash mismatch is likewise not repaired by editing historical evidence; the fresh current-checker root above is separate.
- No status promotion, PRD checklist change, staging, commit, push, merge, task finish/archive, or historical evidence rewrite was performed.

### Scoped provider CI review and documentation synchronization (2026-10-20)

- Independent integration review
  `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/41606f2f-bbdf-4150-8757-2428ab7fc6cf_trellis-check_output.md`
  reported a scoped pass for the CI wiring, transformed provider evidence root,
  separate provider-loaded rollback root, and their root-bound tests. It did not
  dispatch hosted CI; hosted upload/declaration and branch-protection mapping
  remain post-merge/hosted confirmation risks. The provider feature/fixture row
  remains `unknown` and the native report remains
  `scoped-observation-not-promoted`.
- Synchronized `.trellis/spec/backend/runtime-compatibility.md`,
  `external-consumer-proof.md`, `error-handling.md`, `quality-guidelines.md`,
  `index.md`, and `tests/ContractInventory.md` with the retained scoped native
  observation, separate source-loader and transformed rollback boundaries,
  strict emitted-code PT_LOAD ownership checks, exact current CI roots, and
  still-open hosted/runtime gates. The pre-execution Slice C gap inventory is
  explicitly labeled historical; the current evidence/checker/CI inventory
  records the completed local work and what remains unconfirmed.
- Updated the technical design and current-gap audit with the target-resolution
  versus fixup-state distinction: `SemanticTargetResolution` is
  `Exact`/`BoundedSet`/`RuntimeResolved`/`Unresolved`; `Deferred` is a fixup
  state. Local movable targets require source→output `AddressMap` bindings;
  external-provider table/target VAs remain in provider identity space, with
  runtime loader mappings verified separately. The final general report
  criterion remains open.
- Reconciled the child PRD: checked only the completed one-provider/one-consumer
  scoped external-table evidence item, with exact retained roots and an explicit
  `unknown`/non-promoted statement. The general ownership-policy, all-runtime,
  and final target-resolution/address-map criteria remain unchecked. Musl,
  Bionic, arbitrary providers/dependencies, other table families and general
  indirect-call support remain unpromoted. Historical Bionic staged-merge test
  failures remain unexplained and are not erased by later passing suites.
- This is documentation/acceptance-accounting only: no production behavior,
  evidence root, fixture/evaluator registry, CI workflow, task status, staging,
  or commit was changed in this synchronization pass.
- Documentation checks: `python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-indirect-control-jump-tables` passed (existing oversized context-file injection warnings only); `git diff --check` passed; LF/final-newline hygiene passed for all 10 documentation files changed here; `git diff --cached --quiet` passed (no staged files). No app/native test suite or retained evidence producer was rerun because this pass changes documentation/acceptance accounting only.

### PR #25 branch-integration checkpoint (2026-10-20)

- The parent fetched `origin/feat/indirect-control-jump-tables` and confirmed it remained at `a945d44`, then began the authorized ordinary `--no-commit --no-ff` merge. `HEAD` is `cea4bcd`; `MERGE_HEAD` is `a945d44`. The expected nine conflicts are active. The merge command's exit 1 denotes these conflicts, not a harness failure.
- Preserve the pre-existing dirty journal and untracked investigation report byte-for-byte and keep the auto-merged remote files. The initial journal SHA-256 was `ab813f2957bc0e4a884ca01bf6f60c622fbc76528427d5a9f369dde3a8812e3e`; the investigation report SHA-256 was `552c5ffe8835efce6912ff6a0de319ec67af16bf120fc7a875bcb0ce73059069`.
- Resolve only the nine reported conflicts using the investigation's file-by-file crosswalk; do not use wholesale ours/theirs resolution. Keep the strict 19-job sharded CI/mainline contract, exact-head dedup, four strict compatibility shards, independent terminal product checker/quality gate, and Scheme A retirement. Retain the mandatory shared-table/provider E2Es, separately-rooted source-loader rollback, exact run-key logs/statuses and always-upload step, plus both provider-root-bound Python suites with fresh environment roots. Preserve the deeper local CFI and indirect-control source/native checkers while integrating the remote genuine CFI negative-producer validation and relocated-FDE/address-map fixture fixes, and keep the local schema-2/runtime/address-map/full-provenance and safe-root/no-overwrite checks. Adapt the emitter's final-fallthrough semantics and B-family address binding with the remote regressions, then close index/base/output and post-LDRSW register-alias gaps with nearest-negative tests. Keep retired evaluator-protocol removal consistent with the live registry/current strict contracts; do not rewrite historical baselines or promote this feature.
- Validation order: resolve and review the nine conflicts; run shell/YAML/workflow and registry/architecture/encoding/digest validators; run Release build plus all managed tests and all Python tests in fresh retained roots; run native glibc runtime, ordinary/shared-table/CFI/provider E2Es and exact checkers, source-loader rollback and both provider-root-bound suites. Run the approved musl compile/helper guard and Bionic lane only if the environment supports them; report real toolchain gaps and never overwrite retained artifacts. Prioritize focused/full managed, Python, and native glibc CFI/provider validation before the 120-minute cap; checkpoint at 15 minutes remaining and report any gates not run honestly. No merge commit, push, task archive, promotion, or staging of the journal/report is authorized.

### PR #25 divergent-branch integration checkpoint (2026-10-20)

This is a merge checkpoint within the existing child task, not a new task, acceptance promotion, or commit authorization.

- Parent fetched `origin/feat/indirect-control-jump-tables` and confirmed it was unchanged at `a945d44ab7611633ab5de9bfadd581eb425f315e`, then started `git merge --no-commit --no-ff origin/feat/indirect-control-jump-tables`. The expected conflict exit is not a tool failure. Merge base is `5c05f532aa985eed24c9d7029756bb4f1cbf4932`; pre-merge local `HEAD` is `cea4bcdc83f771374426276fb6fb50dee9042c94`.
- Preserve pre-existing `.trellis/workspace/SMlc666/journal-1.md` exactly (SHA-256 `ab813f2957bc0e4a884ca01bf6f60c622fbc76528427d5a9f369dde3a8812e3e`) and keep `.trellis/tasks/10-06-indirect-control-jump-tables/research/divergence-integration-investigation.md` untracked and unchanged (SHA-256 `552c5ffe8835efce6912ff6a0de319ec67af16bf120fc7a875bcb0ce73059069`). Never stage either file.
- Resolve the nine anticipated conflicts by the reasoned crosswalk in that investigation: retain remote 19-job/sharded strict-corpus CI and exact-head dedup, port required shared-table/provider producers and exact-root checkers into `protection-and-tls`, preserve local deep source/native checkers and provider contracts, retain remote CFI negative/FDE fixes, resolver alias guards, emitter side-effect/B identity fixes, and retire Scheme-A evaluator assets consistently. Preserve auto-merged files unless focused integration review proves a necessary correction.
- Validate in priority order under the 120-minute checkpoint: resolved state/manifest hygiene; Release managed build and managed suite; full Python suite including fresh roots for both provider suites; focused/new checker and CI shard/dedup tests; native glibc provider/shared-table/CFI and source-loader rollback where host capability permits; fixture/regression/architecture/encoding/CI YAML and shell checks. Use fresh roots and retain failures; report Bionic/musl/toolchain unavailability honestly. Do not promote the provider row or erase historical failures.
- Keep `MERGE_HEAD`; do not commit, push, reset, rebase, stash, drop, archive or promote. Resolve conflict files in the worktree/index as needed, never stage the protected journal or investigation report, then return exact conflict decisions, tests/log roots, residual gates and final git status to the parent for independent review.

### PR #25 branch-integration validation results (2026-10-21)

- Worktree conflict contents are resolved according to the integration crosswalk; no conflict markers remain. Conflict records are intentionally left unstaged for the parent to stage. No commit, push, merge command, journal edit, or investigation-report edit was performed by this implementation pass. The merge-created automatic additions/deletions remain staged by Git's original merge operation.
- Preserved the remote 19-job CI architecture, exact-head gate, four strict-corpus shards and terminal `ci-quality-gate`; retained the local provider/shared-table lanes and both separate provider rollback scopes. Corrected the shared-table CI checker call to provide its required source-derived `--selected-function`, with a workflow-contract regression. Corrected the provider fixture manifest to point at the unit-level closed `SHA256SUMS` (the producer creates no outer positive-root `SHA256SUMS`) and refreshed the retained fixture-manifest digest in `compatibility-corpus.json`. Kept the provider feature `unknown` / not promoted and removed the retired evaluator protocol from the worktree.
- Ported the missing HostContext callback guard for `CMP Xn,#0; B.EQ` / inverted `B.NE` edges and added positive/negative tests. The resolver rejects architectural W/X aliases that overwrite the checked index or loaded displacement/table-base pair. The emitter retains a final ordinary fallthrough instruction's effects and maps only rewritten direct `B` instructions to the emitted state transition.
- Validation passed: `dotnet build UrProtect.sln --configuration Release --no-restore` (0 warnings/errors); `dotnet test UrProtect.sln --configuration Release --no-build --no-restore` (764 passed); Python discovery (417 passed, 2 skipped); fixture and regression validators; CI dedup/shard/strict-product contracts; architecture self-test, AArch64 encoding boundary, YAML parse (19 jobs), `git diff --check`; and `make -C native/urprotect-runtime test`.
- Fresh native AArch64/glibc evidence passed: CFI producer/checker/rehydration and manifest gate at `.artifacts/cfi/current`; shared-table producer/checker/rehydration and manifest gate at `.artifacts/indirect-control/shared-copy/current`; provider positive producer/checker plus its 26-test root-bound suite and manifest gate at `.artifacts/indirect-control/external-provider/current`; provider-loaded rollback oracle/checker plus its 5-test root-bound suite and provider manifest gate at `.artifacts/indirect-control/provider-loaded-rollback/current`. A separate fresh ordinary jump-table root `.artifacts/indirect-control/merge-validation-20261021T001810Z-jump-table` passed all four table cases and four fail-closed negatives.
- Residuals: the pre-existing `.artifacts/indirect-control/pr` root (mtime Oct 14) was not overwritten; its read-only checker rejects it as stale (`jump-table behavior identity is invalid`), so the local declared `pr` jump-table feature gate cannot be revalidated against that old root. The fresh isolated root passes. Musl/Bionic runs were not available because `musl-gcc`, Docker and Podman are absent; actionlint is absent, though workflow YAML parsed and contract tests pass. Provider promotion, hosted Actions/branch-protection confirmation, and musl/Bionic/general indirect-control claims remain open.

### Independent review remediation: evidence roots, provenance, and consumers (2026-10-21)

This bounded follow-up fixes the four review findings without changing runtime acceptance or any retained historical root.

- [x] Import `evidence_load_range.py` from the private indirect-control checker’s sibling path using `spec_from_file_location`; derive the private module key from that resolved path and reject a preloaded module whose source is not the expected sibling. Provider and rollback suite imports pass with ambient `PYTHONPATH` unset.
- [x] Close the retained provenance inventory. Fresh positive-provider archives now include and hash the exact provider/rollback producer and checker sources, provider ELF and indirect-control parsers, `evidence_load_range.py`, runtime identity helper, and build inputs/toolchain outputs. Rollback roots independently include and validate their producer, checker, shared range helper, and parser hashes. Added checksum-refreshed helper-byte tampering tests for both roots.
- [x] Before private evidence parsing, the indirect checker inventories the complete no-symlink/no-special-file root, enforces explicit per-file, aggregate-byte, file-count and directory-count limits, and accounts for every manifest-listed and actual payload file (nested child manifests remain independent closure boundaries). Root-relative `O_NOFOLLOW` descriptor reads are bounded and compare stat identity/size/timestamps before and after, rejecting truncation/growth. External image reads also check the maximum before allocation/read.
- [x] Remove the stale `scripts/evaluator_lib.py` consumer from the active generic-layout contract row only; no evaluator behavior or historical fixture/artifact cleanup was performed.
- [x] Keep the runtime row `unknown` / non-promoted; no PRD acceptance was broadened. Nine parent merge conflict records and the existing merge state remain for parent review; this agent did not stage, commit, push, merge, or archive.

Validation on fresh, unique native AArch64/glibc roots:

- `scripts/run-external-provider-e2e.sh --tier pr --artifact-root .artifacts/indirect-control/provider-checker-integration-20261021T040943-1357` — passed. Provider unit `runtime.indirect-control.external-provider.glibc.host-context-entry`; unit manifest SHA-256 `a58d0e4dd276910b9fec61929f3182c84ff82f572d33fde886e237df8606ca2d`; retained provenance archive SHA-256 `3e945fb4e229ca82597a27a278b54844959bd23980e954f9c4b46368435b92ee`. The producer and checker explicitly recorded the row as not promoted.
- `scripts/run-external-provider-rollback-oracle.sh --artifact-root .artifacts/indirect-control/provider-rollback-checker-integration-20261021T041022-5279` — passed; rollback manifest SHA-256 `e81f1a02c520166ad632902a11fd4d729e2bba1d41fe377dec885fe2eb0bf231` and rollback record confirms 21 lifecycle events, cleanup/release, reload, and rejection.
- With `env -u PYTHONPATH`: the exact positive-provider checker and rollback checker both passed; `python3 -m unittest -v tests.test_external_provider_evidence` passed 27/27, and `tests.test_external_provider_rollback_evidence` passed 6/6 with their exact fresh root environment variables. `tests.test_rehydration_evidence` also passes in the full discovery run, including exact-max/max-plus-one and read-time growth/truncation regressions.
- `env -u PYTHONPATH URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT=<fresh-provider-unit> URP_PROVIDER_ROLLBACK_EVIDENCE_ROOT=<fresh-rollback-root> PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v` — passed, 461 tests, zero skips.
- Shell syntax, Python compilation, `git diff --check`, and `python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-indirect-control-jump-tables` passed; task validation emitted only existing oversized-context injection warnings for curated files. Persistent detailed remediation record: `/tmp/indirect-control-review-remediation-20261021.md`.

No native-positive/general-runtime acceptance was implied. Hosted CI confirmation, musl/Bionic, other provider/table families, and broad indirect-control support remain open. Existing merge-index entries/conflict records were preserved; `git diff --cached --quiet` is false due to the parent’s pre-existing merge state, and no staging operation was performed here.

### Bounded final evidence-reader remediation checkpoint (2026-10-21)

- [x] Close the preloaded sibling-helper cache substitution: use a checker-instance-scoped private module key and require any existing cache entry to be the exact `_RANGE_HELPER` object created by that checker. Add a forged same-origin module test with a copied source-digest marker and malicious replacement export; reject it before source reuse or module attribute execution. Retain the foreign-origin negative. No ambient `PYTHONPATH` imports are used.
- [x] Keep the root-reader contracts bounded before allocation/hash/parse: indirect-control limits are 4096 files, 512 directories including root, and 512 MiB aggregate, with type-specific per-file limits and exact/closed path checks; external-provider limits are 256 files, 32 directories including root, 512 MiB aggregate and 2 MiB/256-entry manifest; source-loader rollback limits are 128 files, 64 directories including root, 256 MiB aggregate and 1 MiB/128-entry manifest. Descriptor reads use no-follow/nonblocking root-relative opens, same-handle pre/post identity and growth probes; tests cover exact/plus-one file/count/aggregate bounds, FIFO/symlink replacement, truncation/growth, and root/manifest closure. The provider output writer now rejects zero-progress writes and advances only by the actual short-write count.
- [x] Re-run ordinary jump-table, shared-table, exact provider positive and rollback root validators after the checker change. The provider positive root remains `.artifacts/indirect-control/provider-reader-final-20261021T054049Z-21474/runtime.indirect-control.external-provider.glibc.host-context-entry` (unit manifest SHA-256 `31cdcdd8a1a2a6560c479e80f8ac6b23edf3182201cd67b0dbae7271da70949c`, report SHA-256 `77c1af9eae73861394abcff7d30b6c5ff236e1d537ea06f687c6af4b8ac49aee`); its own report preserves the `unknown` / `scoped-observation-not-promoted` boundary. Its retained parser digest is `db32856cefd79004b657f15e0dd05d1258e878cea34bbc5ece49f120200066d1`, an internally consistent pre-cache-fix provenance identity; it intentionally does not claim to bind the later current parser (`a8b9567e480b2a528cb177da7443c64bb1394b61994b3335052f0169d9ee669c`). The provider root and its source-hash inventory were not rewritten or regenerated; focused current-checker tests passed against it.
- [x] The first full Python run against the pre-change rollback root correctly failed the retained-source identity test after the checker source changed; the old root was not edited. A separate unique, successful source-loader rollback root was then generated at `.artifacts/indirect-control/provider-rollback-reader-final-current-20261021T061309Z-9939`, leaving the earlier root intact. The new root checker accepted its 21-event cleanup/reload/release record and its manifest is `3ca3d02874deb19adacabe5c3c971d366e69e918a27ab81ffd39f14f3859ab07`.
- [x] With `PYTHONPATH` explicitly unset and these exact positive/rollback roots, full Python discovery passed **470 tests, zero skips**. Log: `/tmp/indirect-control-reader-full-python-20261021T061421Z-10399.log`; exact command: `/tmp/indirect-control-reader-full-python-20261021T061421Z-10399.command`. Focused exact-root suites passed 29/29 (`/tmp/indirect-control-reader-provider-focused-20261021T062926Z-14564.log`) and 7/7 (`/tmp/indirect-control-reader-rollback-focused-20261021T062926Z-14564.log`). Ordinary checker, shared rehydration checker and shared-table checker all passed; exact commands/results are in `/tmp/indirect-control-reader-ordinary-20261021T062907Z-14224.log` and `/tmp/indirect-control-reader-shared-20261021T062907Z-14224.log`. `git diff --check` passed.
- [x] Durable detailed audit, commands, root hashes, source line inventory, and residual runtime limits are recorded at `/tmp/indirect-control-reader-remediation-20261021T0630Z-14564.md`.

Residual: the evidence remains local native AArch64/glibc only. Hosted CI and branch protection have not confirmed the provider lane; musl/Bionic and arbitrary provider/table/indirect-call families remain unknown or unpromoted. The short-write/no-progress writer guard has no test that injects partial or zero `os.write` returns; the manifest-writer path is exercised, and no such failure was observed. Do not treat this checkpoint as child completion or PRD acceptance promotion. No staging, commit, push, merge, reset, stash, archive, or journal/investigation change was performed.

### Current-source jump-table ownership/runtime audit checkpoint (2026-10-21)

- Recorded the source-authoritative ownership classification, current production tests, runtime-lane gaps, and a concrete glibc/musl/Bionic evidence plan in `research/current-owner-and-runtime-audit-2026-10-21.md` (audited at `e281a94`). This is audit/documentation only; no resolver, rehydration, layout, runner, checker, fixture, CI, registry, PRD, or evidence-root behavior changed.
- The bounded in-image signed-relative-32 family is accepted for the exact checked `ADRP/ADD/LDRSW/ADR/ADD/BR` shape. Both positively observed shared ownership and incomplete/ambiguous ownership use a distinct PF_R clone and retarget only the selected function; incomplete inventory remains explicitly incomplete, never a private-owner proof. `GenericRehydrationEngine` rederives the table and carried owner/reference facts from Source Image bytes before Native Image publication, with source/snapshot/layout tamper tests. This closes only the bounded family, not general ownership policy or other table families.
- Current production table behavior evidence remains glibc-only. Existing musl smoke/runtime-matrix and Bionic protection/HostContext jobs do not execute this table fixture or prove selected/unselected transformed behavior. `SelectedFunctionPrivate`, generic external/runtime-owned tables, arbitrary indirect branches/calls, other table encodings and musl/Bionic rows remain unpromoted. The pinned glibc `dlmopen` provider row remains `unknown` / scoped-observation-not-promoted.
- Current-source checks: the focused `RelativeJumpTable|SharedJumpTableOwnerWorkflowTests` managed filter passed 21 tests; `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_bionic_node_runner` passed 40 tests. Neither result executes the native table fixture or explains historical Bionic staged-merge failures.
- Historical Bionic records were preserved as unresolved: the earlier audit lists directory-over-symlink plus two replacement cases; the separate 432-test checkpoint records `symlink-over-directory` with empty stderr. Later 446/470-test passes and this 40-test pass do not identify or repair either historical failure. See the research report for the exact reproduction request and retained risk.
- Native glibc/musl/Bionic E2Es were not run here: this AArch64 environment lacks Docker and `musl-gcc`. The PRD acceptance checkboxes and task status remain unchanged. Existing dirty `.trellis/workspace/SMlc666/journal-1.md` and untracked `research/divergence-integration-investigation.md` were not edited; no artifact root, stage, commit, push, merge, or archive was created.

### Final independent review and merge preflight (2026-10-21)

- Independent reader/cache review returned **scoped PASS, no blocking defect**: `/tmp/indirect-control-final-independent-20261021T065100Z-14564.md`.
- A fresh current-source provider positive was generated at `.artifacts/indirect-control/provider-final-independent-20261021T065100Z-14564/runtime.indirect-control.external-provider.glibc.host-context-entry`; manifest SHA-256 `7846194baf2c90e0183886bdad8548a2485e85dd3cabac3a4ce0286fcf652c86`. Its retained indirect-control, provider, rollback and range-helper sources exactly match the reviewed working source. Historical roots remain unchanged.
- Full Python discovery against that fresh positive and the current-source rollback root passed **470 tests, zero skips**, with `PYTHONPATH` unset; provider 29/29 and rollback 7/7 passed. Ordinary/shared root checkers passed. This supersedes the earlier checkpoint's missing post-cache-fix positive observation, not its historical provenance.
- Parent merge preflight: Release solution build passed with zero warnings/errors; full managed tests **764 passed, zero skipped**; production architecture check and `git diff --check` passed.
- Historical preflight state: provider status remained `unknown` / `scoped-observation-not-promoted`; hosted CI and broader runtime acceptance were open at this checkpoint. The hosted portion is superseded by the observations below; no task completion or archive is implied.

### Reviewed next slice: one ordinary musl table row (2026-10-21)

PR #25 was squash-merged as `e281a94c1b0c57205366534ac8090f8bc4444b3c`. Hosted PR CI `39559228628` passed on head `16825b2` (17 successful jobs, five expected conditional skips); merged-main CI `39561529902` passed (13 successful jobs, nine expected skips). Both retained provider positive and separate loaded-rollback evidence. Hosted provider verification is observed, not pending; final documentation/registry review remains outstanding and the provider row stays unknown/non-promoted. Main-push runtime skips do not establish musl/Bionic table execution.

Independent review accepted the bounded ownership account but required documentation corrections and a concrete runtime identity seam before implementation. Scope remains the existing PRD three-runtime criterion and implementation item 18. The first vertical slice is **one ordinary musl signed-relative-32 table row**, not shared-musl, Bionic, or provider portability. The full ordinary/shared covering set has six rows total: two existing glibc rows and four new rows. Preserve the existing shared registry ID (`runtime.indirect-control.shared-jump-table-copy.glibc.host-context-entry`) and its distinct evidence unit (`runtime.indirect-control.shared-table.glibc.host-context-entry`).

Execution order and review gates:

- [x] Correct the current audit's stale hosted-CI wording, row count and registry/unit distinction. Historical checkpoints, immutable evidence, PRD boxes and protected journal/investigation files are preserved.
- [x] Define a versioned, bounded native handoff identity record and independent verifier. The native source/transformed handoff processes capture mapped runtime files, version, file identity and digests and bind each observation to the handoff/image. The verifier checks retained ELF/maps facts and rejects missing facts, mislabeled family, version/hash/path mutations and source/target disagreements after checksum refresh. Public HostContext ABI and provider semantics are unchanged.
- [x] Add runner-only allowlisted `--runtime glibc|musl` selection to ordinary and HostContext rehydration runners while preserving default glibc behavior. The musl fixture/helper use pinned `musl-gcc` and isolated `BUILD_DIR=build/musl-indirect-control`; paths are plumbed explicitly. Missing architecture/toolchain/loader fails closed without fallback.
- [x] Extend ordinary and rehydration checkers for this row while preserving source/native byte proofs, mapping and clone checks, four results (17, 103, -7, 91), statuses/streams/release and all four actual failed-producer negatives. Root guards, bounded reads and refreshed-checksum semantic tests remain covered.
- [x] Wire the producer and exact-root checker into the existing native AArch64 `musl-container-smoke` job using pinned packages. The job uses a fresh run-keyed root and uploads it. No validated registry claim or PRD checkbox was added.
- [x] Run shell syntax, Python compile/focused evidence tests, fixture/regression validators, native helper compilation, and a fresh native glibc ordinary regression with independent exact-root checks. This local environment has no `musl-gcc` or Docker/Podman, so no local musl execution was claimed.
- [ ] Observe the fresh ordinary musl producer/checker result in the pinned hosted job and obtain independent review before submission. Inspect the uploaded exact-root evidence; do not promote any acceptance/registry claim from CLI wiring or synthetic musl tests alone.

Validation interface now supported: `scripts/run-indirect-control-e2e.sh --tier pr --runtime musl --unit runtime.indirect-control.jump-table.musl.host-context-entry --artifact-root .artifacts/indirect-control/musl-<unique>/ordinary`, followed by `scripts/check-indirect-control-evidence.py` with the same root/tier/runtime/unit and `--require-runtime-identity`. Fresh ordinary glibc invocation similarly requires identity. The pinned musl job supplies the unavailable local toolchain/runtime. Local shell syntax, focused/full rehydration-evidence tests, fixture/regression validation, native helper build, fresh glibc root, and `git diff --check` are recorded below.

Rollback/scope boundary: leave resolver/publication admission, shared runner/checker, Bionic runner, provider `dlmopen`, historical roots and accepted glibc row identities unchanged. An identity or runtime failure publishes no successful evidence row and must not be hidden as a skip. Shared-musl/Bionic, broader ownership, historical Bionic failure causality and the final general resolution-mode/AddressMap report remain open for later slices.

#### Implementation checkpoint and validation (2026-10-21)

- Added `native_process_identity.c/.h` to the native handoff helper and Makefile. Each selected source/target handoff retains a versioned native identity carrier only when explicitly required; musl always requires it. The record binds helper PT_INTERP, mapped loader/libc paths and device/inode, ELF load ranges/bias, retained bytes/digests, runtime version marker, PID, role and exact image SHA-256. Identity reads/writes, maps lines, ELF sizes/headers and aggregate bytes are bounded. Runtime selection remains an evidence-runner option, not a product setting.
- Added `scripts/native_runtime_identity.py` and integrated it into the ordinary/rehydration checkers. Historical glibc roots without the carrier remain accepted in default compatibility mode; any present carrier is always validated; trusted fresh ordinary producer/CI checker invocations pass `--require-runtime-identity`; musl requires identity unconditionally. Glibc `run-host-context-rehydration-e2e.sh` shared-table callers do not gain a new required-carrier flag.
- Added checksum-refreshed tests for runtime family/version/path/file/interpreter/maps/image binding, source-target divergence, optional-vs-required policy, and musl identity facts. When native-image mutation tests refresh the image binding, their test helper also refreshes the native identity carrier so the intended table/layout semantic check remains the rejecting boundary.
- Corrected an observed native glibc issue: the first fresh run at `.artifacts/indirect-control/recovery-20261021T112753Z` was rejected because a valid `/proc/self/maps` `[heap]` row was treated as a file path (`retained process maps line 4 path is not a canonical printable mapped path`). Retained that failed root unchanged. The parser now permits only bounded printable kernel region labels in unrelated maps rows while keeping absolute runtime-file path validation strict; synthetic glibc/musl positive fixtures include `[heap]`.
- Fresh native AArch64/glibc ordinary E2E passed at `.artifacts/indirect-control/recovery-20261021T114759Z-aggregate`. Its unit-level `SHA256SUMS` SHA-256 is `31493f31e1a112d1ccaa35122170957ab9b574a18225c1d02c0b76d220258a75`; the outer manifest SHA-256 is `daaa371be8ea836cefbaa14491e51a3344f230002ba7c3f019cf96a79f483ec5`. Source Image SHA-256 is `bf5f9266255bfb8382455cb298534361cb1abb2690938098f9b1e254df996d06`, Native Image SHA-256 is `ea77b0f656cb4cf79f550f640602df723133bf35518669ca46d9a5ab18f5b577`. Source and transformed identities independently recorded native AArch64 glibc 2.43 in distinct process IDs, with `/lib/ld-linux-aarch64.so.1` resolving to `/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`. The behavior oracle/checker confirmed exact case values `[17,103,-7,91]`, entry/process status 91, empty equivalent streams, and all four producer negatives.
- The runner's nested rehydration check passed, and separate exact-root invocations of `check-rehydration-evidence.py` and `check-indirect-control-evidence.py` both passed with `--runtime glibc --require-runtime-identity`. Both outer and unit `SHA256SUMS` manifests verified with `sha256sum -c`. Retained readelf inspection confirmed helper/libc/loader are ELF64 little-endian AArch64 and helper PT_INTERP matches the native record.
- Validation passed: final native `make ... host-context-image-handoff` with `-Werror`; `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_rehydration_evidence` (58 tests); focused musl/mapping positives and negatives (3 tests, including malformed kernel-region label); fixture validator (13 cases); PR regression validator plus regression unit tests (5 tests); shell syntax; isolated-cache `py_compile`; workflow YAML parsing; and `task.py validate` (existing context-file size warnings only). Final `git diff --check` is recorded in the handoff.
- Local `musl-gcc`, Docker and Podman are unavailable. No musl native evidence or substitute toolchain/container was produced; only synthetic musl checker tests and the existing pinned CI producer/checker wiring were verified. Hosted exact-root result and independent review remain required. No PRD/manifest promotion, status change, staging, commit, push, merge, archive, or protected journal/divergence edit was performed.
- Detailed durable handoff: `/tmp/ordinary-musl-vertical-slice-handoff-20261021.md`.

### Page-rounded PT_LOAD ownership review and spec synchronization checkpoint (2026-10-22)

- The scoped independent review at `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/36cfc61c-7b26-4222-bf58-de4df0aa5636_trellis-check_output.md` found no blockers. Its raw command/results log is `/tmp/pi-subagents-uid-0/async-subagent-runs/36cfc61c-7b26-4222-bf58-de4df0aa5636/output-0.log`; the requested `/tmp` final-report copy did not persist. The review reran equivalent current cases because original probe logs were unavailable and made no repository edits.
- Evidence reviewed: strict `-Werror` C identity self-test passed all 10 cases; four focused Python ownership/boundary tests passed; full Python discovery passed 487 tests with zero skips; provider-positive and provider-loaded rollback suites passed 29 and 8 tests; exact retained ordinary-glibc and provider-rollback roots, independent checkers, and SHA256SUMS manifests passed. The ordinary unit root was `.artifacts/indirect-control/ordinary-musl-va-overlap-repair-glibc-final-20261022T045325Z-3105/runtime.indirect-control.jump-table.glibc.host-context-entry`.
- The ordinary lane is not live musl evidence: `musl-gcc`, Docker, and Podman are unavailable in the review environment. Hosted musl producer/checker result remains pending. Keep glibc scope explicit; do not promote provider, Bionic, shared-musl, or general indirect-control support, and do not change PRD/status/registry or historical evidence.
- Verified the current worktree's seven-section executable runtime contract, backend quality guidance, contract inventory, and current research identity contract cover the exact carrier, runner-only runtime-identity policy, maps/helper/runtime binding, exact-integer schema checks, dual page-rounded `PT_LOAD` file/`p_memsz` ownership, half-open overflow/RELRO rules, 512-directory no-follow root limit, helper loading, and tested/residual evidence boundary. The current research contract already records the same review results; no duplicate contract or PRD/status/registry promotion was added. Older checkpoints and the protected divergence investigation remain unchanged.
- Documentation checks and handoff details are recorded separately; this is docs-only, not feature completion or promotion. No product/app/native/full-suite run, workflow/fixture/registry change, evidence mutation, staging, commit, push, merge, reset, stash, or archive is part of this checkpoint. Preserve `.trellis/workspace/SMlc666/journal-1.md` and `research/divergence-integration-investigation.md` byte-for-byte; the parent owns any commit or hosted-CI follow-up.

### PR #29 musl fixture-link failure and diagnostics contract (2026-10-22)

- PR run `39752657696` (job `119736825534`) failed before the jump-table checker or runtime-identity validation: Makefile's assembly-fixture `.so` recipe invokes `$(LD)` with linker-only `--build-id=none`, `--no-undefined`, and `--eh-frame-hdr`, but the runner passed `/usr/bin/musl-gcc` as `LD`. The GCC driver rejected those options. This is a fixture-build command failure, not evidence of a musl loader/runtime-identity defect.
- The bounded fix preserves `CC=musl-gcc` for C/helper builds and sets `LD=ld` for direct linker recipes in both ordinary and HostContext runners. The ordinary runner records Make stdout/stderr under `ordinary/`; its sibling `ordinary.native-build-diagnostics/` stores exact status and command metadata (runtime, build cwd, shell-escaped argv). The `if: always()` upload covers their shared run-specific parent.
- Added executable regression `test_musl_jump_table_runner_retains_and_propagates_stubbed_make_failure`: a copied runner runs under hermetic fake tools; fake `make` emits distinct streams and exits 23. It verifies the runner propagates 23, exact streams/status/cwd/argv and upload-parent containment, and does not invoke the availability-only compiler stub. The focused `test_rehydration_evidence.py` suite passed 69 tests locally; final scoped independent review `/tmp/pr29-musl-build-fix-final-independent-review.md` returned PASS and reran both focused regressions, shell syntax and `git diff --check`.
- Hosted rerun of the repaired ordinary musl producer plus exact-root checker with `--require-runtime-identity` remains pending. Separate Node.js and Alpine libarchive acquisition failures remain unchanged: their pinned downloads returned HTTP 404 before sample parsing/execution. No support promotion, registry/CI/PRD change, or historical evidence rewrite is implied.

### PR #29 musl helper-link and incremental-rebuild spec sync (2026-10-22)

- Hosted PR run `39774401348` built the ordinary musl jump-table fixtures successfully (`ordinary.native-build-diagnostics/native-build.status` was `0`), then the nested HostContext helper link failed because GCC's outlined-atomics `libgcc.a(lse-init.o)` referenced glibc-internal `__getauxval`, absent from musl. The historical nested Make numeric exit was not retained. This was a build/link boundary failure; no runtime identity or behavior evidence was produced.
- The bounded repair uses musl-only `HOST_ADAPTER_CFLAGS=-mno-outline-atomics` for `host_adapter.o` only, leaving normal `CFLAGS` unchanged. An object-specific `host_adapter.compile-config` stamp records effective `CC`, `CPPFLAGS`, `CFLAGS`, and `HOST_ADAPTER_CFLAGS`; the same-`BUILD_DIR` regression proves default → musl → unchanged musl → default invokes the compiler `1, 2, 2, 3` times. One independent Make writer per `BUILD_DIR` is required.
- Nested command/cwd/runtime, stdout, stderr, and numeric status are retained under the uploaded sibling diagnostics root, outside the positive evidence unit. The nested runner exits with the actual Make status and the ordinary runner propagates it; the nested fake-Make status-23 regression verifies exact streams and status.
- The final independent review `/tmp/pr29-musl-helper-final-independent-review.md` returned PASS; its final focused suite passed 71 tests, including the configuration-stamp sequence and nested status-propagation case. This is review/test evidence only, not a hosted musl rerun. The pinned hosted producer and exact-root checker with `--require-runtime-identity` remain pending; no runtime promotion or ABI/identity-contract change is implied.
- This documentation-only sync changes only `.trellis/spec/backend/quality-guidelines.md` and this `implement.md`; no source/test/CI/registry/journal/research files or task pointers/status were changed. Task validation and `git diff --check` are recorded with this sync; no commit, push, merge, CI retry, or nested agent was used.
