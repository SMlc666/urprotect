# External-table nearest-negative implementation handoff

**Disposition:** completed the bounded, fail-closed external-table negative slice only. This is evidence of the current producer's rejection boundary, not external-table support, imported function-pointer support, or a change to indirect-call admission.

**Authoritative output:** `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/outputs/be02be41-f2b6-4dc8-a663-9c0969407e34/.trellis/tasks/10-06-indirect-control-jump-tables/research/external-table-negative-implementation-handoff.md`

**Durable child handoff:** `.trellis/tasks/10-06-indirect-control-jump-tables/research/external-table-negative-implementation-handoff.md` (same contents).

## Task and scope

`python3 ./.trellis/scripts/task.py current --source` reported `.trellis/tasks/10-06-unify-elf-protection-infrastructure` as the active parent. No task was created, activated, archived, or status-changed. The child and parent remain `in_progress`. The prior research handoff was read completely first; `/tmp/urprotect-research-timeout-20261015T222456Z` was not accessed or changed.

The new evidence uses one separate assembly fixture and one new negative row. Existing positive, malformed/out-of-closure, out-of-range, and index-clobber fixtures/evidence were not edited. The accepted schema-2 positive root was copied and hash-compared by the runner; positive native execution was not rerun and the origin was not written.

## Changed paths

- `native/urprotect-runtime/host_context_external_jump_table_fixture.S` — new AArch64 guarded GOT-imported-object dispatch fixture.
- `native/urprotect-runtime/Makefile` — fixture target/object registration.
- `scripts/run-indirect-control-e2e.sh` — builds the fixture, retains its readelf/fact report, and invokes it as `negative-external-table` through the real producer flow.
- `scripts/check-indirect-control-evidence.py` — bounded PT_DYNAMIC/GNU-hash/dynsym/DT_RELA/PT_LOAD parser, instruction/dataflow binding, and external negative validation/inspection mode.
- `tests/test_rehydration_evidence.py` — sectionless synthetic external-table evidence and refreshed-checksum owner/link/diagnostic/stage tamper negatives.
- `.trellis/spec/backend/quality-guidelines.md` — external-table nearest-negative evidence contract; no support claim.
- `fixtures/manifest.json` — fixture/evidence inventory and fail-closed-only constraint.
- `tests/regression-matrix.json` — external-row artifact paths.
- `.trellis/tasks/10-06-indirect-control-jump-tables/prd.md` — child progress wording; ambiguity and support remain open.
- `.trellis/tasks/10-06-indirect-control-jump-tables/implement.md` — bounded slice progress and validation record.
- `.trellis/tasks/10-06-indirect-control-jump-tables/research/external-table-negative-implementation-handoff.md` — durable copy of this handoff.
- The configured authoritative output path above.

No managed C# source, accepted positive fixture source, TLS/CFI implementation, CI workflow, parent PRD, or task status was changed for this slice.

## Fixture ELF facts (independently reparsed from retained bytes)

Build command `make -C native/urprotect-runtime external-jump-table-fixture` passed on native AArch64. `readelf -hW -lW -rW -Ws` and the evidence checker's independent PT_DYNAMIC-based parser agree:

- ELF64, little-endian, `ET_DYN`, `EM_AARCH64`.
- Selected function: `.dynsym[4]`, `urp_entry`, `STT_FUNC`, global/default, defined in section 5, VA/file offset `0x2d0`, size `0x48` (72 bytes), mapped in executable `PT_LOAD`.
- Imported object: `.dynsym[2]`, `urp_external_jump_table`, `STT_OBJECT`, global/default, exact `st_other=0`, `SHN_UNDEF`, `st_value=0`, `st_size=0`. Its payload has **no Source Image file range**.
- Exact non-PLT relocation: the single matching `DT_RELA` row is `R_AARCH64_GLOB_DAT` type 1025, `r_offset=0x1fff8`, `r_info=0x200000401`, dynsym index 2, symbol name `urp_external_jump_table`, addend 0; no matching PLT relocation or conflicting relocation at that slot.
- The relocation slot maps uniquely to eight file-backed bytes at file offset `0xfff8` in a writable/readable `PT_LOAD` (flags `6`, RW); its initial bytes are zero. It is the imported-object **pointer carrier only**, not table storage.
- The selected-function bytes bind the relocation to the branch dataflow: `CMP W0,#3` at `0x2d0`; `B.HI` at `0x2d4` to in-function default `0x310`; `ADRP X9` at `0x2d8` plus unsigned `LDR X9,[X9,#4088]` at `0x2dc` computes exactly `0x1fff8`; signed indexed `LDRSW X2,[X9,W0,UXTW #2]` at `0x2e0`; `ADR X3` at `0x2e4` computes relative base `0x2f0`; `ADD X1,X3,X2` at `0x2e8`; and `BR X1` at `0x2ec`.
- The guard bounds unsigned W0 to `[0,3]`, i.e. a 16-byte bounded indexed read of signed 4-byte entries. That access extent is inferred from the code/guard; the import's dynamic symbol size is zero and no provider DSO/table payload was loaded or verified.

Retained source SHA-256: `c3584835e47f6a1bdd9c17f62bb83a145f7aa9af2ec6c5be877e2508f436f442`.

## Actual producer observation

The prediction was tested against the built fixture before recording the negative claim. The final root retains the actual `protect-image` `argv`, source digest, stdout/stderr bytes and hashes, structured stage, exit status, and no-publication check. Selected identity is `dynsym:4`; producer build SHA-256 is `27cf73829c698da9b9614e7e8c41163e4bb88ce0451df5d993b0916a9b0efb50`.

Observed result:

- Exit status: `4`.
- Stage: `protected-image-producer`; `status=failed`, `firstFailureStage=protected-image-producer`, `transformationStatus=failed`, `publicationComplete=false`.
- Diagnostic at offset `748` (`0x2ec`): `IndirectTargetUnresolved: The selected instruction does not match the promoted relative jump-table family.`
- Producer stderr is empty (SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
- No Protected Image artifact/role, Native Image, rehydration record, source/transformed handoff, loader record, or loader invocation was published.

This is the generic promoted-family mismatch, not an external-owner-specific diagnostic and not evidence that the resolver classified the import as externally owned.

## Fresh retained root and checker results

Final fresh root: `.artifacts/indirect-control/external-table-negative-final-20261015T230806Z-c521ea55`.

Exact producer/evidence command:

```sh
scripts/run-indirect-control-e2e.sh --tier pr --artifact-root .artifacts/indirect-control/external-table-negative-final-20261015T230806Z-c521ea55 --reuse-positive-root .artifacts/indirect-control/check-final-20261015T142238Z-13922
```

Result: passed. It reused the accepted schema-2 positive by the existing closed-file inventory/hash comparison and executed all four actual fail-closed producer negatives; it did not rerun positive source/transformed execution.

Standalone checker command:

```sh
python3 scripts/check-indirect-control-evidence.py .artifacts/indirect-control/external-table-negative-final-20261015T230806Z-c521ea55 --tier pr --unit runtime.indirect-control.jump-table.glibc.host-context-entry
```

Result: `Indirect-control evidence valid: all table cases, measured handoff/streams, and four fail-closed negatives`.

Fresh outer `SHA256SUMS` SHA-256: `e4084d4e1971f84e68f8e3f6156bef76812515898ed4636cf500dd3fc134aedf`. Retained external facts SHA-256: `0bc11a0289d7478876ae9df2f99b99379ac510d3a9c0f7bcb436585decfd6f9d`. Retained `negative-result.json` binds producer exit 4, source hash, command/stdout/stderr hashes, external-facts hash, diagnostic, and failed stage.

Reused positive origin remains unchanged: its inner `SHA256SUMS` SHA-256 is `844433bc16fc954c3de7c2fd85be08c6a2c25d4bb2561c59bbaf5698265da6b2`; its Native Image SHA-256 is `33766fb3d7dcd4778ce78f1f9a2d13a7525b9a6d44c1dff765921bdc2d4db681`. The positive reuse record says `positiveExecutionRerun=false` and binds the source outer manifest hash. The external row directory retains only its source ELF, external facts/readelf report, producer argv/stdout/stderr/exit/stage, and negative-result record; no downstream publication artifacts exist.

## Commands and results

- `python3 ./.trellis/scripts/task.py current --source` — passed; resolved the active parent, no workflow status changes.
- `dotnet build UrProtect.sln --configuration Release --no-restore` — passed, zero warnings/errors. No managed source changed afterward.
- `make -C native/urprotect-runtime external-jump-table-fixture` — passed; linker output contains the expected undefined OBJECT/GLOB_DAT facts.
- Actual `protect-image` probe on the new fixture — observed exit 4 and the exact diagnostic/stage above.
- `python3 -m unittest discover -s tests -p 'test_rehydration_evidence.py' -v` — passed, 33 tests, including refreshed-checksum owner identity, relocation, GOT/dataflow, diagnostic, and stage tampering.
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr` — passed, 13 cases.
- `python3 tests/test_regression_matrix.py` — passed, 5 tests.
- `python3 scripts/check-architecture-boundaries.py` and `--self-test` — passed; focused `test_architecture_boundaries.py` — passed, 4 tests.
- `python3 scripts/check-aarch64-encoding-boundary.py` and `--self-test` — passed; focused `test_aarch64_encoding_boundary.py` — passed, 3 tests.
- `bash -n scripts/run-indirect-control-e2e.sh`, Python `py_compile` for the checker/test module, and `git diff --check` — passed.
- No focused managed jump-table test was run because no managed source changed. Native positive execution and broader TLS/CFI E2E were not rerun.
- `git diff --cached --name-only` — empty; no files were staged or committed.

## Remaining blockers and limits

External table support and provider/runtime resolution remain open. This row does not execute the imported table, prove a DSO provider or its payload range, change indirect-call admission, or claim generic ownership classification. Ambiguous tables, imported function-pointer support, musl/Bionic jump-table runtime rows, and broader parent TLS/CFI gaps remain open. The checker is deliberately scoped to bounded ELF facts and the fixture's exact dispatch family; it is not a general dynamic-linker or external-object resolver.
