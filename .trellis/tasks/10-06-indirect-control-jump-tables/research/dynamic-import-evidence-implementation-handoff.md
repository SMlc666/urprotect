# Dynamic imported-call evidence implementation handoff

Date: 2026-10-16
Task: `.trellis/tasks/10-06-indirect-control-jump-tables`

## Result

Completed one bounded native AArch64/glibc HostContext GLOB_DAT indirect-call evidence slice without closing the child or promoting a broader feature. The project-built `urp_entry` imports and calls `getpid` through ADRP/GOT-LDR/BLR (`x9`). It passes zero to `getpid`; only a positive PID returns status 97, while a nonpositive return takes the fail-closed status 96 path. The caller LR is saved/restored around the non-leaf call.

A fresh run of `scripts/run-dynamic-import-e2e.sh --tier pr --artifact-root .artifacts/dynamic-import/recovery-glibc-20261018d` passed end to end. The runner's fixture build stage reported `Nothing to be done`, after the completed fixture build had been inspected for current inputs/output timestamps. Source and transformed HostContext handoffs both passed entry dispatch and release with entry/process status 97. The retained source and transformed stdout/stderr files are all zero bytes and have the same SHA-256. The generic Protected Image corruption negative returned 5 with `ProtectedImageIntegrityMismatch` at rehydration, entry `not-run`, and no Native Image or loader handoff publication.

## Independent ELF / handoff facts

Evidence directory:

`.artifacts/dynamic-import/recovery-glibc-20261018d/runtime.host-context.dynamic-import.glibc.host-context-entry`

The evidence report (`dynamic-import-evidence.json`) and its closed `SHA256SUMS` manifest are present there. Runtime identity is native AArch64, glibc 2.43. The checker independently parses and binds both the project Source Image and transformed Native Image:

- `urp_entry`: dynsym index 3, VA/file offset `0x1d8`, size 60 bytes.
- Undefined `getpid`: dynsym index 2.
- Non-PLT `R_AARCH64_GLOB_DAT`: type 1025, relocation target/GOT VA `0x1fff8`, file offset `0xfff8`, writable 8-byte slot in the file-backed PT_LOAD.
- Source call: address `0x1f0`, BLR through target register `x9`; source fail-closed branch target `0x208`; success/failure statuses 97/96.
- Source handoff SHA-256: `b6d7926b5f2b020065acf7febe4cdc85b1f3ba643e95da35344f91bb3bb7e6bb`.
- Transformed handoff SHA-256: `d697bb5b0bc2e6f239c966ca917928ed1b59f7f2c83c2eb1ebc43be6a1a70e01`.
- Source / Protected / Native Image SHA-256: `844546d3561ff89113c960b1ef18f6b668b1375f0efff656bef9b21a52515bea` / `849cf17432b927d93f3e818b72722e8aec3813e9c722d1c439459c59324626ee` / `76d6a405f5810ee3b57f9f8906c2c554c7bdb9ffce008c99f7b692767e73871b`.
- Negative failed rehydration record SHA-256: `48aadf5e81ee9deecd52dc45878e2b63e8bf7267c32ec8e1270631d0e91efdc4`.
- Evidence report SHA-256: `27a23fcb8340dcad98241f0ce48d736374176d27b5af944ebdfc47e71d4294ed`.
- Closed manifest SHA-256: `b690b7489bd94e5898e255d8c140ba7c29c217df0f37a6468635c97010037468`.

The immutable retained report's embedded `acceptanceState` remains `scoped-observation-pending-independent-review`; the subsequent checker-only identity remediation and its review are recorded below. This remains one scoped glibc HostContext import observation, not broad feature promotion.

## Managed owner / tamper evidence

`DynamicImportOwnerWorkflowTests` exercise the project fixture through typed semantic snapshot, Protected Image, and successful `GenericRehydrationEngine` Native Image publication. The test also binds owner fields to independently parsed source ELF dynsym/RELA/GOT data. The 14 focused cases cover refreshed-checksum tampering in the call/GOT/RELA/dynsym/address map, producer/address/owner edges, omitted clobber, and forged non-import-runtime cases. The separate Python evidence checker independently parses bounded ELF PT_LOAD/PT_DYNAMIC/GNU-hash/dynsym/RELA facts, ties the source oracle and Native Image import facts to actual retained files/handoffs/streams, validates the negative rollback records, and enforces a closed manifest. Three refreshed-checksum semantic-claim tampering tests, truncated-ELF rejection, and closed-manifest dangling-symlink rejection are in `tests/test_dynamic_import_evidence.py` (4 focused tests total).

## Validation performed

Passed:

- `scripts/run-dynamic-import-e2e.sh --tier pr --artifact-root .artifacts/dynamic-import/recovery-glibc-20261018d` (native runtime source/transformed + negative E2E and checker).
- `python3 -m unittest discover -s tests -p 'test_dynamic_import_evidence.py' -v` (4 tests).
- `python3 -m unittest discover -s tests -p 'test_rehydration_evidence.py' -v` (23 tests).
- Focused `DynamicImportOwnerWorkflowTests` (14 cases; Release solution build had zero warnings/errors).
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr` (13 cases).
- `python3 scripts/validate-regression-matrix.py tests/regression-matrix.json` (24 cases).
- Architecture and AArch64 encoding boundary production/self-test commands and unit suites (4 and 3 tests, respectively).
- `bash -n scripts/run-dynamic-import-e2e.sh`, `python3 -m py_compile scripts/check-dynamic-import-evidence.py tests/test_dynamic_import_evidence.py`, dynamic evidence checker, and `git diff --check`.

No staging or commit was performed. The large pre-existing dirty working tree was preserved. No task status/closure changes were made.

## Independent review follow-up (scoped PASS)

The initial independent review blocked only the checker’s runtime-version integrity: a checksum-refreshed false `glibc` version was accepted. The checker was changed to require producer-local `verify_identity(..., verify_current_process=True)` with no portable fallback, and the regression now rejects the forged version and unavailable runtime measurement after valid checksum refresh. A fresh read-only review returned a scoped PASS for this remediation, confirming the checker binds libc/loader files and complete identity to the current native process and that the false-version/unavailable-measurement negatives are adequate. The retained checker and five focused Python tests passed afterward, and the identity/report/SHA256SUMS hashes remained unchanged. The native E2E was not rerun after this checker-only change.

This closes the identified runtime-identity checker finding for the retained GLOB_DAT/getpid slice; it does not claim general imported-call support, cross-runtime behavior, or child/parent completion. The retained report's embedded pending-review marker is preserved as historical evidence metadata.

## Remaining scope / risks

- Additional import call sequences / owner classes, broader dynamic-linking policies, other table families, and native musl/bionic rows are not established by this evidence.
- The parent/child task remains in progress. No broad compatibility or feature promotion should be inferred from this slice.
