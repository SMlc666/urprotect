# Bionic ordinary/shared jump-table evidence slice — implementation checkpoint

**Task:** `.trellis/tasks/10-06-indirect-control-jump-tables`
**Scope approval:** supervisor authorized a strictly evidence-only Bionic identity extension and pinned-container bridge. No product, HostContext/frame ABI, runtime-behavior, resolver/admission, or support-promotion changes. No staging/commit/push/merge.

## Implemented

- Added private Bionic runtime identity schema/carrier v2, keeping glibc/musl v1 unchanged. Bionic `runtimeVersion` is exactly `null`, with source marker `bionic-semantic-version-not-claimed`; the record fingerprints the live retained `libc.so` and `/system/bin/linker64` bytes. Capture/checker independently bind exact Bionic `PT_INTERP`, process maps, file/device/inode/size/hash/ELF facts and image/role. The checker verifies exact locked fixture image/package/source facts, exact-integer schema/page-size fields, and bounded regular-file reads; no libc release string or unobserved content-digest pin was invented.
- Added a narrow host-owned container bridge to execute the already-built managed source/Native Images only in the existing digest-pinned Termux image. It requires matching image identity and maps only retained evidence paths into the container. Added Bionic ordinary/shared runner selection, fresh roots, runtime identity capture for both ordinary source/target and all four shared selected/observer handoffs, RELR-disabled fixture builds, source-relative AArch64 assembler wrapper for the index-clobber negative, and exact-root checker wiring.
- Gated the Bionic indirect-control slice inside the existing native ARM64 Bionic CI job. Its checker step independently reruns ordinary/shared and rehydration checks; artifact upload now explicitly enables `include-hidden-files: true`. Added a workflow regression and a Bionic shared-identity agreement regression. Backend runtime-compatibility spec now describes the evidence-only contract and explicitly leaves both rows unknown/non-promoted.

## Local verification

- `env -u PYTHONPATH python3 -m unittest discover -s tests` — **496 passed, 2 skipped**.
- Focused Bionic identity/workflow tests — **6 distinct cases passed across focused runs**; includes exact-integer schema/page-size tampering.
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr` — 13 fixture cases validated.
- `python3 scripts/validate-regression-matrix.py tests/regression-matrix.json --tier pr` and `python3 tests/test_regression_matrix.py` — passed (6 tests).
- Workflow YAML parse, shell syntax checks, `git diff --check`, local AArch64 fixture/helper builds, native identity self-test, HostContext self-test, `-D__ANDROID__` syntax/build check, and assembler-wrapper AArch64-object checks — passed.

## Exact live-runtime blocker / residual risk

This host is native `aarch64`, but neither Docker nor Podman is installed. Therefore no pinned Termux container was started: actual Bionic mapped `libc.so`/loader path, device/inode, bytes/digests, kernel/page-size provenance, live `/proc/self/maps`, managed-produced Bionic execution, and the final pinned-lane ordinary/shared exact roots are **not observed locally**. The implementation fails closed unless the existing locked native CI lane provides these facts. Do not claim Bionic runtime evidence passed or infer a Bionic release/pin from assumptions. Hosted native ARM64 CI remains the required final observation; if the locked image exposes different mapping facts or fails the mapping proof, retain its diagnostics and correct only from observed facts.

The implementation intentionally did not edit task acceptance/status, fixture promotion metadata, product code, historical evidence, or unrelated dirty files.
