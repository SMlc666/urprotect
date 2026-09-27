# Runtime matrix expansion audit

## Result

The selected AArch64 runtime covering set is implemented, retained, and
validated on the production-native runner. The registry is
`fixtures/runtime-matrix.json`; the SHA-256-locked musl source toolchain is
`fixtures/runtime-matrix-toolchains.json`. The same runtime oracle and cell
definitions serve PR, nightly, and release tiers.

The six registry cells cover current native Ubuntu 24.04/glibc, pinned older
Ubuntu 22.04/glibc, source-built musl 1.2.4, pinned Alpine/musl 1.2.5, the
existing locked Termux/bionic lane, and a native 16KiB page-size probe. The
probe observed a 4096-byte kernel page size and recorded
`environment-unavailable`/`unknown` for the 16KiB kernel claim. Separate
linker-produced 16KiB `PT_LOAD.p_align` witnesses were validated and run in
the claimed user-space cells; they are not described as a 16KiB-kernel claim.

## CI evidence

| Tier | GitHub Actions run | Commit | Result |
|---|---:|---|---|
| PR | `36290915990` | `9856887648ad6aef8c36d0a1c1d8a9c9e6cefff6` | build/test, 20-identity real-sample, bionic, PR runtime matrix passed |
| Nightly rehearsal | `36291070139` | `9856887648ad6aef8c36d0a1c1d8a9c9e6cefff6` | extended fixtures, fuzz/stress, containers, musl, real-sample, bionic, and runtime matrix passed |
| Release rehearsal | `36292019899` | `9856887648ad6aef8c36d0a1c1d8a9c9e6cefff6` | release fixture, runtime matrix, glibc/musl package smoke and remaining jobs passed after retrying a transient Termux archive timeout |

Both retained nightly and release runtime artifacts were independently
downloaded and checked against the combined SHA256SUMS manifest. Each manifest
covered and verified 4,484 runtime and bionic evidence files, including hidden
musl source-build files. `include-hidden-files: true` is scoped to the runtime
matrix evidence upload so every hashed file is actually retained.

The release manifest's `validated_claim_cells` exactly matches the five
validated runtime claims. `kernel-page.16k.native-aarch64` is listed in
`selected_cells` but not in `validated_claim_cells`; its 4KiB host observation
preserves the required unknown status. Release bundle smoke passed and the
actual release publication step was skipped by the non-publishing rehearsal.

## CI-driven corrections

The acceptance work proceeded from retained CI failures rather than relying on
local emulation:

1. The source-built musl cell initially omitted the native Ubuntu identity;
   runner OS ID/version facts were added.
2. The source-built loader's recorded identity is its pinned `libc.so` image,
   not a basename ending in `ld-musl-aarch64.so.1`; the evidence gate now
   checks the exact loader path and resolved source-build image.
3. The run intentionally removes its temporary interpreter symlink before the
   evidence gate re-executes binaries; the gate now uses the pinned loader
   directly for those exact musl fixtures.
4. Alpine's musl cell previously attempted to resolve the nonexistent glibc
   interpreter path first; the in-container probe now selects an executable
   loader path from the declared runtime and verifies it before resolution.
5. Runtime SHA256SUMS included a hidden source file omitted by the default
   upload behavior; the runtime artifact now retains hidden files, and the
   post-download checksum audit confirms complete retention.
6. One release workflow attempt experienced a transient timeout fetching the
   locked Node.js package from `packages.termux.dev`. Rerunning the failed job
   passed the full real-sample matrix; the initial runtime/release jobs were
   already green and their retained release evidence was independently
   verified.

## Local checks

- `python3 tests/test_runtime_matrix.py` — 13 tests passed.
- `python3 tests/test_regression_matrix.py` — 5 tests passed.
- `python3 scripts/validate-runtime-matrix.py fixtures/runtime-matrix.json` —
  six named AArch64 cells and reviewed interactions validated.
- `bash -n scripts/run-runtime-matrix.sh` and Python byte-compilation passed.
- Final CI's managed/native build, runtime gates, evidence gates, nightly fuzz
  and stress tiers, and release package smoke passed as listed above.

## Claim limits

- No native 16KiB kernel was available; that runtime claim stays `unknown`.
- The bionic claim remains limited to the locked Termux/container baseline.
- Container rows share the native host kernel; they do not introduce a new
  kernel page-size claim.
- Musl 1.2.4/1.2.5 and glibc 2.35/2.39 are the only named runtime versions in
  this covering set; other versions are not inferred.
