# Native Launcher Research

## Existing frame and runtime facts

- Wrapper 0.1 stores a 112-byte `URPCK01` header, a UTF-8 source basename,
  raw-deflate encoded bytes, and a 24-byte `URTRAIL1` trailer at EOF.
- The managed encoder uses raw deflate; a native decoder must not enable
  miniz's zlib-header mode.
- The managed launcher reads `/proc/self/exe`, validates the frame, extracts to
  a temporary directory, sets `argv[0]` to the stored basename, and calls
  `execve`.
- A static AArch64 PIE can be `ET_DYN` without `PT_INTERP`; launcher
  classification must distinguish it from a shared object.

## Native dependency decision

- Use one static AArch64 PIE launcher built with the pinned ARM64 musl/static
  toolchain so it does not depend on the target's glibc, musl, zlib, libcrypto,
  or .NET runtime.
- Use miniz tinfl only for raw-deflate decoding. The pinned research checkout
  is Git commit `77d0dce8627735138c51770d1799a1ef48f2117d`; upstream describes
  it as MIT licensed and provides the low-level inflater in `miniz_tinfl.c`.
- Keep SHA-256 project-owned and test it against standard vectors and .NET;
  do not add a general crypto runtime dependency.

## Security/compatibility decisions

- Locate the wrapper through `/proc/self/exe`, not `argv[0]`, environment, or
  current directory.
- Use a fixed private `0700` temporary directory and basename-only filename;
  reject `.`, `..`, separators, NUL, invalid UTF-8, and oversized names.
- Verify encoded digest, exact decompressed size, source digest, and minimal
  AArch64 `ET_DYN`/executable-entry/`PT_INTERP` identity before `execve`.
- Keep temporary-file `execve` as the 0.2 handoff. Unlink-before-exec,
  `fexecve`, `execveat`, and `memfd_create` need a separate kernel/libc
  compatibility contract.

## Implementation evidence

- The native launcher carries the frozen marker
  `URPROTECT-AARCH64-LAUNCHER-V1`. `ElfPackService` requires that marker,
  static-PIE classification, an executable entry mapping, and no `DT_NEEDED`
  entries before it accepts a launcher; `pack` has no managed-launcher
  fallback.
- A reproducible AArch64 build with `SOURCE_DATE_EPOCH=0` produced a
  669,368-byte static launcher. The retained Wrapper 0.1 self-contained
  launcher was 75,683,760 bytes in the same workspace, so the native runtime
  is materially smaller. Two clean native builds compared byte-for-byte.
- Native self-tests cover SHA-256 vectors and raw-deflate decoding. The
  integration harness covers valid execution, repeated wrapper bytes,
  arguments, `argv[0]`, environment, cwd, generated output, non-zero exit,
  signal status, truncation, digest/tamper, wrong ABI fields, unsafe basename,
  bounds overflow, trailing deflate data, invalid interpreter, and exec
  failure. Failure artifacts can be retained under the CI artifact root.
- Release archives contain the native launcher, self-test, source tree,
  miniz license/commit material, and provenance. Release smoke verifies the
  launcher hash from provenance and runs the self-test before packing.
- Two complete `0.2.0` package runs with the same `SOURCE_DATE_EPOCH=0` and
  pinned inputs produced byte-identical glibc and musl tarballs after removing
  the temporary build path from the `file` evidence.
- CI installs the exact Ubuntu Noble `musl`, `musl-dev`, and `musl-tools`
  package versions selected for the native ARM64 jobs; provenance records the
  compiler path/hash/spec hash and installed package versions when available.
- CI run `34693063892` exposed two portability details: the Debian Bookworm
  musl 1.2.3 specs selected `Scrt1.o` and injected `PT_INTERP` despite
  `-static-pie`, so the build now uses the checked-in `musl-static-pie.specs`
  fragment (selecting `rcrt1.o`) plus an explicit `--no-dynamic-linker`; signal
  assertions compare the wrapper with a baseline shell because `timeout`
  reports signal exits differently across runner images.
- CI run `34711783556` passed the native ARM64 glibc packed fixture matrix and
  the pinned ARM64 musl container smoke after that fix. Release rehearsal
  `34712246157` additionally passed package generation, native launcher
  provenance/self-test checks, and release smoke for both ARM64 bundles.

## Known scope

No custom ELF loader, relocation application, shared-object wrapping, Android
execution, encryption, signatures, anti-debugging, stealth, or host-architecture
fallback belongs in Wrapper 0.2.
