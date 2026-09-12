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

## Known scope

No custom ELF loader, relocation application, shared-object wrapping, Android
execution, encryption, signatures, anti-debugging, stealth, or host-architecture
fallback belongs in Wrapper 0.2.
