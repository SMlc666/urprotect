# UrProtect native launcher

This directory contains the current `outer-execveat` profile launcher for Linux
AArch64. It is intentionally separate from the C# packer: the packer validates
the source ELF and appends the current v3 frame, while this executable only
discovers its own profile frame, verifies and inflates the payload, and hands the
recovered program to `execveat(AT_EMPTY_PATH)`.

Build on a native AArch64 host with the pinned musl toolchain used by CI:

```sh
./build.sh
./build.sh test
```

The output is a static `ET_DYN` PIE with no `PT_INTERP` or `DT_NEEDED` entries.
The checked-in `musl-static-pie.specs` fragment selects musl's `rcrt1.o` and
suppresses the interpreter on older Debian musl-gcc packages. `CC` may be
overridden for an explicitly identified AArch64 cross compiler in local tests,
but required CI jobs must use the pinned native ARM64 toolchain.
The build records compiler, linker, miniz, source-hash, and launcher-hash
information in `build/PROVENANCE.txt`.

The launcher uses the current raw-deflate frame and SHA-256 implementation in
this repository. It rejects stale versions, non-outer profiles, malformed
trailers, unsupported frame metadata, unsafe basenames, digest mismatches,
invalid recovered ELF files, and failed memfd_create/execveat operations
without invoking a shell. The recovered payload is never written to an
executable temporary pathname.
