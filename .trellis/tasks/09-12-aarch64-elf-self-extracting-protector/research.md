# Self-Extracting Protector Research

## Repository evidence

- The existing parser and validator can validate the source snapshot and the
  launcher without serializing either ELF model.
- The existing product is published as a self-contained `linux-arm64` single
  file, so it can serve as the first launcher without adding a second native
  toolchain or runtime dependency.
- Appending bytes after the launcher's program-header ranges does not change
  its ELF load model; the launcher can read its own complete file and locate a
  fixed trailer.

## First-slice decisions

- The frame uses fixed little-endian fields, version 1, deterministic deflate,
  source and encoded SHA-256 values, source architecture/type, bounded source
  basename, and trailer offsets/lengths.
- The runtime extracts to a private temporary directory and uses the source
  basename for both `argv[0]` and the final temporary filename. This preserves
  multi-call program dispatch that depends on `AT_EXECFN` more reliably than a
  random temporary filename.
- `execve` receives a reconstructed UTF-8 argument/environment array and
  inherits the current working directory and standard streams. The source
  program's `/proc/self/exe` and temporary extraction directory are known
  differences and are not hidden as compatibility guarantees.
- `RPATH` and `RUNPATH` are rejected because `$ORIGIN` resolution would change
  when the source is extracted to a temporary directory.
- A custom in-process ELF loader, `memfd_create`/`execveat`, shared-object
  wrapping, Android execution, encryption, and stealth behavior remain
  separate scope.

## Local evidence

- The native ARM64 PR covering set (GCC/Clang C/C++, Rust, and Go) was built,
  packed with a self-contained ARM64 launcher, and executed successfully. Each
  wrapper differed from its source and matched baseline status/stdout/stderr.
- A real `/bin/echo` wrapper was tested with arguments; the source basename
  handling preserved multi-call dispatch and produced the expected output.
- Tampering with the compressed frame produced exit code 5 and prevented the
  payload from launching.
- The ARM64 Debian musl-container job uses the glibc self-contained launcher to
  wrap and execute the musl fixture. The container's Debian userland can run
  that launcher, while the recovered fixture still enters through
  `/lib/ld-musl-aarch64.so.1`; publishing the launcher itself as a musl .NET
  single-file binary would require additional musl-compatible C++/zlib runtime
  libraries that are not part of the pinned Debian image.
