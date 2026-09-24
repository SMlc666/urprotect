# Coverage-guided fuzzing design

## Runner

Create an isolated .NET 8 console target using the pinned SharpFuzz
instrumentation tool and `SharpFuzz.Common` package, plus a small MIT-licensed
compatibility runner in `third_party/SharpFuzzCompat`. The compatibility runner
uses file-backed mmap rather than SysV IPC because the native ARM64 kernel used
for local/CI evidence may omit System V shared memory. Instrument only
project-owned assemblies. Expose `elf` and `payload-frame` modes so each corpus
has a clear coverage signal.

## Inputs and limits

Seed from existing minimal/malformed ELF fixtures and frame tests. Bound input
length before allocation, use conservative frame limits, and pass explicit
libFuzzer timeout/RSS/total-time flags. Expected malformed results return
normally; unexpected exceptions remain crash findings.

## Evidence

The runner writes engine/source/package/compiler metadata, seed, command line,
corpus, crash/timeout artifacts, and minimized output. PR uses a fixed short
run; nightly performs longer exploration and corpus merge. Missing prerequisites
are explicit failures.
<!-- End of task artifact. -->
