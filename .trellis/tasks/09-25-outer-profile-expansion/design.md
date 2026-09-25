# Design: outer-execveat compatibility expansion

## Objective

Broaden the outer profile by delegating source ELF loading to the native kernel
and interpreter while proving baseline/wrapped process behavior. This child
does not expand HostContext semantics.

## Input-class model

Treat each class as an independent contract:

- dynamic AArch64 PIE with supported interpreter;
- static PIE;
- static ET_EXEC;
- dynamic ET_EXEC where the execution environment and launcher semantics make
  it meaningful;
- sectionless/stripped variants;
- shared objects, only if a distinct entry/launch contract is defined;
- interpreter/runtime variations.

The parser can report a class while the packer decides whether the outer
profile can launch it. The native launcher must validate recovered bytes before
handoff and preserve anonymous memfd behavior.

## Selected first slice: dynamic ET_EXEC

The current real-sample CI artifact has 2 `ET_EXEC` identities among 20
distinct projects (10%): Caddy and Python. Both are dynamic AArch64 executables
using `/lib/ld-linux-aarch64.so.1`; this crosses the program's 5% prioritization
trigger. The first outer-profile increment accepts only ELF64 little-endian
AArch64 dynamic `ET_EXEC` with an executable entry in `PT_LOAD`, a bounded
`PT_DYNAMIC`, one terminated absolute supported `PT_INTERP`, and no
`DT_RPATH`/`DT_RUNPATH`.

Static `ET_EXEC`, shared objects, missing/duplicate/unrecognized interpreters,
and dynamic images with path-search tags remain rejected. The runtime loader
continues to own dependency resolution; this is not HostContext relocation or
dependency support. Parser classification is observational, `ElfPackService`
owns outer-profile acceptance, and the native launcher validates that
recovered `ET_EXEC` has both `PT_DYNAMIC` and `PT_INTERP`. Frame v3 and the
anonymous `execveat(AT_EMPTY_PATH)` handoff remain unchanged.

The linker-produced process probe compares exit/signal status, output, source
`argv[0]`, arguments, environment, cwd, an inherited descriptor, and a
declared-file side effect between baseline and wrapped executions. The
initial runtime claim is native AArch64 glibc only; a recognized musl loader
path is not musl runtime evidence.

## Equivalence oracle

Run the same fixture in baseline and wrapped form and compare:

- exit status and signal termination;
- stdout/stderr bytes;
- argv and `argv[0]` source-name behavior;
- selected environment and cwd observations;
- inherited descriptor behavior and declared files;
- loader failure class and stable diagnostic where failure is expected.

ASLR addresses and timing are excluded. Differences involving `/proc` identity,
auxv, secure-exec, or interpreter path must be classified explicitly before a
class is claimed equivalent.

## Code structure

Keep pack acceptance in the profile policy owner and process behavior in native
launcher/integration tests. Do not add source-class conditionals to the frame
codec or copy native loader rules into managed validation. Reuse existing ELF
model/validator and launcher marker contracts.

## Rollback

Remove only the new input class and matrix claim if its oracle is incomplete.
The current v3 outer profile, launcher, and existing validated rows remain the
baseline.
