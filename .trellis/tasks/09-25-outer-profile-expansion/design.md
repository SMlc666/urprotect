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
