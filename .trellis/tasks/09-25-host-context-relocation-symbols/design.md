# Design: HostContext relocation, PLT/GOT, and symbol expansion

## Objective

Add common AArch64 dynamic relocation and symbol semantics to HostContext only
when their lookup, binding, target permission, and lifecycle behavior is
defined and observed through a real native oracle.

## Contract layers

1. Managed ELF model records the observed relocation/symbol metadata.
2. Static validator checks bounds, table ownership, alignment, writable target
   rules, dynamic flags, and feature-specific structural invariants.
3. HostContext capability metadata states what the adapter contract supports.
4. Native adapter preflight rejects unsupported combinations before loader
   handoff and clears output handles on failure.
5. Native fixture entry observes resolved values or dispatch behavior.
6. Manifest/evidence reports only the exact profile/runtime layer proven.

## Candidate family sequence

Use the real-sample histogram to select the first family. Candidate order is
likely common PLT/GOT/JUMP_SLOT and broader symbolic forms, followed by symbol
version metadata, but frequency and semantic feasibility decide. Each family
must specify:

- relocation type and encoding;
- symbol index/name/version scope;
- binding time and conflict/weak/visibility rules;
- writable/aligned target and memory-protection requirements;
- dependency requirements;
- loader delegation boundary;
- failure status and pre-handoff guarantee;
- ABI capability/version impact.

Do not copy the same classification logic into managed C# and native C. The
managed model records facts; the native adapter enforces its runtime contract;
shared feature IDs and layout checks bind them.

## Fixtures and oracles

Use real linker output for positive fixtures, preferably with a minimal entry
that returns an observed value. Use bounded mutations for malformed and nearest-
negative cases, asserting no image handle, no entry call, and no side effect.
Retain separate glibc/musl/bionic evidence when behavior is runtime-specific.

## Rollback

If symbol scope or loader behavior remains ambiguous, keep the family modeled
or observed but rejected. Remove capability bits and acceptance branches while
retaining positive source fixtures as future evidence.
