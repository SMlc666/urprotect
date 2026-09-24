# P2 Design: AArch64 Relocation and Symbol Semantics

## Boundary

P2 extends the `host-context-entry` adapter after P0 has supplied a stable
profile and after P1 has supplied the common fixture/evidence shape.

## First slice

Use a real AArch64 weak-symbol fixture for the first family:
`R_AARCH64_GLOB_DAT`. The adapter requires a nonzero symbol index,
`DT_SYMTAB`/`DT_SYMENT == 24`, a file-backed symbol record, and an aligned
writable relocation target before delegating application to the system loader.
The managed v3 profile oracle observes the entry status produced by the weak
symbol resolution.

The contract records symbol scope, visibility, weak-symbol behavior, conflict
resolution, binding timing, version policy, relocation target mapping, and
stable failure status. Unsupported forms remain explicit rejection rows.

## Evidence

Each family receives a real positive fixture, a malformed/mutated negative
fixture, a HostContext entry oracle, and separate glibc/musl/bionic evidence.
The adapter may delegate application to the system loader only after its
preflight checks prove the declared family and image invariants.
