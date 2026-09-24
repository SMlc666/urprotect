# P2 Design: AArch64 Relocation and Symbol Semantics

## Boundary

P2 extends the `host-context-entry` adapter after P0 has supplied a stable
profile and after P1 has supplied the common fixture/evidence shape.

## First slice

Use real AArch64 producer fixtures to select the first family. The default
candidate order is `GLOB_DAT`, `JUMP_SLOT`, and `ABS64`, but the child must
select only a family whose target permissions and symbol lookup behavior can be
specified and observed on the supported loader environments.

The contract records symbol scope, visibility, weak-symbol behavior, conflict
resolution, binding timing, version policy, relocation target mapping, and
stable failure status. Unsupported forms remain explicit rejection rows.

## Evidence

Each family receives a real positive fixture, a malformed/mutated negative
fixture, a HostContext entry oracle, and separate glibc/musl/bionic evidence.
The adapter may delegate application to the system loader only after its
preflight checks prove the declared family and image invariants.
