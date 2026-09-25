# Design: HostContext dependency and path semantics

## Objective

Define deterministic dependency graph, path-search, and image lifecycle policy
before increasing HostContext support beyond the current single system-libc
slice.

## Policy model

The contract must make these choices explicit:

- dependency graph ownership and load order;
- allowed roots and whether roots are host configuration or payload metadata;
- RPATH/RUNPATH precedence and `$ORIGIN` resolution;
- environment-variable influence;
- system/default roots;
- symbol scope and dependency sharing;
- filters/auxiliary dependencies;
- cycles, missing dependencies, and partial-load rollback;
- constructor/destructor ordering and release ownership.

The first implementation should prefer a small deterministic subset with
explicit roots over inheriting all process environment behavior. The system
loader may apply relocations and constructors, but HostContext must define the
observation and lifetime contract around that handoff.

## Data flow and ownership

```text
frame capability/policy
  -> managed input/profile validation
  -> native image metadata preflight
  -> dependency policy validation
  -> sealed image + explicit loader handoff
  -> dependency-backed entry dispatch
  -> release/rollback observation
```

Dynamic tag parsing remains in the shared ELF model/adapter preflight owner.
Path policy and lifecycle state belong to HostContext adapter/runtime code, not
to generic frame decoding.

## Fixtures

Build a small dependency graph with known entry state, separate path-search
fixtures, and failure/cycle variants. Use filesystem roots controlled by the
test harness and assert that an invalid path form fails before loader handoff.
Record constructor and destructor markers and handle state.

## Rollback

Leave RPATH/RUNPATH or graph forms rejected until policy and failure rollback
are complete. A failed subset does not change the current single-libc claim.
