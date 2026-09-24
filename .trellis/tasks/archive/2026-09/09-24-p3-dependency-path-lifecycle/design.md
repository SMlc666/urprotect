# P3 Design: Dependency, Path, and Lifecycle Semantics

## Contract

HostContext receives explicit dependency roots and image ownership rules. The
first deterministic subset should avoid ambient search behavior: roots are
declared by the host configuration, path precedence is fixed, and environment
influence is either excluded or explicitly represented in the launch contract.

The contract defines dependency graph construction, sharing, cycles, rollback,
symbol scope, constructor/destructor order, reentrancy, entry ordering, and
release ownership before enabling dynamic metadata.

## Loader boundary

The system loader remains responsible for mapping and applying accepted images,
but the adapter preflights metadata whose semantics the HostContext contract
owns. A loader success without graph and lifecycle observations remains a
rejection/unknown result.

## Evidence

Use dependency-bearing and lifecycle-bearing ET_DYN fixtures with observable
constructor, entry, destructor, failure, and release events. Add paired
metadata mutations and leak/rollback assertions.
