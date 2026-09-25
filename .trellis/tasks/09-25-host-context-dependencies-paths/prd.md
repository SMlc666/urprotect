# Expand HostContext dependency and path semantics

## Goal

Define deterministic dependency-graph and path-search policy for HostContext
entry images, then expand supported dependency forms with paired runtime
evidence.

## Dependencies and constraints

- Depends on architecture ownership and HostContext symbol-scope semantics.
- Must define policy before accepting multiple `DT_NEEDED`, RPATH/RUNPATH,
  `$ORIGIN`, environment influence, filters, or auxiliary dependencies.
- Preserve the current single recognized system-libc slice until replacement
  behavior is fully validated.
- A system loader resolving a dependency is implementation evidence, not the
  complete product contract.

## Requirements

- Define allowed roots, search ordering, environment effects, graph ownership,
  sharing, cycles, missing dependency behavior, rollback, constructor ordering,
  and release order.
- Implement a deterministic first increment selected by real-sample frequency.
- Add multi-dependency positive fixtures, path-control negative fixtures, and
  teardown/failure oracles.
- Ensure payload-controlled search paths cannot escape the explicit policy.
- Keep glibc, musl, and bionic claims independently evidenced.

## Acceptance Criteria

- [ ] HostContext dependency policy is explicit, versioned if ABI-visible, and
      testable independent of incidental loader environment.
- [ ] Positive graph fixtures exercise multiple dependencies and entry output;
      negative fixtures cover unknown roots, path tags, cycles, and failures as
      relevant to the selected slice.
- [ ] Partial load failures roll back handles and resources deterministically.
- [ ] No unsupported path-search or dependency form reaches entry dispatch.
- [ ] CI retains runtime identity, dependency facts, and complete evidence.
