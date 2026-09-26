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

## Observed priority

The native PR artifact `real-samples-pr-36232924362` contains 20 distinct
project identities. Its bounded `readelf` records show the exact direct
`DT_NEEDED` name `ld-linux-aarch64.so.1` in 16/20 identities (80%), always
alongside `libc.so.6`. This is observation only: those normal executables
remain HostContext `not-applicable` because they do not declare `urp_entry`.

## Requirements

- Define allowed roots, search ordering, environment effects, graph ownership,
  sharing, cycles, missing dependency behavior, rollback, constructor ordering,
  and release order.
- Preserve the existing single system-libc slice and add only the closed glibc
  direct dependency set `{libc.so.6, ld-linux-aarch64.so.1}`; support no
  arbitrary graph, third dependency, duplicate, path tag, filter, or auxiliary
  dependency.
- Require empty/unset loader influence variables for the new two-entry graph;
  define the accepted root objects, load sharing, and release ownership.
- Add a linker-produced two-dependency positive fixture, unknown/duplicate/
  excess/path/environment negative boundaries, and teardown/failure oracles.
- Ensure payload-controlled search paths cannot escape the explicit policy.
- Keep this additional loader-SONAME claim native AArch64 glibc-only; do not
  infer musl or bionic graph support.

## Acceptance Criteria

- [x] HostContext dependency policy is explicit, versioned if ABI-visible, and
      testable independent of incidental loader environment.
- [x] Positive graph fixtures exercise the exact libc/loader pair and entry
      output; negative fixtures cover unknown roots, duplicates, excess
      entries, path tags, environment influence, and cycles/failures relevant to
      the closed selected slice.
- [x] Partial load failures roll back handles and resources deterministically.
- [x] No unsupported path-search or dependency form reaches entry dispatch.
- [x] CI retains runtime identity, dependency facts, and complete evidence.
