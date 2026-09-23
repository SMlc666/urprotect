# Implementation Plan

## Ordered Checklist

1. [x] Add the native HostContext public header with fixed-width structures,
       size/version negotiation, capability bits, callback errors, and the
       explicit entry declaration.
2. [x] Add managed records/constants for the HostContext frame metadata and
       extend the payload codec with a new version while preserving legacy v1
       parsing behavior.
3. [x] Add native frame discovery, bounded decoding, digest verification, and
       required-capability checks to the new runtime core.
4. [x] Implement one host loader adapter that satisfies immutable image
       handoff without an executable temporary pathname.
5. [x] Implement entry-symbol lookup, lifecycle cleanup, and stable diagnostic
       propagation.
6. [x] Add a minimal AArch64 HostContext fixture and host process integration
       test.
7. [x] Add malformed-frame, ABI-mismatch, missing-capability, image-load,
       lookup, and entry-failure tests.
8. [x] Record compiler, linker, native source, frame version, and output hash
       provenance.
9. [x] Update the parent matrix with ABI and handoff feature IDs.

## Risk and Rollback Points

- Freeze the public header and frame version before implementation. If layout
  changes, bump the ABI/frame version instead of changing fields in place.
- Keep the legacy v1 launcher path available for v1 inputs during migration.
- If host loading cannot satisfy no-path semantics, mark the handoff unknown and
  stop; do not add a temporary-file fallback.
- If dynamic dependencies or TLS cannot be proved for a fixture, keep the
  parser/report case but reject it as a HostContext runtime image.

## Validation

    PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release
    make -C native/urprotect-runtime test
    readelf -hW -lW -dW native/urprotect-runtime/build/urprotect-runtime.so

The native command names are finalized with the build layout. All AArch64
runtime tests must fail when executed on a non-AArch64 host.

## Completion Evidence

- The HostContext ABI, v1/v2 frames, immutable memfd handoff, and adapter
  boundary are documented in the public header, runtime README, parent design,
  and compatibility matrix.
- Managed tests (101), native runtime self-test, and parser fuzz checks passed.
- PR run 35934602944 and release-tier run 35934619123 passed on commit
  `57a0d1f`; the retained bionic artifact includes the real adapter v2 witness.
