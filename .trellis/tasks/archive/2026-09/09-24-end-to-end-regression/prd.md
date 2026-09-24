# Expand end-to-end regression matrix

## Goal

Turn the existing CLI, native launcher, HostContext, fixture, musl, bionic,
and optional Android paths into an explicit, machine-readable regression
matrix with tiered evidence and no inflated compatibility claims.

## Requirements

- Cover CLI validation, stable exit codes, JSON output, no-op identity,
  publication failure, and pack rejection boundaries.
- Cover native packed-launcher and managed anonymous handoff observables:
  payload integrity, `argv[0]`, stdout/stderr, exit and signal status,
  deterministic repeat packing, and no executable temporary pathname.
- Reuse existing fixture-matrix, packed-fixture, HostContext, musl, bionic, and
  Android native-bridge scripts instead of duplicating their runtime logic.
- Add a separate machine-readable regression matrix with command, tier,
  platform requirement, budget, expected status, and artifact witness. Validate
  it in CI and upload failures even when a capability is unavailable.
- Keep `runtime.host-context.production-pack` and other documented unknown or
  optional statuses unchanged unless the required oracle is present.

## Ordering and integration notes

This child integrates the outputs of the constants/assertion, fuzz, and
concurrency children. It can add missing independent scenarios first, but the
final matrix and CI wiring should land after their profile names and artifact
schemas are stable.

## Acceptance Criteria

- [x] Managed CLI and supported native E2E cases pass in their declared tiers
      and compare status, streams, identity, and failure behavior.
- [x] The regression matrix validator rejects missing witnesses, invalid tiers,
      and unsupported compatibility claims.
- [x] PR, nightly, release, native, bionic, musl, and optional Android rows
      report their actual availability and retain logs/manifests/artifacts.
- [x] Existing fixture and compatibility evidence checks continue to pass;
      no unknown row is promoted by test scaffolding alone.
<!-- End of task artifact. -->
