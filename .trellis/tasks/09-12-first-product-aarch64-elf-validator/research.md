# First Product Research

## Existing evidence

- The archived AArch64 ELF MVP already validates ELF64 little-endian AArch64
  `ET_DYN` PIE/shared-object inputs, preserves unknown data, and proves no-op
  byte identity.
- The current GitHub workflow has native ARM64 glibc fixture coverage, pinned
  native musl/Zig fixture provisioning, a pinned ARM64 musl container smoke,
  x86_64 Android native-bridge coverage, and release-tier conditions.
- The current CLI is intentionally small and human-text oriented. Product work
  should add a report/exit-code boundary rather than make fixture scripts parse
  human output.

## Release/runtime constraints

- `global.json` pins .NET SDK `8.0.424`; release publish profiles must either
  restore the required RIDs under locked mode or document the compatible
  publish setup before producing archives.
- The ARM64 musl container uses the platform-specific
  `mcr.microsoft.com/dotnet/sdk` `8.0.424-bookworm-slim` manifest digest
  `sha256:00c73d766c2c8fea23a9214954a5dec33c022c1a530c09e0f2a5e333fa4578ed`.
- The Android native-bridge AVD remains slow software emulation and is manual
  opt-in outside schedule/release workflows.
- Waydroid ARM64 system/vendor manifests are pinned in `fixtures/manifest.json`
  for provenance, but the hosted ARM64 runner currently lacks the Binder/LXC/
  graphics capabilities required to claim container E2E.

## Product decisions

- The first public compatibility contract is the CLI, stable exit classes, and
  report schema v1; there is no public core library compatibility promise yet.
- glibc and musl bundles are both release targets, but Android native-bridge
  timing is never a native performance baseline.
- `RuntimeIdentifiers` is pinned at the solution level for `linux-arm64` and
  `linux-musl-arm64`; locked restore carries both runtime targets, while the
  publish script selects one with `-p:RuntimeIdentifier` and emits a normalized
  single-file archive. The ARM64 host can validate the glibc archive directly;
  musl smoke requires the matching musl loader package.
- The release smoke runs the musl bundle inside the pinned platform-specific
  ARM64 `mcr.microsoft.com/dotnet/sdk:8.0-alpine` digest
  `sha256:386b8fd9f78bb9aa7e5fb566656e0903518cb6f81d3b1520e1787a7dce1ef243`
  when Docker is available, because a self-contained .NET musl binary still
  needs musl-compatible `libstdc++`, zlib, and compiler runtime libraries.
