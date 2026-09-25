# Design: AArch64 runtime covering array

## Objective

Expand runtime evidence without turning the CI into an unbounded Cartesian
product. Select cells that cover main effects and high-risk interactions found
in the real-sample fingerprint.

## Matrix dimensions

Required dimensions:

- native AArch64 runner and explicitly separated x86_64 native-bridge facts;
- older/current glibc representatives;
- at least two musl representatives;
- locked native bionic/Termux baseline;
- 4K and 16K page size;
- loader/interpreter identity;
- producer/toolchain class;
- executable class and feature shape (relocation, dependency, symbol version,
  TLS, hardening, stripped/sectionless).

The exact version/image cells are selected from available pinned sources and
the corpus histogram. Every required cell has a stable ID and selection
rationale.

## Evidence record

Each cell records:

- runner architecture and kernel;
- page size;
- libc/loader version and path;
- container/image digest;
- compiler/linker/package hashes and licenses;
- isolation and capability facts;
- command/tier/budget;
- per-feature and aggregate artifact paths.

`environment-unavailable` is a first-class result. Required rows fail their
gate when the environment is absent; optional rows remain visibly unavailable
and do not support a product claim.

## Tier strategy

- PR: fast required covering set plus all static metadata checks;
- nightly: expanded runtime cells, full repeatability and stress;
- release: every runtime cell named by the release claim, full provenance and
  release smoke.

All tiers consume the same registry and oracle code. Only selection strength,
repetition, retention, and approved environment cells vary.

## Rollback

Remove a flaky or unavailable cell from the claim only with an explicit matrix
status and reason. Do not substitute another libc, architecture, emulator, or
loader silently.
