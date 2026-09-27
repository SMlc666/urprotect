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

## Selected initial cells

The matrix uses named source-of-truth cells rather than multiplicative runner
jobs:

| Cell | Runtime/toolchain | Kernel page | Shape / interactions | Tier |
|---|---|---:|---|---|
| `glibc.current.native-arm64` | Current Ubuntu 24.04 ARM64 runner glibc, system GCC | observed (expected 4K) | ET_DYN PIE, baseline/copy/packed; 16K `PT_LOAD.p_align` GNU fixture | PR/nightly/release |
| `glibc.older.ubuntu-22.04-arm64` | Digest-pinned Ubuntu 22.04 ARM64 userland, glibc 2.35 | shared runner kernel, recorded | real linked dynamic PIE with bounded GLIBC imports and 16K `PT_LOAD.p_align` | nightly/release |
| `musl.1.2.4.ubuntu-native` | SHA-256-pinned musl 1.2.4 source build with native Ubuntu ARM64 GCC | observed (expected 4K) | 4K/16K PIE, no-op/outer-wrapper smoke; Alpine 1.2.5 cross-runtime cell | nightly/release |
| `musl.1.2.5.alpine-3.22.2` | Digest-pinned Alpine ARM64 userland (musl 1.2.5) | shared runner kernel, recorded | run musl PIE built by the native 1.2.4 toolchain; verify loader and byte/status/stream facts | nightly/release |
| `bionic.termux.locked` | Existing Termux image and package-hash-locked Clang closure | observed (expected 4K) | Bionic PIE and adapter-level HostContext handoff; no glibc/musl promotion | PR/nightly/release |
| `kernel-page.16k.native-aarch64` | Native kernel page-size probe | target 16K | if no native runner matches, retain `environment-unavailable`; never convert alignment-only fixture evidence into kernel runtime support | optional until native host available |

The current public CI AArch64 runner reports a 4K page size. Container cells
share the host kernel, so they add older/different userspaces, not a distinct
kernel page-size fact. A dedicated linker-produced fixture sets `PT_LOAD`
alignment to 16KiB and is parsed/validated/run where the containing runtime
permits; that proves the ELF alignment contract, not operation on a 16KiB
kernel. The registry reports the native 16KiB cell as unavailable unless the
host probe actually observes 16384. A kernel page-size 16KiB product claim
stays unknown until a native cell with that page size produces retained
runtime evidence.

The selected array covers glibc current/older with baseline + 16KiB ELF
alignment, musl 1.2.4/1.2.5 with toolchain/runtime separation, and bionic with
its locked compiler/runtime witness. It does not claim the full Cartesian
product over producer, libc, loader, and ELF shape. Every cell has a stable ID,
selection rationale, runtime identity output, and evidence paths.

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

Image manifests are pinned by OCI digest. Container rows explicitly record
that the kernel and page-size are inherited from the native AArch64 runner.
Tool package versions/hashes and runner/compiler identities are retained for
reproducibility; no moving image tag or unrecorded package version can identify
a support cell.

`environment-unavailable` is a first-class result. Required rows fail their
gate when the environment is absent; optional rows remain visibly unavailable
and do not support a product claim.

The musl 1.2.4 producer is built from the upstream release tarball whose
SHA-256 is locked in `fixtures/runtime-matrix-toolchains.json`. CI compiles
musl for native AArch64 using the runner GCC and records its compiler/runtime
hashes, configure/build/install logs, and loader-reported version. The
test-owned `/lib/ld-musl-aarch64.so.1` symlink is created only when that path is
absent and is removed by the matrix runner on every exit path; a preexisting
host musl loader is preserved and causes an explicit failure rather than being
overwritten. The bionic producer retains the downloaded locked package
archives alongside its lock and verification output.

The native post-run evidence gate repeats musl fixture execution by invoking
the exact retained source-built loader directly after the test-owned `/lib`
interpreter symlink has been removed. Container loader probes select the
runtime-specific interpreter only after an executable path existence check;
an unresolved or absent glibc path is never mistaken for a musl loader. The
uploaded runtime artifact includes hidden files because they are covered by
the exact post-run SHA256SUMS manifest; the producing job and an independent
post-download check both verify complete runtime and bionic evidence sets.

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
