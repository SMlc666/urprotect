# Expand TLS and image lifecycle semantics

## Goal

Define explicit TLS, threading, constructor/destructor, reentrancy, and image
release ownership for HostContext, then validate the selected AArch64 subsets
with deterministic runtime fixtures.

## Dependencies and constraints

- Depends on the architecture foundation, HostContext relocation/symbol
  semantics, and dependency graph/release policy.
- Preserve the current validated initial-exec TLS and constructor/destructor
  slices unless a coherent versioned contract replaces them.
- Dynamic TLS or live-thread unload is not accepted merely because the system
  loader permits it; HostContext owns the callback and lifetime semantics.
- Expanded lifecycle semantics may require an ABI/frame capability change and
  must update all managed/native consumers together.

## Requirements

- Define current-thread and new-thread TLS initialization, dynamic TLS, thread
  creation/exit, constructor/entry/destructor order, reentrancy, concurrent
  calls, live-thread image retention, and release behavior.
- Preserve initial-exec `PT_TLS` plus `R_AARCH64_TLS_TPREL64`; add an
  explicit optional HostContext thread-lifetime capability for managed worker
  creation/join and append the opaque current image handle to launch args.
- Keep dynamic/general-dynamic, local-dynamic, TLSDESC, unmanaged worker
  lifetime, and reentrant frame dispatch outside the supported contract. A
  frame requiring worker support must fail before load when the host lacks the
  capability. `release_image` must join registered workers before unloading
  image/TLS state.
- Select first supported subsets from observed corpus frequency and product
  value; reject combinations whose ownership remains unspecified.
- Add real-toolchain threaded fixtures with state observation, deterministic
  barriers, teardown markers, and failure-path assertions.
- Validate on named native AArch64 runtime cells and retain evidence.

## Acceptance Criteria

- [x] HostContext lifecycle contract defines exactly when image memory remains
      live and when callbacks/threads are permitted to use it.
- [x] Positive threaded/lifecycle fixtures demonstrate declared ordering and
      values; negative tests cover missing capabilities, failures, and invalid
      release order.
- [x] No release occurs while supported live users remain; unsupported
      behavior fails deterministically before unsafe dispatch/release.
- [x] Current initial-exec TLS and lifecycle regression oracles continue to
      pass.
- [x] Runtime-specific claims are limited to retained evidence.

## Selected initial increment

The first thread-lifecycle increment is native AArch64 glibc only. Registered
workers may outlive `urp_entry`, but the adapter retains the image and joins
them before `dlclose`; dynamic TLS, unmanaged thread creation, reentrant frame
dispatch, and musl/bionic threaded claims remain outside this increment.

## Observed priority

The current PR real-sample artifact `real-samples-pr-36248424559` reports
`PT_TLS` on 3/20 identities (15%): Caddy, Perl, and ripgrep, produced by Go,
GCC, and Rust respectively. All three records identify the glibc loader.
This frequency clears the program's 5% disposition threshold; it prioritizes
the TLS/lifecycle work but does not itself grant HostContext support.
