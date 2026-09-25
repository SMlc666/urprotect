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
- Select first supported subsets from observed corpus frequency and product
  value; reject combinations whose ownership remains unspecified.
- Add real-toolchain threaded fixtures with state observation, deterministic
  barriers, teardown markers, and failure-path assertions.
- Validate on named native AArch64 runtime cells and retain evidence.

## Acceptance Criteria

- [ ] HostContext lifecycle contract defines exactly when image memory remains
      live and when callbacks/threads are permitted to use it.
- [ ] Positive threaded/lifecycle fixtures demonstrate declared ordering and
      values; negative tests cover missing capabilities, failures, and invalid
      release order.
- [ ] No release occurs while supported live users remain; unsupported
      behavior fails deterministically before unsafe dispatch/release.
- [ ] Current initial-exec TLS and lifecycle regression oracles continue to
      pass.
- [ ] Runtime-specific claims are limited to retained evidence.
