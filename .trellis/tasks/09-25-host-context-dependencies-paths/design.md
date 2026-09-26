# Design: bounded HostContext dependency graph and path policy

## Objective and evidence

Add the smallest useful multi-entry `DT_NEEDED` contract selected from the
locked corpus, without importing the system loader's ambient path policy into
HostContext.

The native PR artifact `real-samples-pr-36232924362` contains 20 distinct
identities. The exact `DT_NEEDED` basename `ld-linux-aarch64.so.1` appears in
16 identities (80%), always with `libc.so.6`; these are normal executable
observations, not HostContext launch evidence. Their HostContext layer remains
`not-applicable` because they lack the declared entry ABI. The new controlled
fixture proves only the corresponding native AArch64 glibc subset.

## Contract boundary

Preserve the existing single recognized libc entry-image slice. Add exactly one
new validated row, `runtime.host-context.bounded-glibc-loader-dependency`, for
an entry image whose direct dependency list contains each of
`libc.so.6` and `ld-linux-aarch64.so.1` exactly once and no other name. The
entries may occur in either order. The pair is accepted only on the native
glibc cell covered by the fixture; musl and bionic are not promoted.

The pair is a bounded, closed graph:

```text
HostContext entry image -> libc.so.6 -> ld-linux-aarch64.so.1
                       -> ld-linux-aarch64.so.1
```

Both system objects already belong to the running glibc process's loader
namespace. The loader coalesces the repeated SONAME reference; HostContext does
not own or individually release these process objects. The sealed memfd-backed
entry image remains the root image handle and is released through the existing
`release_image` contract. The allowlist has no cycles or arbitrary recursive
graph: duplicates and any third/unknown node fail before `dlopen`. A missing
system object is an environment/load failure with a cleared output handle and
no entry call.

No frame, HostContext ABI, capability, or launcher marker changes are needed;
the accepted class and preflight policy are not ABI-visible. The existing
single-libc behavior and all relocation/symbol slices remain unchanged.

## Search and environment policy

- No payload paths are search roots. `DT_RPATH`, `DT_RUNPATH`, `$ORIGIN`,
  `DT_AUXILIARY`, and `DT_FILTER` remain rejected before loader handoff.
- The new pair requires `LD_LIBRARY_PATH`, `LD_PRELOAD`, and `LD_AUDIT` to be
  unset or empty at the HostContext handoff boundary. A non-empty value returns
  `URP_STATUS_UNSUPPORTED` before creating a memfd or image handle. This makes
  the pair independent of incidental path/symbol injection while preserving
  the historical singleton path for this increment.
- When the environment predicate holds, `RTLD_NOW | RTLD_LOCAL` resolves only
  the two allowlisted system objects in the native process namespace. The
  retained oracle also supplies a fake `ld-linux-aarch64.so.1` through a
  temporary `LD_LIBRARY_PATH`; it must be rejected before entry, and its
  constructor marker must remain absent.
- The runtime contract does not define configurable roots, arbitrary SONAMEs,
  environment-variable search precedence, payload-controlled path resolution,
  `DT_NEEDED` cycles, dependency sharing for other names, or filters/auxiliary
  dependencies. These stay rejected rather than delegated implicitly.

The existing singleton `libc.so.6` version-requirement subset remains tied to
the exact `vn_file == libc.so.6` name and bounded GNU-hash preflight. The new
pair fixture has no import-version tags; it cannot widen symbol-version
semantics.

## Ownership and data flow

```text
managed profile validation
  -> frame-v3 HostContext entry selection (unchanged)
  -> host_image_validation.c: bounded DT_NEEDED allowlist and rejection
  -> host_adapter.c: loader-environment gate before memfd creation
  -> sealed anonymous memfd + RTLD_NOW | RTLD_LOCAL handoff
  -> entry dispatch, status/constructor observation
  -> root image release and destructor observation
```

`host_image_validation.c` remains the sole ELF/dynamic metadata owner; it
returns the bounded dependency count to `host_adapter.c` so the adapter can
apply the environment gate without reparsing ELF bytes. `host_adapter.c` keeps
memfd, dynamic-loader, symbol lookup, handle rollback, and release ownership.
The frame codec, managed parser, CLI report layout, and HostContext ABI are not
owners of this policy and do not change.

## Test design

- Build the pair fixture with GNU ld as a linker-produced AArch64 shared
  object: exactly one `DT_NEEDED libc.so.6` and one
  `DT_NEEDED ld-linux-aarch64.so.1`, no path/filter/auxiliary tags, and a
  declared `urp_entry` that returns status 37 while observing the existing
  constructor/destructor marker.
- Retain `readelf -dW --version-info` output for the pair fixture.
- Positive native glibc managed pack/dispatch compares the declared entry
  result and release marker. The native adapter self-test directly loads and
  releases the fixture and verifies a zero handle on every negative load.
- Negative mutations cover a third `DT_NEEDED`, duplicate libc/loader names,
  missing libc, unknown system name, RPATH, RUNPATH, AUXILIARY, FILTER, and each
  non-empty loader influence variable. Failure occurs before memfd/`dlopen`;
  output handle remains zero and entry/destructor markers are absent.
- A linker-produced pair fixture with an unresolved strong GLOB_DAT import
  passes preflight but fails `dlopen(RTLD_NOW)`. The self-test requires
  `URP_STATUS_LOAD_FAILED`, a zero image handle, one memfd attempt, and no net
  descriptor increase, proving rollback after loader handoff begins.
- A temporary fake loader SONAME under `LD_LIBRARY_PATH` proves that an
  environment-controlled dependency is stopped by the explicit environment
  gate rather than selected by the host loader.
- CI records the build-and-test runner environment, fixture metadata, native
  logs, and managed output under the existing test evidence artifact. Only the
  native AArch64 glibc oracle promotes this row.

## Real-sample impact

The evidence source is real-sample artifact `real-samples-pr-36232924362`
(commit `ce21e9bd1a73ebe369e38a5f0972ebaf79c9fc32`). The 16 affected identities
are listed below. Each remains static `accepted-and-runs` and HostContext
`not-applicable`; the new controlled fixture, not the ecology histogram, is
the positive support oracle.

| Project IDs | Observed fact | Expected layer result | Evidence |
|---|---|---|---|
| `cmake`, `curl`, `ffmpeg`, `git`, `gnu-bash`, `gnu-coreutils`, `jq`, `nano`, `nginx`, `openssl`, `perl`, `postgresql`, `python`, `redis`, `sqlite`, `vim` | `DT_NEEDED libc.so.6` plus `ld-linux-aarch64.so.1`; 16/20 distinct identities (80%) | Preserve static `accepted-and-runs`; HostContext `not-applicable`, no product claim inferred | `.artifacts/real-samples/pr/<project-id>/{elf-fingerprint.json,readelf.txt,result.json}`; aggregate `.artifacts/real-samples/pr/aggregate.json` |
| `host_context_dependency_fixture.c` linked as the exact pair | controlled HostContext graph, entry, and release observation | native AArch64 glibc `accepted-and-runs`; nearest-negative names/path/env fail before handoff | `.artifacts/host-context/managed/{dependency-graph-readelf.txt,graph-self-test.log,graph-result.txt,graph.stdout,graph.stderr}` |

## Rollback

If the pair or environment oracle fails, remove only the multi-entry allowlist
and new feature row. Preserve the prior single-libc path, import-version row,
and explicit path/filter rejections. No frame or ABI migration rollback is
required.
