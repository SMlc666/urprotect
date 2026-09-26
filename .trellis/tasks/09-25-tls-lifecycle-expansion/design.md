# Design: TLS and HostContext image-lifecycle expansion

## Objective and boundary

Close the current lifetime gap: HostContext proves initial-exec TLS only on
the dispatch thread and closes the image immediately after `urp_entry` returns,
but has no declared semantics for a worker thread that still executes image
code or uses image TLS. Extend the HostContext owner contract with an explicit,
opt-in worker-lifetime capability. Do not infer thread behavior from ELF tags or
delegate image lifetime to incidental `dlclose` behavior.

The first additional runtime claim is native AArch64 glibc only. Preserve the
current initial-exec TLS row, constructor/destructor row, frame profile, and
dependency policy; musl and bionic do not gain the threaded TLS row.

## Selected contract

- **TLS models:** the existing initial-exec model remains accepted for the
  current thread and registered worker threads, using bounded `PT_TLS` and
  `R_AARCH64_TLS_TPREL64`. The loader initializes each thread's module TLS
  from `p_filesz` and zero-fills through `p_memsz`. Dynamic/general-dynamic,
  local-dynamic, TLSDESC, and other unsupported TLS relocations remain rejected
  before `load_image`.
- **Opt-in worker capability:** add `URP_HOST_CAP_THREAD_LIFETIME` as an
  optional size-versioned HostContext capability with `create_image_thread`
  and `join_image_thread` callbacks. Append these fields to the existing
  HostContext table; retain ABI version 1 and the 56-byte legacy minimum.
  The adapter advertises this capability only when both callbacks and the
  extension fields are present. A frame that requires it is rejected before
  image loading if the host lacks the bit or its callbacks.
- **Image identity:** append the opaque current `urp_image_handle` to
  `urp_launch_args_v1` at offset 32. Keep the legacy 32-byte minimum; the
  current table size is 40 bytes. Runtime dispatch builds a full current
  argument view without reading beyond a caller's declared legacy size.
- **Thread ownership:** a payload may create registered workers only from the
  `urp_entry` dispatch thread and only through the HostContext callback. The
  adapter retains each thread handle and image mapping before `pthread_create`
  and rolls back the reservation if thread creation fails. The callback rejects
  invalid handles, null routines/outputs, nested worker creation, and spawn
  after image release begins with stable status and no partially published
  thread handle. Payloads must not create unmanaged workers or call back into
  the frame dispatcher from a worker.
- **Join and release:** `join_image_thread` joins one registered worker and
  returns its routine result; invalid, foreign, repeated, and self-join handles
  fail without decrementing another thread's ownership. After entry returns,
  `release_image` closes the spawn gate, joins every remaining registered
  worker, waits for their thread-exit/TLS-destructor processing, and only then
  calls `dlclose`, closes the sealed memfd, and frees the image state. Thus a
  supported worker may outlive entry return, but not image release. There is no
  timeout or forced thread cancellation; a worker that never exits can hold
  release open indefinitely rather than execute unmapped image code.
- **Lifecycle order:** system-loader constructors run before entry. The current
  thread's initial-exec TLS is initialized before constructors/entry; each
  registered worker receives a distinct initialized TLS instance. Explicit
  joins may occur inside entry. Unjoined workers finish during
  `release_image`, including their native TLS teardown, before image
  destructors run. This order also applies when entry returns a nonzero status.
- **Calls and reentrancy:** independent concurrent frame executions are
  supported by the native adapter when the caller's HostContext callbacks are
  thread-safe; each image owns separate loader/thread state. The runtime rejects
  same-thread recursive `urp_runtime_execute_frame` calls before a nested image
  load. Constructor/destructor callbacks may not re-enter dispatch or create
  workers. Existing serial repeated dispatch remains supported and is tested.
- **Failure behavior:** a frame's missing thread-lifecycle capability fails
  before image load. Failed create operations publish no thread handle and
  restore the live-worker count. A failing entry still joins registered workers
  and releases in the same order, then preserves the entry status. A failed
  `pthread_join` returns `URP_STATUS_LOAD_FAILED` and keeps the mapping/fd
  pinned rather than unloading code that might still be live.

## Ownership and data flow

```text
v3 frame capability preflight
  -> host table extension/callback validation
  -> immutable image load and owner-thread identity
  -> constructors + current-thread initial-exec TLS
  -> entry receives opaque image handle in launch args
  -> optional adapter-managed worker create/join (per-image TLS)
  -> entry return; release closes spawn gate and joins outstanding workers
  -> worker TLS teardown completes
  -> dlclose runs image destructors
  -> close sealed fd and return entry status
```

`runtime.c` owns frame capability checks, recursion rejection, and launch-args
projection. `host_image_validation.c` owns TLS-model/relocation preflight.
`host_adapter.c` owns per-image thread records, synchronization, joins, and
image release. The payload owns only its registered thread routine and thread
argument. The fixture script/CI own named native glibc evidence. The managed
frame contract owns the optional requirement bit; no separate TLS policy is
added to the ELF parser.

## Test design

- Preserve the current status-43 current-thread TLS fixture and its malformed
  `PT_TLS` boundaries.
- Add a linker-produced initial-exec fixture that observes constructor state,
  initializes main-thread TLS, starts a HostContext-registered worker, and
  checks worker TLS data-template and zero-fill values. A deterministic gate
  holds the worker across entry return so the native test can prove release
  blocks before teardown; the worker writes a completion marker before the
  destructor writes the release marker.
- Test both explicit join inside entry and automatic join during
  `release_image`, entry success/nonzero status, serial reload, and two
  concurrent independent dispatches. Require distinct per-thread TLS values
  and constructor -> entry -> worker completion/TLS teardown -> destructor
  ordering.
- Test missing frame capability with a host whose load callback counts calls;
  require `URP_STATUS_HOST_INVALID`, zero loads, zero entry calls. Test invalid
  thread handles/order, missing callbacks, failed create rollback, and a
  linker-produced dynamic-TLS nearest-negative rejected before memfd creation.
- Retain readelf TLS/dynamic facts, runner/runtime identity, barrier/worker /
  release markers, statuses, native logs, managed pack output, and hashes under
  the PR HostContext evidence artifact.

## Real-sample basis

The retained PR real-sample artifact `real-samples-pr-36248424559` reports
`PT_TLS` for Caddy (Go), Perl (GCC), and ripgrep (Rust): 3/20 distinct
identities (15%), with the glibc loader in all three observations. The
feature-disposition ledger already marks TLS as deferred pending explicit
model/thread semantics; this task resolves that disposition through a
controlled native AArch64 glibc oracle, not by treating ordinary executables as
HostContext samples. Normal binaries without `urp_entry` remain HostContext
`not-applicable`; the controlled real-toolchain fixture and nearest-negative
pair are the product oracle.

## Rollback

If managed worker ownership or a named runtime oracle fails, remove only the
new capability bit, callbacks, thread-lifetime feature row, and its positive
claim. Preserve the current initial-exec TLS and constructor/destructor rows,
their tests, and the explicit rejection of dynamic TLS and live unmanaged
threads.
