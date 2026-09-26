# Audit: HostContext TLS and image lifetime

## Result

Implemented an opt-in, size-versioned HostContext thread-lifetime extension.
The 56-byte v1 table and 32-byte launch-args minimum remain valid; current
sizes are 72 and 40 bytes. `pack --thread-lifetime` sets the optional frame
capability only for `host-context-entry`; default packing is unchanged and the
outer profile rejects the flag. Runtime preflight checks size and callback
presence before loading. Non-threaded frames receive a legacy-size projected
host and args with no optional callbacks/capability or image handle.

The native adapter advertises the optional capability only in a verified
glibc build/runtime. It owns per-image worker registrations, monotonic
non-reused image/thread handles, owner-thread-only create/join/release, and
root-link-map validation of worker routines. Failed creation publishes no
handle; join failure leaves the image registered and pinned for retry; release
closes the spawn gate and joins workers/TLS teardown before `dlclose`. Runtime
dispatch rejects same-thread recursion. A failed image release takes precedence
over entry status so a teardown failure is observable rather than masked.

The linker-produced initial-exec TLS fixture has initialized TLS data and
zero-fill, constructor/entry observations, deterministic inherited event/gate
pipes, worker TLS-key teardown, and image-destructor markers. The packed
wrapper harness verifies automatic release-time join, explicit join, failing
entry cleanup, and serial reruns. A native runtime harness exercises two
concurrent independent image dispatches. Adapter tests cover root membership,
owner restriction, invalid/foreign/repeated/self handles, failed create/join,
release retry, spawn-after-release, missing capability/callbacks, and dynamic
TLS rejection before memfd.

## Real-sample basis and scope

PR real-sample artifact `real-samples-pr-36248424559` records `PT_TLS` for
Caddy (Go), Perl (GCC), and ripgrep (Rust): 3/20 identities (15%), all with the
glibc loader. These normal executables remain HostContext `not-applicable`;
they are a prioritization signal only. The threaded support claim is proven by
the controlled fixture on native AArch64 glibc. No threaded musl/bionic claim,
dynamic TLS, unmanaged workers, or worker-triggered recursive dispatch is
introduced.

## Local verification

- `.NET` solution tests: **140 passed**.
- Native ABI contract probe: passed; current HostContext size 72, legacy
  minimum 56; current launch args size 40, legacy minimum 32; appended field
  offsets match the managed contract.
- Native runtime tests: passed, including threaded adapter negative/rollback
  tests and preserved dependency graph, PLT, and symbol-version oracles.
- Managed HostContext handoff: passed; optional threaded pack and real wrapper
  harness report ordered constructor/entry/worker/TLS teardown/destructor
  events for automatic join, explicit join, and failing entry.
- Fixture matrix: **24 passed**; regression matrix: **5 passed**; PR fixture
  validation: **13 cases passed**; PR evidence gate and threaded-TLS feature
  gate passed (21 paths); regression stress PR tier: **6 passed**.
- GNU readelf: positive fixture has `PT_TLS` and
  `R_AARCH64_TLS_TPREL64`; nearest dynamic-TLS fixture has `PT_TLS` and
  `R_AARCH64_TLSDESC` and is rejected before memfd creation.
- Task context validation, shell syntax, JSON parsing, executable mode, and
  `git diff --check`: passed.
- Independent full-scope `trellis-check` review: no remaining findings after
  correcting release-failure status precedence and adding explicit main-thread
  TLS isolation observation.

## CI / PR

The first CI attempt on implementation commit `0bdd835` passed the managed
build/evidence job and full real-sample matrix, but its bionic lane exited 2.
The runner preflight was tightened to assert an AArch64 host and a Linux/arm64
Docker server rather than equating an installed host-side emulator executable
with emulated execution. Follow-up PR run `36261267596` still exited 2 in the
bionic job while build-and-test and real-sample jobs passed, so the runner/tool
preflight was not confirmed as the root cause. PR run `36261694499` retained
the next diagnostic: host and Docker architecture preflight passed, then
Bionic Clang `-Werror` rejected glibc-only callback functions and the thread
handle sequence variable as unused. Those definitions are now guarded by
`__GLIBC__`; Bionic continues compiling the base adapter but advertises no
thread-lifetime capability or callbacks. The runner also prints host/Docker
identity and dumps apt/native-build logs when a Termux container phase fails.
PR #16 attempt `36261694499` still failed in the bionic job and its retained
logs confirmed the unused glibc-only identifiers. This guard fix has passed
locally on the native glibc host; its current PR and push runs are pending.
Both CI triggers must pass before archiving this child. The
acceptance gate requires the native AArch64 glibc HostContext feature evidence,
the full public real-sample run, and the bionic adapter lane; bionic results do
not promote the threaded row.
