# Compatibility Contract

This document states the compatibility claim that the fixture matrix is
allowed to make. A device, emulator, or vendor anecdote is an implementation
witness; it is not the proof of compatibility.

## Conditional Claim

Let `S` be the exact payload bytes, `F(S)` its versioned frame, `H` a host that
satisfies `HostContext v1`, and `P` an image accepted by the AArch64 ELF
invariants in `fixtures/manifest.json`.

The supported claim is:

```text
H satisfies HostContext v1
and F(S) verifies
and P satisfies the accepted image invariants
and H.load_image(S, immutable) returns an image I
and H.lookup_symbol(I, "urp_entry") returns the declared entry
=> execute(H, F(S)) invokes urp_entry(H, args) exactly once and returns its
   status after releasing I
```

The proof is conditional on the host callback semantics. In particular,
`load_image` must preserve the payload bytes, apply all declared relocations and
dependencies, honor the image lifetime, and return only after constructors and
memory-protection obligations required by the declared image contract are
complete. Those obligations belong to the host adapter, not to an incidental
Linux or Android branch.

## Proof Layers

1. **Frame identity.** The frame parser checks bounds and format; SHA-256 is
   checked for both the encoded bytes and the decoded source bytes. Therefore
   the runtime dispatches the verified `S`, not an attacker-controlled
   replacement.
2. **Image contract.** The native runtime requires ABI version, structure-size,
   immutable-image, symbol-lookup, and release capabilities before dispatch.
   Truncated or unknown contracts fail closed.
3. **Entry boundary.** The runtime resolves the fixed `urp_entry` symbol,
   passes the versioned launch arguments, returns the entry status, and releases
   the host image. It does not synthesize `_start`, `main`, or a kernel stack.
4. **Observation.** For a conforming host adapter, the observation boundary is
   entry arguments, verified image bytes, declared dependencies, constructors,
   TLS/thread behavior, callback ordering, file descriptors, signals, output,
   and returned status. A runtime row is not proven until its adapter defines
   these observations and the corresponding invariants.

## Evidence Status

The matrix uses `proven` for static/model obligations, `validated` for
deterministic implementation evidence, `rejected` for deliberate fail-closed
boundaries, and `unknown` when an obligation is not complete. `unknown` never
counts as support.

The HostContext self-test contains both a deterministic fake-host contract
oracle and a real AArch64 `ET_DYN` entry fixture. The fd-backed adapter loads
the fixture through an anonymous memfd created with `MFD_ALLOW_SEALING`, adds
and verifies `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL` after
writing the verified bytes, and only then calls the host `dlopen`/`dlsym`
mechanism. A missing sealing capability or incomplete seal set fails closed
before loader handoff. The test-visible adapter invariant checks those seals
on the live image handle, then verifies entry dispatch and release ordering
without an executable temporary pathname. This upgrades only the narrow
adapter slice to `validated`; it accepts checked AArch64 `RELATIVE`/`RELR`
targets while the system loader applies them. Dependencies, TLS, constructors,
GNU properties, and the rejected unsupported-relocation-table feature remains
outside that claim.

The first expanded ELF slice is sectionless `ET_DYN`: section headers are
optional metadata, so the parser and validator use bounded program headers and
the load map as the runtime authority. `ElfParserTests` provides the positive
witness and the malformed corpus keeps a paired alignment rejection; this
proves the parser boundary, not arbitrary loader behavior.

PT_TLS is an explicit rejected HostContext v1 boundary, recorded as
`runtime.host-context.pt-tls` in the matrix. The current system-loader adapter
has no contract for TLS module allocation, per-thread initialization, TLS
relocation models, thread creation/reentrancy, or teardown relative to
`release_image`; a successful `dlopen` therefore does not establish support.
The native self-test keeps the unchanged entry fixture as the positive
HostContext baseline, then mutates a bounded PT_LOAD-covered metadata segment
into a structurally valid PT_TLS and requires `URP_STATUS_UNSUPPORTED` with no
handle. A paired mutation with `p_filesz > p_memsz` requires
`URP_STATUS_LOAD_FAILED`. Generic bounds, file/memory-size, alignment, and
congruence checks protect these rejection boundaries, but no positive TLS
fixture or compatibility claim is made until
the Host Contract defines the missing semantics.

PT_GNU_PROPERTY is a separate rejected HostContext v1 feature, recorded as
`runtime.host-context.gnu-property`. The current system-loader adapter does not
negotiate GNU properties or define BTI/PAC/instruction-state obligations, so a
loader that accepts a property note does not establish compatibility. The
self-test preserves the unchanged entry image as its positive HostContext
baseline, then changes only the type of a bounded PT_LOAD-covered metadata
program header to PT_GNU_PROPERTY and requires `URP_STATUS_UNSUPPORTED` with a
zero image handle before loader handoff. No positive property-bearing
HostContext fixture or support claim is made until those semantics are part of
the Host Contract. DT_NEEDED, DT_AUXILIARY, and DT_FILTER dependency metadata form a
separate rejected boundary recorded as `runtime.host-context.dependency-resolution`.
HostContext v1 and the current system-loader adapter define no
dependency-resolution, search-path, symbol-scope, or dependency-lifetime
semantics, so a loader that can resolve a library does not establish support.
Its self-test mutates one bounded dynamic-table tag at a time, preserves
surrounding bytes, initializes a sentinel handle, and requires
`URP_STATUS_UNSUPPORTED` with a zero handle before loader handoff. The
unchanged non-dependency entry fixture remains the positive HostContext
baseline.

Constructor/destructor metadata is a separate rejected boundary recorded as
`runtime.host-context.constructor-destructor`. It covers `DT_INIT`, `DT_FINI`,
`DT_INIT_ARRAY`, `DT_FINI_ARRAY`, `DT_INIT_ARRAYSZ`, `DT_FINI_ARRAYSZ`,
`DT_PREINIT_ARRAY`, and `DT_PREINIT_ARRAYSZ`. HostContext v1 and the current
system-loader adapter define no constructor/destructor ordering, callback or
reentrancy behavior, teardown, or lifecycle ownership semantics. The self-test
mutates one bounded `DT_NULL` tag at a time, preserves all surrounding bytes,
initializes a nonzero output-handle sentinel, and requires
`URP_STATUS_UNSUPPORTED` with a zero handle before loader handoff. The
unchanged non-lifecycle entry fixture remains the positive HostContext
baseline.

RPATH/RUNPATH metadata is a separate rejected boundary recorded as
`runtime.host-context.path-search`. HostContext v1 and the current
system-loader adapter define no dynamic path-search roots, ordering, or
precedence semantics, so the same bounded mutation must fail closed before
loader handoff. Unsupported relocation-table tags use the separate
`runtime.host-context.unsupported-relocation-table` rejection boundary and are
not included in this row.

DT_TEXTREL writable-text relocation metadata is a separate rejected boundary
recorded as `runtime.host-context.text-relocation`. HostContext v1 and the
current system-loader adapter define no writable-text relocation or
W^X/protection semantics for in-process images, so loader acceptance alone does
not establish support. The self-test mutates one bounded `DT_NULL` tag to
`DT_TEXTREL`, preserves all surrounding bytes, initializes a nonzero
output-handle sentinel, and requires `URP_STATUS_UNSUPPORTED` with a zero
handle before loader handoff. The unchanged non-text-relocation entry fixture
remains the positive HostContext baseline. Unsupported relocation-table tags
use the separate `runtime.host-context.unsupported-relocation-table` rejection
boundary; checked AArch64 `RELATIVE`/`RELR` acceptance and system-loader
application remain the validated `elf.relocation.aarch64-relative` feature.

Unsupported dynamic relocation-table tags are an independently rejected
HostContext v1 feature recorded as
`runtime.host-context.unsupported-relocation-table`. It covers `DT_REL`,
`DT_RELSZ`, `DT_RELENT`, `DT_JMPREL`, `DT_PLTRELSZ`, and `DT_PLTREL`; the
current system-loader contract defines only the checked AArch64
`RELATIVE`/`RELR` path, so these forms are rejected before relocation
processing or image-handle creation. The self-test mutates one bounded
`DT_NULL` tag at a time, preserves surrounding bytes, initializes a nonzero
output-handle sentinel, and requires `URP_STATUS_UNSUPPORTED` with a zero
handle. The unchanged `RELATIVE`/`RELR` fixture remains the positive baseline;
no broader relocation-table support is claimed.

The native Termux/bionic case is a peer runtime fact beside glibc and musl. It
records native ARM64 container execution, `/system/bin/linker64`, kernel and
page-size facts, and the pinned image/source revision. The live package index
is used only to locate the exact compiler dependency set in the manifest;
versions, artifact paths, SHA-256 hashes, and license identifiers are locked.
The lane checks the downloaded package set and hashes before installation,
fails on additional or changed packages, and retains the lock, hash-verification
output, and before/after inventories. The image digest pins the base userspace,
so the compiler inputs are reproducible despite the live index. This evidence
intentionally excludes Android framework, OEM, SELinux, device-kernel, AVD,
Waydroid, QEMU, and native-bridge claims. The matrix row
`runtime.host-context.bionic-handoff` remains `unknown` until a dedicated
HostContext/package oracle runs a v2 entry image through the adapter and
retains sealed-image, linker, package, kernel, page-size, and no-fallback
evidence; the ordinary bionic PIE pass does not upgrade it.

The production managed pack path is a separate deliberate migration boundary.
`ElfPackService` emits legacy frame v1 for the legacy launcher and must not
force a v2 frame into that path. The matrix row
`runtime.host-context.production-pack` is `unknown` until the missing
HostContext entry-image adapter, v2-capable launcher, and managed pack/dispatch
oracle are implemented and retained. Its unknown status does not weaken the
legacy v1 compatibility baseline.

The claim therefore applies to every correctly implemented host satisfying the
contract, not to an unqualified statistical majority of phone vendors.
