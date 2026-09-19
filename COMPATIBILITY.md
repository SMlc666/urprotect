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
the fixture through an anonymous memfd and the host `dlopen`/`dlsym` mechanism,
then verifies entry dispatch and release ordering without an executable
temporary pathname. This upgrades only the narrow adapter slice to
`validated`; it accepts checked AArch64 `RELATIVE`/`RELR` targets while the
system loader applies them. Dependencies, TLS, constructors, GNU properties,
text relocations, and broader relocation behavior remain outside that claim.

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
the Host Contract. DT_NEEDED dependency resolution is a separate rejected
boundary recorded as `runtime.host-context.dependency-resolution`. HostContext
v1 and the current system-loader adapter define no dependency-resolution,
search-path, symbol-scope, or dependency-lifetime semantics, so a loader that
can resolve a library does not establish support. Its self-test mutates only a
bounded dynamic-table tag, preserves surrounding bytes, initializes a sentinel
handle, and requires `URP_STATUS_UNSUPPORTED` with a zero handle before loader
handoff. The unchanged non-dependency entry fixture remains the positive
HostContext baseline; lifecycle and path-search tags remain in their separate
rejected row.

The native Termux/bionic case is a peer runtime fact beside glibc and musl. It
records native ARM64 container execution, `/system/bin/linker64`, kernel and
page-size facts, and pinned image/source/package provenance. It intentionally
excludes Android framework, OEM, SELinux, device-kernel, AVD, Waydroid, QEMU,
and native-bridge claims. The matrix row `runtime.host-context.bionic-handoff`
remains `unknown` until that userspace runs the HostContext/package oracle and
retains its no-path evidence; the ordinary bionic PIE pass does not upgrade it.

The claim therefore applies to every correctly implemented host satisfying the
contract, not to an unqualified statistical majority of phone vendors.
