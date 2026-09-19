# HostContext runtime core

This directory defines the versioned, host-neutral `HostContext` entry
contract and a bounded frame-dispatch runtime. `urp_runtime_execute_frame`
verifies the legacy v1 or HostContext v2 frame and both payload digests, asks
the host for an immutable image, resolves the declared entry symbol, invokes
it, and releases the image before returning.

The native evidence adapter implements the contract with an anonymous memfd
and the host's `dlopen`/`dlsym` loader through the generated virtual
`/proc/self/fd/<N>` reference. It creates no executable filesystem pathname
and keeps the descriptor open until `release_image`. Before loading, the
adapter requires AArch64 ELF64 `ET_DYN` program headers and rejects an
interpreter, TLS, GNU property, dependency, constructor/destructor lifecycle,
text-relocation, or path-search requirement that this first entry slice does
not define. PT_TLS is
a deliberate rejected boundary: HostContext v1 does not define TLS module
allocation, per-thread initialization, thread creation/reentrancy, or TLS
teardown relative to `release_image`, so acceptance by `dlopen` would not close
the runtime contract. Generic program-header bounds, file/memory-size,
alignment, and congruence checks still run before the PT_TLS rejection; they
protect the boundary but do not claim TLS support. Failed adapter loads clear
the output image handle before returning their stable status.
The system loader remains the authority for applying relocation and memory
protection. This adapter accepts only AArch64 `RELATIVE`/`RELR` relocation
forms with checked writable targets, and permits only immediate-binding
dynamic flags; other relocation or lifecycle forms remain outside the
declared slice. Section headers are not consulted by this adapter; bounded
program headers and mapped dynamic metadata are authoritative for the
sectionless image slice.

The self-test includes both the deterministic fake host contract oracle and a
real AArch64 `urp_entry` shared-object fixture loaded in-process. It therefore
validates this narrow adapter slice while leaving broader relocation, TLS,
constructor/destructor lifecycle, dynamic path-search, dependency, and
instruction-property combinations explicit in
the compatibility matrix. The real fixture is the positive HostContext
baseline; bounded copies that turn a PT_LOAD-covered metadata segment into a
structurally valid PT_TLS segment, and a malformed PT_TLS segment with
`p_filesz > p_memsz`, must both be rejected before an image handle is created.
PT_GNU_PROPERTY is a separate rejected boundary: HostContext v1 and this
system-loader adapter define no property negotiation or BTI/PAC/instruction-
state obligations, so an adapter must reject a bounded property-header
mutation with `URP_STATUS_UNSUPPORTED` and a zero image handle even if a
system loader would accept its note. The self-test changes only the bounded
program-header type and retains the unmodified entry image as the positive
baseline. DT_NEEDED dependency resolution is the separately evidenced
`runtime.host-context.dependency-resolution` boundary: HostContext v1 defines
no dependency-resolution, search-path, symbol-scope, or dependency-lifetime
semantics, so loader resolution alone is not support. Its bounded dynamic-table
mutation preserves surrounding bytes, uses a sentinel output handle, and must
return `URP_STATUS_UNSUPPORTED` with a zero handle before loader handoff.
Constructor/destructor metadata is the separate rejected boundary
`runtime.host-context.constructor-destructor`. HostContext v1 and this adapter
define no constructor/destructor ordering, callback or reentrancy behavior,
teardown, or lifecycle ownership semantics. The self-test mutates each of
`DT_INIT`, `DT_FINI`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY`, `DT_INIT_ARRAYSZ`,
`DT_FINI_ARRAYSZ`, `DT_PREINIT_ARRAY`, and `DT_PREINIT_ARRAYSZ` into one bounded
`DT_NULL` slot, preserves all surrounding bytes, initializes a nonzero handle
sentinel, and requires a zero handle before loader handoff. The unchanged
non-lifecycle entry fixture remains the positive HostContext baseline.

RPATH/RUNPATH metadata is the separate rejected boundary
`runtime.host-context.path-search`. HostContext v1 and this adapter define no
dynamic path-search roots, ordering, or precedence semantics, so each bounded
mutation also fails closed before image creation. Unsupported relocation-table
forms remain a separate later relocation boundary, rather than being included
in either lifecycle or path-search row.

Writable-text relocation metadata is the separate rejected boundary
`runtime.host-context.text-relocation`. HostContext v1 and this adapter define
no writable-text relocation or W^X/protection semantics for in-process images,
so loader acceptance alone is not a compatibility proof. The self-test mutates
one bounded `DT_NULL` slot to `DT_TEXTREL`, preserves all surrounding bytes,
initializes a nonzero output-handle sentinel, and requires
`URP_STATUS_UNSUPPORTED` with a zero handle before loader handoff. The
unchanged non-text-relocation entry fixture remains the positive HostContext
baseline. Unsupported relocation-table tags such as `DT_REL` and `DT_JMPREL`
remain a separate later rejection boundary; checked AArch64 `RELATIVE`/`RELR`
acceptance and system-loader application remain the validated relocation
feature.

The runtime accepts the legacy frame v1 and HostContext frame v2. Both use the
same 112-byte common header. A v2 header is 136 bytes and appends, in order,
the HostContext ABI version, a reserved zero field, required capability bits,
the UTF-8 entry-symbol byte length, and a second reserved zero field. Its
variable data is `source_name`, `entry_name`, then compressed payload. The
runtime validates those fields before decoding and copies the bounded entry
name into a terminated local buffer before symbol lookup.

Legacy v1 keeps its wrapper-absolute encoded offset for the existing launcher.
HostContext v2 uses a frame-relative encoded offset because the standalone
runtime receives the frame slice directly; the managed wrapper reader applies
the corresponding versioned interpretation.

Run the native contract self-test on a native AArch64 host:

```sh
make -C native/urprotect-runtime test
```
