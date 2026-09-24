# HostContext runtime core

This directory defines the versioned, host-neutral `HostContext` entry
contract and a bounded frame-dispatch runtime. The current production frame is
v3 with an explicit `host-context-entry` profile. `urp_runtime_execute_frame`
verifies the selected frame and both payload digests, asks the host for an
immutable image, resolves the declared entry symbol, invokes it, and releases
the image before returning. v1/v2 remain isolated migration-test layouts.

The native evidence adapter implements the contract with an anonymous memfd
created with `MFD_ALLOW_SEALING` and the host's `dlopen`/`dlsym` loader through
the generated virtual `/proc/self/fd/<N>` reference. After the verified source
bytes are fully written, it adds and verifies `F_SEAL_WRITE`, `F_SEAL_SHRINK`,
`F_SEAL_GROW`, and `F_SEAL_SEAL` before `dlopen`; any unavailable or incomplete
sealing operation closes the descriptor and fails the load. It creates no
executable filesystem pathname and keeps the sealed descriptor open until
`release_image`. Before loading, the adapter requires AArch64 ELF64 `ET_DYN`
program headers and rejects an
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
real AArch64 `urp_entry` shared-object fixture loaded in-process. It directly
loads that fixture through the adapter, checks the test-visible seal invariant,
and releases the image before exercising frame dispatch. It therefore
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
baseline. DT_NEEDED, DT_AUXILIARY, and DT_FILTER dependency metadata
form the separately evidenced `runtime.host-context.dependency-resolution`
boundary: HostContext v1 defines no dependency-resolution, search-path,
symbol-scope, or dependency-lifetime semantics, so loader resolution alone is
not support. Its bounded dynamic-table mutations preserve surrounding bytes,
use a sentinel output handle, and must return `URP_STATUS_UNSUPPORTED` with a
zero handle before loader handoff.
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
tags use the separate
`runtime.host-context.unsupported-relocation-table` rejection boundary, rather
than being included in either lifecycle or path-search row.

Writable-text relocation metadata is the separate rejected boundary
`runtime.host-context.text-relocation`. HostContext v1 and this adapter define
no writable-text relocation or W^X/protection semantics for in-process images,
so loader acceptance alone is not a compatibility proof. The self-test mutates
one bounded `DT_NULL` slot to `DT_TEXTREL`, preserves all surrounding bytes,
initializes a nonzero output-handle sentinel, and requires
`URP_STATUS_UNSUPPORTED` with a zero handle before loader handoff. The
unchanged non-text-relocation entry fixture remains the positive HostContext
baseline. Unsupported relocation-table tags use the separate
`runtime.host-context.unsupported-relocation-table` rejection boundary; checked
AArch64 `RELATIVE`/`RELR` acceptance and system-loader application remain the
validated relocation feature.

Unsupported dynamic relocation-table tags are independently rejected by the
HostContext v1 adapter under
`runtime.host-context.unsupported-relocation-table`. The boundary covers
`DT_REL`, `DT_RELSZ`, `DT_RELENT`, `DT_JMPREL`, `DT_PLTRELSZ`, and `DT_PLTREL`;
the current system-loader contract defines only the checked AArch64
`RELATIVE`/`RELR` path, so each tag is rejected before relocation processing
or image-handle creation. The self-test mutates one bounded `DT_NULL` slot at a
time, preserves surrounding bytes, initializes a nonzero handle sentinel, and
requires `URP_STATUS_UNSUPPORTED` with a zero handle. The unchanged
`RELATIVE`/`RELR` fixture remains the positive baseline, and no broader
relocation-table support is claimed.

Android packed relocation tags are a distinct rejected boundary recorded as
`runtime.host-context.android-packed-relocation`. It covers `DT_ANDROID_REL`,
`DT_ANDROID_RELSZ`, `DT_ANDROID_RELA`, `DT_ANDROID_RELASZ`, `DT_ANDROID_RELR`,
`DT_ANDROID_RELRSZ`, `DT_ANDROID_RELRENT`, and `DT_ANDROID_RELRCOUNT`;
HostContext v1 defines only the checked AArch64 `RELATIVE`/`RELR` forms, so
packed encodings fail with `URP_STATUS_UNSUPPORTED` before loader handoff.
ELF symbol-version tags are a separate rejected boundary,
`runtime.host-context.symbol-version`, covering
`DT_VERSYM`, `DT_VERDEF`, `DT_VERDEFNUM`, `DT_VERNEED`, and `DT_VERNEEDNUM`.
HostContext v1 defines unversioned entry-symbol lookup only. The self-test
mutates one bounded `DT_NULL` slot per tag, preserves surrounding bytes, uses a
nonzero image-handle sentinel, and requires a zero handle on rejection; the
unchanged unversioned `urp_entry` image remains the positive baseline.

The runtime retains legacy frame v1 and HostContext frame v2 only for migration
tests. The current v3 header is 144 bytes and appends, in order, the HostContext
ABI version, a reserved zero field, required capability bits, the UTF-8
entry-symbol byte length, a dispatch profile, and a second reserved zero field.
Its variable data is `source_name`, optional `entry_name`, then compressed
payload. The outer profile carries no HostContext metadata and is handled by
the separate static launcher. The runtime validates the fields before decoding
and copies the bounded entry name into a terminated local buffer before symbol
lookup.

Legacy v1 keeps its wrapper-absolute encoded offset for migration evidence.
HostContext v2 uses a frame-relative encoded offset in its migration self-test.
Current v3 uses a frame-relative offset for both explicit profiles. The current
managed `pack` path selects v3 and validates the profile-specific launcher
marker before publication. `host-context-launcher` discovers the appended
frame, invokes `urp_runtime_execute_wrapper`, and returns the declared entry
status.

Run the native contract self-test on a native AArch64 host:

```sh
make -C native/urprotect-runtime test
```
