# HostContext runtime core

This directory defines the versioned, host-neutral `HostContext` entry
contract and a bounded frame-dispatch runtime. The current production frame is
v3 with an explicit `host-context-entry` profile. `urp_runtime_execute_frame`
verifies the selected frame and both payload digests, asks the host for an
immutable image, resolves the declared entry symbol, invokes it, and releases
the image before returning. v1/v2 remain isolated migration-test layouts.

The native implementation has two deliberate ownership boundaries:
`host_image_validation.c` owns bounded in-memory AArch64 ELF preflight (program
headers, dynamic metadata, relocation targets, TLS, GNU properties, and
unsupported-feature rejection), while `host_adapter.c` owns sealed-memfd
creation, loader handoff, symbol lookup, and image release. The adapter invokes
the preflight before it can create an image handle; it does not carry a second
validation path.

The native evidence adapter implements the contract with an anonymous memfd
created with `MFD_ALLOW_SEALING` and the host's `dlopen`/`dlsym` loader through
the generated virtual `/proc/self/fd/<N>` reference. After the verified source
bytes are fully written, it adds and verifies `F_SEAL_WRITE`, `F_SEAL_SHRINK`,
`F_SEAL_GROW`, and `F_SEAL_SEAL` before `dlopen`; any unavailable or incomplete
sealing operation closes the descriptor and fails the load. It creates no
executable filesystem pathname and keeps the sealed descriptor open until
`release_image`. Before loading, the adapter requires AArch64 ELF64 `ET_DYN`
program headers and rejects an
interpreter, unsupported TLS model, unsupported GNU property, unsupported
dependency graph, text-relocation, or path-search requirement that this first
entry slice does not define. The
current bounded P3 slice accepts one recognized system-libc dependency with no
RPATH/RUNPATH and delegates constructor-before-entry/destructor-before-release
ordering to the system loader. The bounded P4-A slice accepts AArch64
initial-exec PT_TLS with `R_AARCH64_TLS_TPREL64`; dynamic TLS, new-thread
initialization, and live-thread unload remain outside the contract. Failed
adapter loads clear the output image handle before returning their stable
status.
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
dynamic path-search, dependency graphs, and instruction-property combinations explicit in
the compatibility matrix. The real fixture is the positive HostContext
baseline; bounded copies that turn a PT_LOAD-covered metadata segment into a
structurally valid PT_TLS mutation, and a malformed `p_filesz > p_memsz`
mutation, are rejected before image creation. PT_GNU_PROPERTY has a bounded
validated BTI slice: the adapter parses a GNU property note, accepts only
AArch64 FEATURE_1 BTI/PAC bits, and rejects malformed or unknown bits. The
BTI-instrumented fixture reaches the managed entry oracle with status 47.
DT_NEEDED, DT_AUXILIARY, and DT_FILTER dependency metadata
form the separately evidenced `runtime.host-context.dependency-resolution`
boundary. The current positive fixture accepts only one recognized system-libc
basename with fixed default loader roots; arbitrary dependency graphs, filters,
auxiliary dependencies, and payload-controlled search paths remain rejected.
Constructor/destructor metadata is the separate bounded
`runtime.host-context.constructor-destructor` slice. The system loader runs
nonzero constructor metadata before `urp_entry` and destructor metadata during
`release_image`; the dependency fixture observes both sides. Zero-valued
lifecycle mutations remain rejected before loader handoff, while reentrancy,
live-thread teardown, and broader lifecycle ownership remain outside this
slice.

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
