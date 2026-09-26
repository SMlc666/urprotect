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
protection. This adapter accepts AArch64 `RELATIVE`/`RELR` forms with checked
writable targets, the existing bounded GLOB_DAT form, and the exact
weak-undefined JUMP_SLOT PLT subset described below. The PLT subset requires
immediate binding; other PLT/symbol combinations remain rejected. Section
headers are not consulted by this adapter; bounded program headers and mapped
dynamic metadata are authoritative for the sectionless image slice.

The self-test includes both the deterministic fake host contract oracle and a
real AArch64 `urp_entry` shared-object fixture loaded in-process. A separate
linker-produced graph fixture declares exactly `libc.so.6` and
`ld-linux-aarch64.so.1`; its native self-test checks dispatch status 37,
release, both dependency orders, and all three loader-environment negatives,
asserting that rejected environment values do not increment the memfd-create
count; it also verifies that the prior singleton remains loadable under a
nonempty `LD_LIBRARY_PATH`. A separate probe confirms that the controlled fake
loader's constructor marker works; the managed oracle places that
matching-SONAME object on `LD_LIBRARY_PATH` and requires status 4 with no
fake-loader or entry marker.
The graph self-test also loads a linker-produced pair image with an unresolved
strong `R_AARCH64_GLOB_DAT` import: preflight accepts its exact dependency
pair, `RTLD_NOW` fails with `URP_STATUS_LOAD_FAILED`, the output handle remains
zero, and `/proc/self/fd` returns to its prior count. This proves rollback
after memfd creation and loader handoff have begun.
The managed oracle retains the pair's `readelf` facts, environment, status,
streams, native self-test, and release marker.
This dependency-pair claim is glibc-only and does not promote musl or bionic. It directly
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
boundary. The singleton fixture continues to accept one recognized system-libc basename. A separate pair fixture accepts only the unique direct glibc pair `libc.so.6` and `ld-linux-aarch64.so.1`; arbitrary dependency graphs, filters, auxiliary dependencies, and payload-controlled search paths remain rejected.
The same `libc.so.6` slice has a separate validated
`runtime.host-context.dependency-symbol-version-requirements` row: the adapter
requires `DT_GNU_HASH`, rejects `DT_SYMBOLIC`, and requires a complete
`DT_VERSYM`/`DT_VERNEED`/`DT_VERNEEDNUM` tuple, bounds every
version-need and auxiliary record, requires each `vn_file` to match the sole
`DT_NEEDED` basename `libc.so.6`, and checks the version-name hash/index fields.
SysV `DT_HASH` alone or combined with `DT_GNU_HASH` is outside this slice.
`RTLD_NOW` delegates resolution of those imported libc versions to the native
loader. The retained fixture has a versioned `libc.so.6` import and returns
status 37 on native AArch64 glibc. `DT_VERDEF`/`DT_VERDEFNUM`, weak-version
requirements, versioned imports from other libc names, mismatched dependency
names, and versioned entry selection stay outside the contract.
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

HostContext accepts one exact PLT RELA subset recorded as
`runtime.host-context.weak-undefined-jump-slot`: all of `DT_JMPREL`,
`DT_PLTRELSZ`, and `DT_PLTREL=DT_RELA` must occur once; `DT_RELAENT` and
`DT_SYMENT` must exactly match AArch64 ELF64 entry sizes; the bounded table may
contain only aligned writable in-image `R_AARCH64_JUMP_SLOT` targets referring
to file-backed `STB_WEAK`, `STT_FUNC`, `st_other == STV_DEFAULT`,
`SHN_UNDEF` dynsym records. This subset has no `DT_NEEDED` or symbol-version
tags and rejects
`DT_SYMBOLIC`/non-preemptive flags. Binding is immediate (`DF_BIND_NOW` or
`DF_1_NOW`) and the adapter opens with `RTLD_NOW`. Lookup follows the native
loader's existing global scope and then the image's declared dependencies
(none here); an unresolved weak function resolves to zero. The managed
AArch64 glibc oracle observes zero from the entry and returns status 53. This
is not generic PLT/JUMP_SLOT or arbitrary libc-import support.

`runtime.host-context.unsupported-relocation-table` still rejects `DT_REL`,
`DT_RELSZ`, and `DT_RELENT`, and rejects partial, duplicate, inconsistent,
malformed, dependency-bearing, versioned, or other out-of-slice PLT metadata
before loader handoff. Its self-test checks the zero-handle result. The
unchanged RELATIVE/RELR and GLOB_DAT status-29 rows remain intact.

Android packed relocation tags are a distinct rejected boundary recorded as
`runtime.host-context.android-packed-relocation`. It covers `DT_ANDROID_REL`,
`DT_ANDROID_RELSZ`, `DT_ANDROID_RELA`, `DT_ANDROID_RELASZ`, `DT_ANDROID_RELR`,
`DT_ANDROID_RELRSZ`, `DT_ANDROID_RELRENT`, and `DT_ANDROID_RELRCOUNT`;
HostContext v1 defines only the checked AArch64 `RELATIVE`/`RELR` forms, so
packed encodings fail with `URP_STATUS_UNSUPPORTED` before loader handoff.
ELF symbol-version tags are a separate rejected boundary,
`runtime.host-context.symbol-version` for versioned definitions and out-of-slice
requirements. The adapter always rejects `DT_VERDEF`/`DT_VERDEFNUM`; import
requirements are accepted only for `libc.so.6` by the separate row above.
HostContext v1 continues to select the declared entry with an unversioned
symbol name. The no-dependency self-test mutates each version tag individually
and requires a zero handle for unsupported forms; the versioned libc fixture
separately verifies complete import requirements and nearest malformed cases.

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
