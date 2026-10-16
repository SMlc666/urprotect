# HostContext runtime core

This directory defines the current host-neutral `HostContext` entry
contract and a bounded v3 frame-dispatch runtime. The current production frame
has an explicit dispatch profile. `urp_runtime_execute_frame` verifies the
selected frame and both payload digests, asks the host for an immutable image,
resolves the declared entry symbol, invokes it, and releases the image before
returning.

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
entry slice does not define. The current bounded P3 slice accepts the recognized
system-libc singleton or the exact glibc pair `libc.so.6` plus
`ld-linux-aarch64.so.1`, with no RPATH/RUNPATH, and delegates
constructor-before-entry/destructor-before-release ordering to the system
loader. The bounded P4-A metadata preflight validates AArch64
`R_AARCH64_TLS_TPREL64`, `R_AARCH64_TLS_DTPMOD64`,
`R_AARCH64_TLS_DTPREL64`, and `R_AARCH64_TLSDESC` owners against PT_TLS.
For ELF64 `ET_DYN`, `STT_TLS.st_value` is interpreted only as a TLS-block-relative
offset, with symbol extent and addend bounds checked before loader handoff.
Separate transformed current-thread HostContext glibc oracles exercise
initial-exec, local-dynamic, general-dynamic, and TLSDESC using distinct source
fixtures, status 43, retained lifecycle evidence, and baseline-vs-transformed
behavior comparisons. These rows do not promote outer-execveat, registered
workers, musl, or bionic. The optional registered-worker extension remains
limited to the separately evidenced initial-exec glibc path. Thread creation,
join, and release are restricted to the image owner; routine addresses are
checked against the root `link_map`; opaque thread handles are monotonic and
never reused. Release closes the spawn gate, joins all workers and their native
TLS-key teardown, then calls `dlclose`. A linker-produced fixture and packed
wrapper harness observe initialized data/zero-fill, deterministic worker gates,
constructor/entry/worker/TLS teardown/destructor ordering, explicit and
automatic joins, serial reruns, and concurrent independent dispatches. Dynamic
TLS worker lifecycle, unmanaged workers, recursive dispatch, and musl/bionic
threaded claims remain outside the contract. Failed adapter loads clear the
output image handle before returning their stable status.
The system loader remains the authority for applying relocation and memory
protection. This adapter accepts AArch64 `RELATIVE`/`RELR` forms with checked
writable targets, the bounded GLOB_DAT form, the validated TLS metadata forms
listed above, and the exact weak-undefined JUMP_SLOT PLT subset described
below. The PLT subset requires immediate binding; other PLT/symbol combinations
remain rejected. Section
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
validates this narrow adapter dependency slice without broadening relocation,
TLS lifecycle, dynamic path-search, dependency graph, or instruction-property
claims beyond their separately evidenced rows in the compatibility matrix. The real fixture is the positive HostContext
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
version-need and auxiliary record, requires each `vn_file` to match a declared
`DT_NEEDED` basename, and checks the version-name hash/index fields. The only
admitted names are the `libc.so.6` singleton or the already-validated exact
`libc.so.6` plus `ld-linux-aarch64.so.1` pair; this does not admit other
libraries or dependency graphs.
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
lifecycle mutations remain rejected before loader handoff. The optional
`URP_HOST_CAP_THREAD_LIFETIME` extension appends managed create/join callbacks;
the current HostContext table is 72 bytes with a 56-byte minimum. Launch args
carry the opaque active image handle in the current 40-byte view with a 32-byte
minimum. Adapter release
joins registered workers before `dlclose`, so worker TLS teardown completes
before image destructors. This extension's runtime claim remains evidence-gated
to native AArch64 glibc.

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

The current v3 header is 144 bytes and appends, in order, the HostContext ABI
version, a reserved zero field, required capability bits, the UTF-8 entry-symbol
byte length, a dispatch profile, and a second reserved zero field. Its variable
data is `source_name`, optional `entry_name`, then compressed payload. The outer
profile carries no HostContext metadata and is handled by the separate static
launcher. The runtime validates the fields before decoding and copies the
bounded entry name into a terminated local buffer before symbol lookup. The
encoded offset is frame-relative for both profiles. The managed `pack` path
selects v3 and validates the profile-specific launcher marker before
publication. `host-context-launcher` discovers the appended frame, invokes
`urp_runtime_execute_wrapper`, and returns the declared entry status.

Run the native contract self-test on a native AArch64 host:

```sh
make -C native/urprotect-runtime test
```

The transformed CFI runtime oracle is a separate native C++ unwinding test.
Its C fixture and C traversal frames retain asynchronous unwind tables without
adding C++ runtime dependencies to the fixture. A typed exception is thrown
from the host callback while the target and register-call assembly frames are
active, then caught at the outer C++ boundary; the oracle records the throw-site
target frame, typed token, RAII cleanup, no-normal-return condition, and release
status. The transformed run invokes the address and size from the rehydration
address map. Legacy C `setjmp`/`longjmp` and cancellation observations remain
separate evidence. Retained records bind the exact C/C++ compiler and
libstdc++/libgcc/glibc identities, raw baseline/transformed observations, and
readelf frame witnesses; see `scripts/run-cfi-host-context-e2e.sh` and
`scripts/check-cfi-evidence.py`.

## Trusted external jump-table provider (glibc-only native slice)

An explicitly configured HostContext adapter may load one dependency-free
AArch64 provider DSO for the bounded external signed-relative jump-table
fixture. The host supplies the provider path plus the exact expected SONAME,
GNU build ID, and SHA-256; none of these values or paths come from the consumer
ELF or Protected Image. The provider file is opened without following symlinks,
snapshotted as a bounded regular file, hashed, and compared with the pinned
SHA-256 before ELF parsing. It must have the exact SONAME, no dependencies or
RPATH/RUNPATH, one 16-byte defined table object in a file-backed read-only
`PT_LOAD`, and the validated provider-local executable targets.

The consumer may have exactly one `DT_NEEDED`, naming that configured provider.
Missing, extra, duplicate, or mismatched provider dependencies—and the exact
undefined table-object GLOB_DAT import without that dependency—are rejected
before memfd creation or loader activity. The consumer's undefined global,
default-visible `STT_OBJECT` may have `st_size == 0` (GNU ld's normal output);
the authenticated provider definition supplies the 16-byte size/range, and the
adapter verifies the runtime table mapping and GOT pointer against it. The GOT
slot remains a pointer, not table storage. Provider and consumer RPATH/RUNPATH
are not accepted, and `LD_LIBRARY_PATH`, `LD_PRELOAD`, and `LD_AUDIT` must be
unset or empty; no environment or payload path selects a provider.

On glibc, the adapter loads the sealed provider descriptor into a fresh
`dlmopen(LM_ID_NEWLM, ..., RTLD_NOW | RTLD_LOCAL)` namespace and loads the
consumer into that exact link-map namespace with local visibility. Before
publishing the consumer handle it verifies the actual provider `link_map`, the
provider's read-only table mapping/bytes, and the consumer GOT value. The
provider handle remains pinned until the last dependent consumer is released;
consumer teardown precedes provider teardown. A pre-existing same-SONAME
base-namespace object is rejected by policy, while a different-SONAME global
object exporting the same symbol cannot alter the isolated binding.

Configured consumer candidate preflight uses an aggregate 8 MiB work budget,
initialized before the program-header walk and carried through `PT_DYNAMIC`/
`DT_NEEDED` processing, relocation validation, GNU-hash traversal, and dynsym
checks. The pinned provider DSO parser has a separate, independent aggregate
8 MiB budget for its program-header/indexed-range, GNU-hash, dynsym, and string
work. The indexed load ranges avoid rescanning program headers for each symbol.
The native regression covers an exact-limit pass and a one-unit-under-limit
rejection, missing `DT_NEEDED` with both configured and unconfigured adapters,
unchanged memfd/loader counters for preflight failures, same-SONAME collision
rejection, and successful binding in the presence of a different-SONAME global
symbol collision. This is source fixture/native-loader evidence only; it is not
proof of managed transformation or rehydration. No musl or bionic provider
support is claimed.
