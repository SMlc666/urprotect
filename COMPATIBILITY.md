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

The matrix feature `runtime.wrapper-v1-baseline` preserves the current Wrapper
0.2 v1 frame, managed pack, and native launcher as migration regression
evidence. It is deliberately separate from HostContext v2 and is not an
in-process compatibility claim. The existing Android row
`android.jni.native-bridge` is likewise a JNI/native-bridge baseline: it does
not execute packed output or prove a native ARM64 Android device/runtime.

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
targets while the system loader applies them. The bounded
`elf.relocation.aarch64-symbolic` slice additionally accepts a checked
`R_AARCH64_GLOB_DAT` entry with a file-backed dynamic symbol table record and
writable target; its managed v3 profile oracle returns status 29. A separate
`runtime.host-context.weak-undefined-jump-slot` row accepts only a complete
RELA PLT tuple whose entries are `R_AARCH64_JUMP_SLOT` for file-backed,
undefined weak `STT_FUNC` symbols with `st_other == STV_DEFAULT` and
`st_shndx == SHN_UNDEF`. It requires NOW binding and excludes `DT_NEEDED`,
symbol-version metadata, and non-preemptive-local flags. The loader's
current global scope is searched before the image's dependency scope (empty for
this subset); unresolved weak functions resolve to zero. The real managed
AArch64 glibc fixture observes zero and returns status 53. This does not claim
generic PLT/JUMP_SLOT or cross-libc PLT resolution. Partial or malformed PLT
tables and all out-of-slice symbol combinations remain pre-handoff rejections;
legacy REL tables remain rejected. The exact `libc.so.6` dependency slice,
including its import-version boundary, is specified separately below.
Broader dependency graphs, dynamic TLS, live-thread lifecycle, and unknown GNU
properties remain outside the bounded validated rows.

The first expanded ELF slice is sectionless `ET_DYN`: section headers are
optional metadata, so the parser and validator use bounded program headers and
the load map as the runtime authority. `ElfParserTests` provides the positive
witness and the malformed corpus keeps a paired alignment rejection; this
proves the parser boundary, not arbitrary loader behavior.

The managed parser has parser-only rows `elf.symbol-version.definitions` and
`elf.symbol-version.requirements` for bounded `DT_VERDEF` and `DT_VERNEED`
records, respectively, including dynamic-string-table auxiliaries and malformed
chain diagnostics. Parser observation does not define runtime symbol
resolution. HostContext rejects versioned definitions and versioned entry
selection under `runtime.host-context.symbol-version`; one narrower
dependency-side import slice is separately validated below. The checked-in
registry baseline's `symbol-versions: 7` entry is a prioritization cue, not a
runtime support claim.

The HostContext production slice includes the preserved single-system-libc
witness and a separate closed native-glibc pair witness. The existing singleton
accepts one recognized libc basename with bounded string-table metadata. The
new `runtime.host-context.bounded-glibc-loader-dependency` row accepts exactly
the unique direct pair `libc.so.6` and `ld-linux-aarch64.so.1`, in either order,
with no third or duplicate name. This pair is validated only on native AArch64
glibc. The process loader namespace shares its already-loaded libc and loader
objects; HostContext retains and releases only the sealed memfd-backed entry
root. The pair requires `LD_LIBRARY_PATH`, `LD_PRELOAD`, and `LD_AUDIT` unset or
empty, checked after ELF preflight and before memfd creation. Search roots are
the native process namespace's fixed defaults; payload directories, RPATH,
RUNPATH, `$ORIGIN`, arbitrary graphs, cycles, filters, and auxiliary dependencies
remain rejected. The pair fixture's constructor is observed by `urp_entry`,
and its destructor writes a release marker. Native tests cover both
`DT_NEEDED` orders and verify that the environment gate leaves the memfd-create
count unchanged, while a singleton regression still loads with a nonempty
`LD_LIBRARY_PATH`. A controlled fake-loader probe verifies its marker before
the managed oracle places it under `LD_LIBRARY_PATH`; the pair launch returns
4 without the fake-loader or entry marker. No musl or bionic dependency-pair
support is claimed. A separate valid-pair fixture with an unresolved strong
`R_AARCH64_GLOB_DAT` proves a post-memfd `RTLD_NOW` failure returns
`URP_STATUS_LOAD_FAILED`, clears the output handle, and leaves no descriptor
increase after rollback.
The associated import-side symbol-version slice is recorded as
`runtime.host-context.dependency-symbol-version-requirements`: it requires the
complete `DT_VERSYM`/`DT_VERNEED`/`DT_VERNEEDNUM` tuple, bounded and terminating
version-need/auxiliary chains, valid version-name hash/index fields, non-weak
requirements, exact equality between every `vn_file` and the `DT_NEEDED`
basename `libc.so.6`, and no versioned imports attached to recognized musl or
bionic sonames. It requires `DT_GNU_HASH`, rejects `DT_SYMBOLIC`, and excludes
SysV `DT_HASH` alone or combined. The native preflight bounds the hash-derived symbol count to
1,048,576 and checks the file-backed version-symbol table. `RTLD_NOW` delegates
resolution to the native loader; a
linker-produced fixture with a `libc.so.6` `GLIBC_*` requirement
returns status 37 on native AArch64 glibc. This does not add arbitrary
versioned definitions, entry selection, dependency graphs, or search paths.

PT_TLS has a bounded validated HostContext slice, recorded as
`runtime.host-context.pt-tls` in the matrix. It covers AArch64 initial-exec TLS
with a structurally bounded PT_TLS segment and `R_AARCH64_TLS_TPREL64`; the
system loader owns module allocation and initialization. The managed v3 oracle
uses a real TLS-backed entry and returns status 43. Dynamic TLS models,
new-thread initialization, reentrancy, and unload with live TLS users remain
outside the claim.

PT_GNU_PROPERTY has a bounded validated HostContext feature recorded as
`runtime.host-context.gnu-property`. The adapter accepts a GNU property note
containing only AArch64 FEATURE_1 BTI/PAC bits and rejects malformed notes or
unknown feature bits. A BTI-instrumented property fixture reaches the managed
v3 entry oracle and returns status 47 on the native glibc lane. PAC negotiation
beyond the note mask and host instruction-state conflicts remain outside the
claim. The bounded dependency slice is separately recorded as
`runtime.host-context.dependency-resolution`: one recognized system-libc
`DT_NEEDED` basename, bounded string-table metadata, fixed native loader roots,
and no RPATH/RUNPATH. Arbitrary graphs, filters, auxiliary dependencies, and
payload-controlled search paths remain rejected.

Constructor/destructor metadata is a separate bounded validated slice recorded
as `runtime.host-context.constructor-destructor`. Nonzero `DT_INIT`, `DT_FINI`,
`DT_INIT_ARRAY`, `DT_FINI_ARRAY`, `DT_INIT_ARRAYSZ`, `DT_FINI_ARRAYSZ`,
`DT_PREINIT_ARRAY`, and `DT_PREINIT_ARRAYSZ` follow the system-loader ordering:
constructors before entry and destructors during release. HostContext v1 and the current
system-loader adapter define no callback or reentrancy behavior, live-thread
teardown, or broader lifecycle ownership semantics. The dependency fixture
observes constructor state in entry and writes a release marker from its
destructor; zero-valued lifecycle mutations remain rejected by the native
self-test.

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

Unsupported dynamic relocation-table metadata remains recorded as
`runtime.host-context.unsupported-relocation-table`: legacy `DT_REL`,
`DT_RELSZ`, and `DT_RELENT` are rejected, as are partial, duplicate,
inconsistent, malformed, dependency-bearing, versioned, or out-of-subset PLT
RELA tables. The exact weak-undefined JUMP_SLOT subset has its own
`runtime.host-context.weak-undefined-jump-slot` row. Its native negative oracle
asserts rejection and a zero output handle before loader handoff; the unchanged
RELATIVE/RELR and GLOB_DAT status-29 fixtures remain positive baselines.

Android packed relocation encodings are separately rejected as
`runtime.host-context.android-packed-relocation`. The adapter rejects
`DT_ANDROID_REL`, `DT_ANDROID_RELSZ`, `DT_ANDROID_RELA`, `DT_ANDROID_RELASZ`,
`DT_ANDROID_RELR`, `DT_ANDROID_RELRSZ`, `DT_ANDROID_RELRENT`, and
`DT_ANDROID_RELRCOUNT` before loader handoff because HostContext v1 defines
only the checked AArch64 `RELATIVE`/`RELR` relocation path. ELF symbol-version
`runtime.host-context.symbol-version` rejects `DT_VERDEF`/`DT_VERDEFNUM`,
versioned entry exports, and incomplete/out-of-scope import-version tables.
The native no-dependency self-test mutates individual tags and requires
`URP_STATUS_UNSUPPORTED` with a zero image handle. Only the complete
single-libc import requirement defined by
`runtime.host-context.dependency-symbol-version-requirements` is accepted;
entry lookup remains unversioned and no other versioned symbol behavior is
inferred from loader acceptance.

The native Termux/bionic case is a peer runtime fact beside glibc and musl. It
records native ARM64 container execution, `/system/bin/linker64`, kernel and
page-size facts, and the pinned image/source revision. The live package index
is used only to locate the exact compiler dependency set in the manifest;
versions, artifact paths, SHA-256 hashes, and license identifiers are locked.
The lane checks the downloaded package set and hashes before installation,
fails on additional or changed packages, and retains the lock, hash-verification
output, and before/after inventories. The image digest pins the base userspace,
so the compiler inputs are reproducible despite the live index. The lane also
builds and runs `native/urprotect-runtime` inside Termux. Its HostContext v2
frame is passed to the real fd-backed adapter, the self-test verifies all
required memfd seals on the image, dispatches `urp_entry` through bionic's
`dlopen`/`dlsym` path, checks status and release, and retains the build log,
ELF report, and fixture hash. This validates the narrow bionic adapter
handoff, with no executable temporary pathname. It does not upgrade the
separate production managed-pack integration row
`runtime.host-context.production-pack`, which now has a retained managed v3
profile oracle on the native glibc lane. The bionic adapter evidence remains a
peer runtime fact and does not silently promote the glibc production row.
The bionic evidence intentionally excludes Android framework, OEM, SELinux,
device-kernel, AVD, Waydroid, QEMU, and native-bridge claims.

The outer-execveat profile now has a separate dynamic `ET_EXEC` compatibility
slice. Its exact acceptance predicate is ELF64 little-endian AArch64 with an
executable entry in `PT_LOAD`, `PT_DYNAMIC`, a terminated absolute `PT_INTERP`
ending in `/ld-linux-aarch64.so.1` or `/ld-musl-aarch64.so.1`, and no
`DT_RPATH` or `DT_RUNPATH`. `ElfParser` and `ElfValidator` model the class;
parser/model observation is recorded separately as
`elf.identity.aarch64-et-exec`; `ElfPackService` owns the outer-profile
decision recorded as `elf.outer.dynamic-et-exec`; the unchanged v3 frame
carries the source; and the existing static launcher recovers it and hands it to
`execveat(AT_EMPTY_PATH)`. Shared objects, static `ET_EXEC`, missing or
duplicate `PT_INTERP` entries, and unrecognized interpreters remain rejected.
The native glibc fixture compares baseline and wrapped status, stdout/stderr,
source-name `argv[0]`, arguments, environment, cwd, an inherited descriptor,
a declared-file side effect, and signal termination. This row establishes a
native AArch64 glibc outer-profile claim only; the packer's recognized musl
interpreter path does not independently validate a musl runtime. HostContext
semantics remain unchanged.

The production managed pack path now uses current frame v3 with explicit
`outer-execveat` and `host-context-entry` profiles. The outer profile retains
the static launcher and `execveat(AT_EMPTY_PATH)` behavior. The HostContext
profile uses the profile-matched HostContext launcher, sealed memfd loading,
exact entry lookup, exactly-once dispatch, release, and status preservation.
Legacy v1/v2 behavior remains migration evidence only; current launchers reject
stale versions and profile/launcher mismatches.

The claim therefore applies to every correctly implemented host satisfying the
contract, not to an unqualified statistical majority of phone vendors.
