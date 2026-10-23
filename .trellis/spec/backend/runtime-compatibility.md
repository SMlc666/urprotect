# Runtime Compatibility Contract

## Scenario: Unified AArch64 runtime and evidence matrix

### 1. Scope / Trigger

This contract applies to changes that cross `UrProtect.Core`, the managed CLI,
native runtime/launcher code, fixture scripts, the compatibility manifest, or
CI. The product has one host-neutral runtime contract. `glibc`, `musl`, and
`bionic` are runtime facts or evidence environments, not user-selectable
compatibility modes.

The compatibility claim is conditional: a payload is executable only when its
frame and ELF invariants pass and the host implements the declared HostContext
ABI. A deterministic runtime pass is evidence for an implementation; it does
not by itself upgrade an unproved host behavior to `proven`.

### Development-stage scope and evolution policy

UrProtect is an AArch64/ARM64-only product. The current compatibility roadmap
does not add x86_64, ARM32, RISC-V, or another architecture backend. Technical
contracts and examples should use **AArch64**; user-facing text may explain the
term as ARM64.

The project is in the 0.x rapid-development stage. Breaking changes to the
frame format, HostContext ABI, launcher ABI, CLI contract, report schema, and
fixture contracts are allowed when the current design requires them. A change
to one of these cross-layer contracts must update every producer, consumer,
validation rule, test, fixture, evidence declaration, and document in the same
change. Do not add a compatibility adapter solely to preserve an obsolete
internal production path.

The production runtime should converge on one current versioned packaging
contract with explicit execution profiles. The current profiles are
`outer-execveat` for standalone AArch64 executable recovery and
`host-context-entry` for an entry image loaded through HostContext. The outer
profile includes the existing ET_DYN PIE/static-PIE slices and the separately
validated dynamic ET_EXEC slice. These profiles have different image lifetime
and launch semantics, so a profile-specific launcher or adapter is explicitly
selected and validated rather than inferred from loader behavior.
The current Payload Frame and CLI/API contract is breaking and
single-version: retired frame/API/CLI paths are deleted rather than retained as
selectable or evidence-producing compatibility routes. A stale version or
profile/launcher mismatch must produce a clear version or unsupported result.

Compatibility work is layered and must be reported at the layer actually
proved:

1. parser/model acceptance;
2. outer wrapper and native interpreter execution;
3. in-process HostContext loading and entry dispatch;
4. runtime-specific evidence such as glibc, musl, or bionic.

Success at a lower layer does not promote a claim at a higher layer. In
particular, a system loader accepting an ELF feature is not HostContext support
until the HostContext contract defines its semantics and a corresponding
oracle is retained.

The compatibility expansion order is recorded in the active parent task rather
than duplicated here: converge the current contract and explicit profiles
first, then expand the outer AArch64 wrapper, relocation/symbol semantics,
dependency/path/lifecycle semantics, and finally TLS/GNU property semantics.
The parent task owns the phase details and child-task acceptance criteria; this
spec owns the durable rules that every phase must follow.

### 2. Signatures

The native runtime entry point is:

```c
urp_status urp_runtime_execute_frame(
    const urp_host_context_v1 *host,
    const uint8_t *frame,
    size_t frame_size,
    const urp_launch_args_v1 *args);
```

The payload entry point is:

```c
int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args);
```

`urp_host_context_v1` is the current ABI version `1`, requires a declared size
of at least `56` bytes, and requires `load_image`, `lookup_symbol`, and
`release_image` capabilities. `urp_launch_args_v1` is the current ABI version
`1` with a minimum declared size of `32` bytes. The current payload frame is v3
with an explicit profile and a 144-byte header containing the HostContext ABI,
required capability bits, bounded UTF-8 entry metadata, and profile fields.
Both profiles use a frame-relative encoded offset.

The managed/native standalone handoff uses this sequence:

```text
memfd_create(name, MFD_CLOEXEC)
-> write and flush verified source bytes
-> fchmod(fd, 0700)
-> execveat(fd, "", argv, envp, AT_EMPTY_PATH)
```

The HostContext system-loader adapter uses a separate sealed-image sequence:

```text
memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING)
-> write verified source bytes and rewind
-> fchmod(fd, 0700)
-> F_ADD_SEALS(F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)
-> F_GET_SEALS and require every seal
-> dlopen(/proc/self/fd/<fd>, RTLD_NOW | RTLD_LOCAL)
```

A failed or incomplete seal operation closes the descriptor and fails before
loader handoff; the virtual proc reference is not a payload-controlled
executable pathname.

### 3. Contracts

#### Outer-execveat

- The validated dynamic `ET_EXEC` slice is recorded as
  `elf.outer.dynamic-et-exec`. Its exact pack predicate is ELF64,
  little-endian AArch64 `ET_EXEC`, an entry point within an executable
  `PT_LOAD`, a bounded `PT_DYNAMIC`, one terminated absolute `PT_INTERP` whose
  path ends in a recognized AArch64 glibc or musl loader name, or is the
  exact bionic loader path `/system/bin/linker64`, and no `DT_RPATH` or
  `DT_RUNPATH`.
- `ElfParser`/`ElfValidator` may classify ET_EXEC images for observation, but
  that layer is recorded separately as `elf.identity.aarch64-et-exec`;
  parser success does not establish packability or launchability. The
  `ElfPackService` owns the profile decision, which is separately recorded as
  `elf.outer.dynamic-et-exec`. Dynamic ET_EXEC is supported only by
  `outer-execveat`; shared objects, static ET_EXEC, and missing or unrecognized
  interpreters remain rejected. HostContext continues to require a declared
  ET_DYN shared-object entry image.
- The launcher validates that recovered ET_EXEC images have both `PT_DYNAMIC`
  and a supported `PT_INTERP`, then preserves the existing anonymous memfd
  plus `execveat(AT_EMPTY_PATH)` handoff. No frame ABI field or HostContext
  semantic changes follow from this slice.
- The retained native glibc fixture compares baseline and wrapped status,
  stdout/stderr, arguments and source-name `argv[0]`, environment, cwd, an
  inherited descriptor, a declared file, and signal termination. The current
  validated runtime cell is native AArch64 glibc; recognizing a musl or bionic
  interpreter path is not a musl or bionic runtime claim without its own native
  oracle and retained evidence.

#### HostContext

- `load_image` consumes verified bytes before returning and returns an opaque
  image handle whose lifetime ends at `release_image`.
- The runtime requests `URP_LOAD_IMAGE_IMMUTABLE`; the host must not mutate
  the supplied image bytes after the load operation accepts them. The native
  adapter enforces this with a sealing-enabled memfd: it adds and verifies
  `F_SEAL_WRITE`, `F_SEAL_SHRINK`, `F_SEAL_GROW`, and `F_SEAL_SEAL` after the
  complete write and before `dlopen`, and fails closed when sealing is absent.
- The native self-test exposes a test-visible live-handle seal invariant; a
  positive HostContext dispatch is not evidence of immutability unless that
  invariant passes.
- `lookup_symbol` resolves the exact declared entry symbol for the loaded
  image; the current outer profile uses `urp_entry` and the current
  HostContext profile carries a bounded symbol name explicitly.
- `urp_entry` is called at most once per successful frame execution.
- The runtime releases the image after entry dispatch, including a nonzero
  entry status. Host callbacks must not be invoked after release returns.
- The optional thread-lifetime capability appends `create_image_thread` and
  `join_image_thread` at offsets 56 and 64 (72-byte current table); the 56-byte
  minimum remains valid. The capability requires both appended fields and
  callbacks. Launch args retain their 32-byte minimum and append the opaque
  image handle at offset 32 (40-byte current view). Runtime passes the current
  HostContext table directly and supplies the active image handle to entry.
- A frame requiring thread lifetime is preflighted against the capability,
  table size, and callbacks before image loading. Registered workers may be
  created only by the dispatch thread through HostContext. Release closes the
  spawn gate, joins registered workers and their TLS teardown, then invokes
  loader destructors and closes image resources. Dynamic TLS, unmanaged
  workers, and worker-triggered recursive dispatch remain out of scope;
  same-thread recursive frame dispatch is rejected before nested loading.
- Unknown ABI versions, truncated tables, missing mandatory capabilities, and
  null mandatory callbacks fail closed before payload dispatch.

#### Frame and ELF

- Frame version, architecture, `ET_DYN` identity, bounds, encoded digest,
  exact decompression size, and source digest are checked before loading.
- AArch64 program headers and `LoadMap` define runtime layout; section headers
  may be absent. Unknown relocation or lifecycle semantics remain `unknown` or
  `rejected` until an invariant and oracle exist. The first native adapter
  slice accepts checked `RELATIVE`/`RELR` targets and the bounded
  `R_AARCH64_GLOB_DAT` symbolic form when `DT_SYMTAB`/`DT_SYMENT` identify a
  file-backed symbol record and the relocation target is aligned and writable.
  It also accepts only the exact `runtime.host-context.weak-undefined-jump-slot`
  subset: one complete, non-duplicated `DT_JMPREL`/`DT_PLTRELSZ`/
  `DT_PLTREL=DT_RELA` tuple with exact RELA and dynsym entry sizes; every entry
  is `R_AARCH64_JUMP_SLOT` with nonzero index, aligned writable in-image
  target, and a bounded file-backed `STB_WEAK`, `STT_FUNC`, exact
  `st_other == STV_DEFAULT`, `SHN_UNDEF` symbol. The slice requires
  `DF_BIND_NOW` or `DF_1_NOW`, has no
  `DT_NEEDED`, symbol-version tags, `DT_SYMBOLIC`, or non-preemptive local
  flags, and stays separate from dependency-backed GLOB_DAT behavior. Lookup
  uses the native loader's current global scope followed by this image's
  declared dependencies (none here); unresolved weak functions resolve to
  zero. The adapter opens with `RTLD_NOW` and delegates relocation application
  to the system loader. A JUMP_SLOT in ordinary `DT_RELA` is rejected; it is
  accepted only in the validated PLT tuple. Other PLT/symbol combinations
  remain rejected before handoff. The managed entry oracle returns status 53
  on native AArch64 glibc only.
- The existing HostContext singleton dependency slice remains one recognized
  system-libc `DT_NEEDED` basename with bounded `DT_STRTAB`/`DT_STRSZ` metadata.
  A separate validated row, `runtime.host-context.bounded-glibc-loader-dependency`,
  accepts only the duplicate-free direct pair `{libc.so.6,
  ld-linux-aarch64.so.1}` in either order and no third name. This closed graph is
  validated on native AArch64 glibc only. The host process loader namespace
  shares its already-loaded libc and loader objects; HostContext owns only the
  sealed memfd-backed entry root and releases it through `release_image`.
  Unknown/missing names, duplicates, excess nodes, and malformed pair metadata
  fail pre-handoff. No recursion, cycle, arbitrary graph, configurable root, or
  payload-controlled path policy is introduced. `LD_LIBRARY_PATH`,
  `LD_PRELOAD`, and `LD_AUDIT` must be unset or empty for the pair; the adapter
  checks them after metadata preflight and before memfd creation. The historical
  singleton path is unchanged by this pair-specific gate. `DT_RPATH`,
  `DT_RUNPATH`, `$ORIGIN`, `DT_AUXILIARY`, and `DT_FILTER` remain rejected.
  Nonzero constructor/destructor metadata follows system-loader order:
  constructors before `urp_entry`, destructors during `release_image`.
  Zero-valued lifecycle mutations remain rejected, and reentrancy/live-thread
  teardown is not claimed. Native tests exercise both dependency orders,
  require unchanged memfd-create counts for all three environment rejections,
  observe root-image destructor completion, and verify the historical singleton
  still loads under a nonempty `LD_LIBRARY_PATH`. A controlled fake loader with
  the matching SONAME is separately loaded by a probe to verify its marker;
  when placed under `LD_LIBRARY_PATH`, the pair fixture returns unsupported
  before memfd creation and neither the fake-loader nor entry marker appears.
  A second pair fixture with an unresolved strong `R_AARCH64_GLOB_DAT` import
  passes metadata preflight and fails at `RTLD_NOW`; the native oracle requires
  `URP_STATUS_LOAD_FAILED`, a cleared image handle, one memfd attempt, and no
  net descriptor increase after rollback.
  The pair claim does not extend to musl or bionic.
- `runtime.host-context.external-table-provider` remains **unknown and
  non-promoted**, not a validated transformed-runtime row. Managed Slice B is
  accepted for one explicitly host-pinned consumer with typed GLOB_DAT/GOT
  ownership, source-derived fixup validation, and complete final-emission
  checking. A scoped native AArch64/glibc source-versus-rehydrated-Native-Image
  observation now also exists: it checks selected `urp_entry`, unselected
  `urp_observer`, all four provider targets and the safe default, mappings,
  bytes, statuses, streams, release, and rollback. The retained report still
  says `scoped-observation-not-promoted`; only local retained-root checks have
  been performed and no official hosted CI run has confirmed the new workflow.
  Keep the fixture/evaluator row `unknown` until the required CI gate passes.
  See [managed admission and scoped native evidence](#scenario-external-provider-managed-admission-and-scoped-native-evidence),
  [external consumer publication](./external-consumer-proof.md), and the
  [current gap audit](../../tasks/10-06-indirect-control-jump-tables/research/current-gap-audit.md).
  This does not widen the libc singleton/pair, arbitrary dependency-graph, or
  general indirect-control rules. The earlier native source-loader self-tests
  remain source/loader-only; the new provider-loaded rollback oracle is a
  separate source-loader observation and must not be called transformed
  execution. The host supplies a provider path and pins its exact `DT_SONAME`,
  GNU build ID, and SHA-256 outside the image. The adapter snapshots a bounded
  no-follow regular file, compares SHA-256 before ELF parsing, and accepts only
  the dependency-free provider DSO with a 16-byte defined table object in a
  file-backed read-only `PT_LOAD` and bounded executable targets.
  The consumer may declare exactly that one configured provider SONAME; missing,
  extra, duplicate, or mismatched provider dependencies and the provider table
  import without its exact `DT_NEEDED` fail before memfd creation or loader
  activity. The consumer's undefined global/default `STT_OBJECT` may have
  `st_size == 0` (as GNU ld emits); its size/range is established by the pinned
  provider definition and checked runtime binding, not by the undefined row.
  Provider RPATH/RUNPATH and dependencies are rejected; `LD_LIBRARY_PATH`,
  `LD_PRELOAD`, and `LD_AUDIT` must be unset or empty. No payload path, search
  root, or environment variable selects the provider. After `DT_NEEDED` parsing
  identifies the configured provider dependency, any consumer `DT_VERSYM`,
  `DT_VERNEED`, `DT_VERNEEDNUM`, `DT_VERDEF`, or `DT_VERDEFNUM` tag is rejected
  with `URP_STATUS_UNSUPPORTED` before generic symbol-version traversal or
  provider-specific RELA accounting. The RELA-side version-tag check remains as
  defense-in-depth. This provider-only ordering does not change the accepted
  non-provider libc version-requirement path.

  The glibc adapter hashes before parsing, loads the sealed provider descriptor
  with `dlmopen(LM_ID_NEWLM, ..., RTLD_NOW | RTLD_LOCAL)`, then loads the
  consumer into that exact `Lmid_t` with local visibility. It verifies the
  actual provider link map, read-only table mapping/bytes, and consumer GOT
  pointer against that provider before publishing the consumer handle, and
  retains the provider until all consumer images are released. A pre-existing
  same-SONAME base-namespace mapping is rejected by policy; unrelated
  different-SONAME global definitions do not affect isolated binding. The
  configured-provider consumer candidate preflight has one aggregate 8 MiB
  work budget initialized before its program-header walk or dynamic-tag scan.
  It charges program-header scans and PT_LOAD range lookups, the bounded
  dynamic-entry scan, each byte examined in a `DT_NEEDED` name, version records,
  version-name scans/hash work, RELA/PLT/RELR entries and target queries,
  GNU-hash buckets/chains, dynsym scans, and provider-specific consumer checks.
  The same work object continues through consumer RELA validation; entering the
  RELA path does not reset it. Candidate `DT_NEEDED` scanning stops after the
  longest accepted configured-provider, libc, or loader SONAME plus its
  terminator; longer and unrecognized names are rejected before version,
  relocation, provider-parser, memfd, or loader work. This budget applies in
  configured mode even when classification ends at an otherwise valid generic
  libc image, so the libc symbol-version positive must continue to pass. With
  no configured provider, the established generic non-provider preflight path
  is unchanged. The pinned provider DSO parser retains its own independent
  aggregate 8 MiB budget for its program-header/indexed-range, GNU-hash,
  dynsym, and string work. Exact-limit and one-under consumer-candidate tests
  include dynamic entries, range lookups, and NEEDED bytes; the one-under case
  must fail before provider parsing, memfd creation, or loader attempts. A long
  adversarial NEEDED-name regression checks bounded rejection, and provider
  version-tag negatives remain before generic symbol-version traversal.

  On native AArch64/glibc, verify this boundary with a focused clean provider
  self-test and the complete isolated runtime suite (use distinct `/tmp` build
  directories for each run):
  `make -C native/urprotect-runtime BUILD_DIR=/tmp/urp-provider-preflight-focused-<unique> clean external-provider-self-test`
  `make -C native/urprotect-runtime BUILD_DIR=/tmp/urp-provider-preflight-full-<unique> clean test`
  `git diff --check`
  The native self-test also checks missing-`DT_NEEDED` rejection with configured
  and unconfigured adapters and unchanged memfd/loader-attempt counters. This is
  native source/loader evidence only, not managed transformation or rehydration
  evidence, and does not establish musl or bionic support.
- The same `libc.so.6` dependency slice accepts only import-side GNU
  version requirements recorded as
  `runtime.host-context.dependency-symbol-version-requirements`: `DT_GNU_HASH`
  is required, SysV `DT_HASH` and `DT_SYMBOLIC` are rejected, and `DT_VERSYM`,
  `DT_VERNEED`, and `DT_VERNEEDNUM` must be complete; bounded `Verneed` and
  `Vernaux` chains must terminate at their declared counts, all version names
  and hashes/indices must be valid, and every `vn_file` must exactly match a
  declared `DT_NEEDED` basename. The only declared names are the existing
  `libc.so.6` singleton or the already-validated exact pair `libc.so.6` plus
  `ld-linux-aarch64.so.1`; no other dependency is admitted by this version-file
  rule. Weak-version requirement flags and version requirements attached to
  recognized musl/bionic sonames are rejected. Native
  preflight caps hash symbol counts, `Verneed` records, and aggregate auxiliary
  records at 1,048,576. The native loader resolves the imported libc versions at
  `RTLD_NOW`; the retained runtime cell is native AArch64 glibc and unavailable
  required versions fail with `LOAD_FAILED`. `DT_VERDEF`/`DT_VERDEFNUM` and
  versioned HostContext entry selection remain rejected; the declared entry is
  looked up by its unversioned name. This does not add dependency graph or
  search-path forms.
- The constructor/destructor lifecycle slice is recorded as
  `runtime.host-context.constructor-destructor`. Nonzero `DT_INIT`, `DT_FINI`,
  `DT_INIT_ARRAY`, `DT_FINI_ARRAY`, `DT_INIT_ARRAYSZ`, `DT_FINI_ARRAYSZ`,
  `DT_PREINIT_ARRAY`, and `DT_PREINIT_ARRAYSZ` follow the system-loader order:
  constructors before `urp_entry` and destructors during `release_image`. The
  dependency fixture observes both sides. Zero-valued lifecycle mutations are
  still rejected before image creation; callback/reentrancy behavior,
  live-thread teardown, and broader lifecycle ownership remain outside the
  validated slice.
- RPATH/RUNPATH are the separate rejected feature row
  `runtime.host-context.path-search`. HostContext v1 and the current
  system-loader adapter define no dynamic path-search roots, ordering, or
  precedence semantics, so each bounded tag mutation fails closed before
  loader handoff. Unsupported relocation-table tags use the separate
  `runtime.host-context.unsupported-relocation-table` rejection boundary and
  are not included in this row.
- `DT_TEXTREL` writable-text relocation metadata is the separate rejected
  feature row `runtime.host-context.text-relocation`. HostContext v1 and the
  current system-loader adapter define no writable-text relocation or
  W^X/protection semantics for in-process images, so loader acceptance alone
  does not establish support. The native self-test mutates one bounded
  `DT_NULL` tag to `DT_TEXTREL`, preserves surrounding bytes, initializes a
  nonzero output-handle sentinel, and requires `URP_STATUS_UNSUPPORTED` with a
  zero handle before loader handoff. The unchanged non-text-relocation entry
  fixture remains the positive HostContext baseline. Unsupported relocation-
  table tags use the separate `runtime.host-context.unsupported-relocation-table`
  rejection boundary; checked AArch64 `RELATIVE`/`RELR` acceptance and
  system-loader application remain the validated `elf.relocation.aarch64-relative`
  feature.
- Unsupported dynamic relocation-table metadata remains independently
  rejected under `runtime.host-context.unsupported-relocation-table`: legacy
  `DT_REL`, `DT_RELSZ`, and `DT_RELENT` are rejected, as are partial, duplicate,
  inconsistent, malformed, versioned, dependency-bearing, or out-of-subset PLT
  RELA tables. The exact weak-undefined JUMP_SLOT subset has its own validated
  feature row. Its native negative oracle requires rejection and a zero image
  handle before loader handoff. The unchanged RELATIVE/RELR and GLOB_DAT
  status-29 fixtures remain positive baselines.
- Android packed relocation encodings are separately rejected as
  `runtime.host-context.android-packed-relocation`. The adapter rejects
  `DT_ANDROID_REL`, `DT_ANDROID_RELSZ`, `DT_ANDROID_RELA`,
  `DT_ANDROID_RELASZ`, `DT_ANDROID_RELR`, `DT_ANDROID_RELRSZ`,
  `DT_ANDROID_RELRENT`, and `DT_ANDROID_RELRCOUNT` before loader handoff,
  because HostContext v1 defines only the checked AArch64 `RELATIVE`/`RELR`
  path. `runtime.host-context.symbol-version` remains the rejected boundary
  for `DT_VERDEF`/`DT_VERDEFNUM`, versioned entry exports, and incomplete or
  out-of-scope import requirements. The no-dependency native self-test mutates
  individual version tags and requires a zero output handle; the separate
  libc import-requirement row covers only the complete bounded
  `DT_VERSYM`/`DT_VERNEED`/`DT_VERNEEDNUM` form whose version-need filenames
  match the declared `libc.so.6`. No versioned entry selection or Android
  packed relocation support is claimed.
- The managed parser has a separate observation-only row,
  `elf.symbol-version.definitions`, for bounded `DT_VERDEF`/`DT_VERDEFNUM`
  records and their dynamic-string-table auxiliaries. A linker-produced
  AArch64 fixture and nearest malformed mutations prove the model and stable
  diagnostics. The parser also has the observation-only
  `elf.symbol-version.requirements` row for bounded `DT_VERNEED` records and
  auxiliaries; neither parser row defines runtime resolution. The only
  HostContext import-resolution claim is the bounded single-libc row above.
- A validated adapter image may retain a non-empty `PT_GNU_RELRO` file range
  when that range is inside the image and `p_memsz >= p_filesz`; the real
  adapter must still dispatch the entry. The native system loader owns the
  resulting memory protection semantics, so this row is implementation
  evidence rather than proof of a custom RELRO loader.
- The first native adapter accepts `PT_GNU_STACK` only when `PF_X` is clear;
  an executable-stack request returns `URP_STATUS_UNSUPPORTED` before an
  image handle is created. Protection semantics for the accepted
  non-executable case remain delegated to the native system loader.
- `PT_TLS` has a bounded validated feature row (`runtime.host-context.pt-tls`).
  Native metadata preflight bounds AArch64 `R_AARCH64_TLS_TPREL64`,
  `R_AARCH64_TLS_DTPMOD64`, `R_AARCH64_TLS_DTPREL64`, and `R_AARCH64_TLSDESC`
  owners against the declared PT_TLS module. For ELF64 `ET_DYN`, `STT_TLS`
  `st_value` is a TLS-block-relative offset (not a virtual address); preflight
  validates the symbol extent and relocation addend before loader handoff. The
  system loader owns per-thread module allocation and initializes the
  `p_filesz` template plus zero-fill through `p_memsz`. Separate transformed
  HostContext current-thread rows for initial-exec, local-dynamic,
  general-dynamic, and TLSDESC return status 43 on native AArch64 glibc, each
  with its own linked fixture, stage/rehydration/handoff evidence, and
  baseline-vs-transformed behavior comparison. These rows do not promote
  registered-worker, outer-execveat, musl, or bionic behavior.
  Registered-worker initial-exec behavior is a separate
  `runtime.host-context.threaded-initial-exec-tls` row, limited to native
  AArch64 glibc. The optional `--thread-lifetime` pack flag sets the required
  frame capability; it is absent by default and forbidden for `outer-execveat`.
  The adapter advertises the capability only when compiled against glibc and
  `gnu_get_libc_version()` verifies the runtime. Creation/join/release are
  owner-thread-only; routines must resolve to the root `link_map`; thread
  handles are monotonic and non-reused. Release closes the spawn gate, joins
  registered workers and TLS teardown, then invokes image destructors and
  unloads. The retained linker fixture validates constructor/entry/worker/TLS
  destructor/image destructor ordering for explicit and automatic joins and
  exercises concurrent independent dispatches. Dynamic TLS worker lifecycle,
  unmanaged workers, recursive worker dispatch, and musl/bionic threaded claims
  remain outside scope; malformed TLS and
  unsupported models fail closed.
- `PT_GNU_PROPERTY` has a bounded validated feature row
  (`runtime.host-context.gnu-property`). The adapter accepts a GNU property
  note containing only AArch64 FEATURE_1 BTI/PAC bits and rejects malformed
  notes or unknown feature bits. A BTI-instrumented property fixture reaches
  the managed v3 entry oracle and returns status 47 on the native glibc lane;
  PAC negotiation beyond the note mask and host instruction-state conflicts
  remain outside the claim.
  `runtime.host-context.dependency-resolution` preserves the one recognized
  system-libc singleton. The separate
  `runtime.host-context.bounded-glibc-loader-dependency` row accepts only the
  exact libc.so.6 + ld-linux-aarch64.so.1 pair on native AArch64 glibc, with an
  empty/unset loader-influence environment and no payload path tags. RPATH,
  RUNPATH, `$ORIGIN`, auxiliary/filter dependencies, and arbitrary graphs remain
  rejected. Imported GNU symbol-version requirements for `libc.so.6` are
  separately recorded as `runtime.host-context.dependency-symbol-version-requirements`;
  versioned definitions and entry selection remain rejected.
- Each `PT_LOAD` with `p_align > 1` uses a power-of-two alignment and satisfies
  `p_offset % p_align == p_vaddr % p_align`; zero and one impose no stronger
  alignment requirement, and a non-page-sized power-of-two alignment is valid
  when the congruence holds.
- The matrix is sourced from `fixtures/manifest.json`, uses tiers (`pr`,
  `nightly`, `release`), and records `proven`, `validated`, `rejected`, or
  `unknown` for each feature. The release tier is a documented covering slice:
  it adds one existing `gcc-c` producer with a `release-hardened` variant and
  a readelf oracle for GNU RELRO and BIND_NOW rather than a blind Cartesian
  product.
- The current production managed pack path emits frame v3 with explicit
  `outer-execveat` and `host-context-entry` profiles. Profile-matched launcher
  markers are validated before frame encoding and unsupported frame versions or
  profile/launcher mismatches fail closed. `runtime.host-context.production-pack` is validated
  by the retained managed HostContext pack/dispatch oracle on the native
  AArch64 glibc lane.
- The bionic HostContext adapter rejects `DT_RELR` metadata before loader handoff because the Termux/bionic loader lane does not apply that relocation table; the retained result includes a `relrImageBoundary` loader-unsupported witness. The glibc adapter continues to exercise the positive RELR path independently.
- The Android `android.jni.native-bridge` row is an unwrapped JNI baseline and
  does not upgrade HostContext runtime support.

#### Environment keys

- `BIONIC_CONTAINER_RUNTIME` optionally selects the Docker-compatible runtime
  for the native ARM64 bionic evidence lane; it defaults to `docker`.
- `FIXTURE_ARTIFACT_ROOT` selects fixture evidence output for matrix runs.
- `MANAGED_HANDOFF_ARTIFACT_ROOT` selects managed handoff smoke artifacts.
- `NATIVE_LAUNCHER_CC` selects the native launcher compiler in tests.

The bionic lane must use the pinned Termux image and exact compiler/linker
facts from the manifest. The live package index may locate artifacts, but the
complete newly installed compiler dependency closure must be version- and
SHA-256-locked, with license identifiers and sources recorded in the lock.
Before installation, the lane verifies that the downloaded artifacts exactly
match the lock and hashes; it fails on missing, changed, or additional packages.
The image digest pins the base userspace. The lane retains the lock, hash
verification, apt logs, package policy, before/after package inventories, and
reports `packageIndex: live` with `packageInputsReproducible: true` to distinguish live
artifact discovery from pinned package inputs. It must record both host and
container kernel/page-size facts, require an AArch64 host and a Linux/arm64
Docker server and container, and reject active Android/AVD/Waydroid host
contexts or non-ARM execution rather than silently falling back. The pinned
container must execute `/system/bin/linker64` directly and retain that
identity witness; presence of an unused QEMU executable on the host is not
treated as emulated execution. The bionic lane now
builds and runs the native HostContext self-test: a current HostContext frame
exercises the real bionic adapter, verifies required memfd seals, dispatches
the entry, releases the image, and retains its log and fixture ELF. The retained
result also records the bionic loader-specific sectionless-image boundary and
the exact self-test marker, so removing that boundary witness fails evidence
validation. This makes only `runtime.host-context.bionic-handoff` validated
for that adapter slice.
The managed production-pack row has its separate native-glibc oracle; the
bionic adapter test does not silently change that runtime-specific claim.

### 4. CI Evidence Postconditions

`fixtures/manifest.json` evidence paths are declarations, not proof that a
local command ran. The producing CI job must run `scripts/check-evidence.py`
after its fixture, HostContext, handoff, bionic, or Android step completes.
The gate selects the exact case tier or execution fact (or an explicit feature)
and fails when any declared path is missing, empty, unreadable, outside the
repository, or an empty generated `.artifacts` location. Local runs may help
debug a failure, but only the retained post-run CI path satisfies the matrix
evidence contract. Validated loader features must include the producing CI
oracle's retained output, not only source files that describe the oracle.

### 5. Validation & Error Matrix

| Condition | Required result |
|---|---|
| Unsupported host ABI version or short table | `URP_STATUS_HOST_INVALID`; no callback beyond validation |
| Missing mandatory host capability/callback | `URP_STATUS_HOST_INVALID`; no entry call |
| Invalid launch args | `URP_STATUS_INVALID_ARGUMENT`; no image load |
| Invalid frame, bounds, metadata, or decompression | `URP_STATUS_FRAME_INVALID`; no image load |
| Unsupported frame version, HostContext ABI, or capability bits | `URP_STATUS_UNSUPPORTED`; no image load |
| Encoded or source digest mismatch | `URP_STATUS_INTEGRITY_FAILURE`; no image load |
| Host image load failure | propagate host status; no lookup or entry call |
| Missing declared entry symbol | `URP_STATUS_SYMBOL_NOT_FOUND`; release any loaded image |
| Entry returns a negative status | return it and emit a diagnostic when available |
| Entry returns a nonzero positive status | preserve and return it; do not treat it as a runtime failure |
| Bionic runtime/toolchain/architecture unavailable | fail the required lane; never substitute another runtime |
| Matrix row has no required witness/oracle/evidence | validator rejects the manifest |
| Selected CI evidence path is missing or empty | post-run evidence gate fails the producer job |

### 6. Good/Base/Bad Cases

- Good: a valid AArch64 `ET_DYN` frame reaches an immutable host image,
  resolves its declared entry symbol, invokes it once, releases the image,
  and preserves its status and declared output.
- Base: a standalone PIE passes parser and outer-profile checks but lacks the
  HostContext entry contract; report it as parser/outer evidence, not as an
  in-process runtime claim.
- Bad: a loader error, unknown relocation, missing bionic linker, or missing
  Docker capability is hidden by a compatibility/fallback branch or labeled as
  successful compatibility.

### 7. Tests Required

- `dotnet test UrProtect.sln --configuration Release --no-restore`: assert
  HostContext validation, parser preservation, stable diagnostics, and frame
  regressions.
- `make -C native/urprotect-runtime ... test`: assert ABI sizes, immutable
  load flags, exact symbol dispatch, release ordering, tamper rejection, and
  ABI/argument failure behavior.
- `native/urprotect-launcher/test_launcher.sh`: assert no executable
  temporary path, argument/environment/cwd preservation, status/signal
  behavior, and malformed/tampered frame rejection.
- `native/urprotect-launcher/test_managed_handoff.sh`: assert the managed
  self-contained host uses the same anonymous handoff and preserves the
  baseline shell result.
- `scripts/validate-fixtures.py fixtures/manifest.json --tier pr` and
  `scripts/validate-fixtures.py fixtures/manifest.json --tier release`: assert
  feature references, status/evidence completeness, pinned bionic facts, the
  release hardening covering case, and tier selection.
- `scripts/check-evidence.py fixtures/manifest.json --tier release`: run in the
  release fixture producer after the release case completes; it must check the
  retained release artifact path.
- `scripts/run-bionic-fixture.sh`: on a native ARM64 Docker host, assert image
  digest, AArch64 architecture, page size, `/system/bin/linker64`, exact
  `clang` package, ELF `ET_DYN`/`PT_INTERP`, direct linker identity, and no
  forbidden fallback.

### 8. Wrong vs Correct

#### Wrong

```text
if Android:
    use_android_specific_branch()
else:
    extract_to_temp_path_and_execve()
```

This creates product branches, makes Linux and Android separate semantics, and
turns a path-dependent smoke result into a compatibility claim.

#### Correct

```text
verify(frame, ELF invariants)
-> call one HostContext.load_image(bytes, immutable)
-> resolve exact declared entry symbol
-> invoke once
-> release image
-> record the feature row and evidence tier
```

Host-specific mechanics stay behind the contract, while unsupported loader
features remain explicit `unknown` or `rejected` rows.

### Public real-sample ecology evidence

The controlled feature matrix and the public real-sample corpus have separate
ownership. `fixtures/manifest.json` proves named invariants with repository
fixtures and explicit oracles; `fixtures/real-samples/manifest.json` records
what public AArch64 software actually produces and which observations are
applicable. The latter is metadata-only in the developer tree and is acquired
only by the native ARM64 GitHub Actions job.

The locked corpus contains exactly 100 distinct upstream identities. Every
pull request runs the full set, including provenance/hash verification, static
fingerprint, and UrProtect JSON validation. Nightly and release reuse the same
set and runner; they may repeat or retain more evidence but never replace PR
coverage with a subset. Runtime/build/libc variants do not add identities.

The reviewed increment contains 23 promoted Debian Bookworm AArch64 records,
37 additional Debian Bookworm AArch64 records, and 20 Alpine v3.22 AArch64
APK records. The resulting runtime mix is 78 glibc, 21 musl, and 1 bionic
identity. The Alpine APK records are distinct upstream projects, not package
or distribution variants of an existing identity; their archive and index
SHA-256 locks remain in the real-sample manifest and candidate ledger.
For the selected Alpine v3.22 format, APK archives are gzip-compressed tar
files with `.SIGN.*`, `.PKGINFO`, and payload members directly at archive root.
The CI extractor checks the locked package name, version, `aarch64` architecture,
origin, and license in `.PKGINFO` before resolving the declared executable.
The bounded source-of-truth limits live in `scripts/real_sample_schema.py` and
are consumed by both the validator and archive extractor.

The CI fingerprint is authoritative for observed facts. The registry locks and
compares only ELF64, little-endian, AArch64, `ET_DYN`, and the declared
interpreter invariants. Relocation/RELR/PLT details, symbol versions, TLS, GNU
properties, RELRO, GNU_STACK, stripped state, dependencies, file size, and
feature tags are emitted by the bounded CI `readelf` inspection and retained
as evidence rather than guessed support claims. Hash drift stops acquisition
before extraction or execution.

Layer policy uses the fixed result vocabulary
`validated`, `accepted-and-runs`, `expected-rejected`, `unexpected-rejection`,
`unexpected-acceptance`, `runtime-failure`, `environment-unavailable`, and
`not-applicable`. `validated` is reserved for static validation that did not
launch a sample process; `accepted-and-runs` requires an execution oracle.
Static evidence is required for all projects. An applicable
baseline/outer/HostContext oracle runs with network disabled, read-only inputs,
a bounded temporary filesystem, dropped capabilities, resource/time/output
limits, and cleanup. A normal ELF without the declared `urp_entry` ABI is
`not-applicable` to HostContext; loader acceptance is not HostContext proof.
The current BusyBox Alpine record is the explicit musl baseline: its policy
command must name the extracted `/bin/busybox` artifact and runs only inside
its archive-derived rootfs, never through a host fallback.

The full-corpus runner may use a bounded `REAL_SAMPLE_PARALLELISM` value (default
`4`, maximum `8`) because each project owns an independent extraction root and
evidence directory. Parallel execution must not share extracted roots or raw
inputs; only the content-addressed runtime package/index cache is shared.
Package cache entries are keyed by the locked digest and archive identity,
written through a temporary file plus atomic rename, and re-verified for the
locked digest and size on every reuse. A cache miss, stale entry, or cache
restore failure must fall back to verified acquisition without changing the
result classification.

The runner invokes the already-built `src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll`
for repeated validation and packing; it must not run project restore/build work
inside the per-sample loop. CI may restore/save only the package and verified
index cache under `RUNNER_TEMP`; extracted roots, source executables, wrappers,
package-manager state, and evidence remain temporary and are never cache or
evidence artifacts.

For future compatibility work, the plan must include a real-sample impact table
(project IDs, feature, layer, oracle, expected classification, and artifact
path). An unexpected result blocks completion. Support expansion additionally
requires real observation, controlled positive and nearest-negative fixtures,
stable diagnostics, and synchronized contract, documentation, and evidence
updates. Real-sample count is ecology evidence and cannot substitute for a
feature invariant or controlled negative boundary.
### Runtime environment covering array

`fixtures/runtime-matrix.json` owns stable cell IDs, OCI pins, tier selection,
and covering rationale. The evidence gate consumes the locked bionic producer;
containers inherit the runner kernel. A non-16KiB native probe remains
`environment-unavailable`/`unknown`; 16KiB `PT_LOAD.p_align` proves ELF shape,
not a 16KiB kernel. Musl 1.2.4 uses SHA-256-pinned source and records its native
compiler/runtime hashes and build logs; its temporary loader link is removed
after the oracle.

The executable entry point is `scripts/run-runtime-matrix.sh pr|nightly|release`;
the post-run gate is `scripts/check-runtime-matrix-evidence.py TIER
ARTIFACT_ROOT BIONIC_ARTIFACT_ROOT`. Native glibc and musl cells retain direct
status/streams, managed validate/no-op-copy status and streams, source/copy
hashes, the exact ELF report, toolchain identities, and the observed runner
kernel/page size. Container cells retain OCI inspection, direct loader output,
individual bounded command results, and the inherited kernel/page facts.

After native musl oracle execution, the test-owned `/lib/ld-musl-aarch64.so.1`
link is removed before evidence packaging. The post-run checker therefore
re-executes the exact musl binaries through the retained
`package-locks/musl-1.2.4/prefix/lib/libc.so`, not by relying on a host loader
link. Container loader selection must first check that the runtime-specific
interpreter is executable, then resolve it; `readlink -f` alone may print a
nonexistent final pathname and is not a presence check. The musl 1.2.5 cell
selects `/lib/ld-musl-aarch64.so.1`; glibc selects
`/lib/ld-linux-aarch64.so.1`.

The producing job hashes the complete runtime and consumed bionic trees before
the evidence gate runs. The upload step must set
`include-hidden-files: true` when the checksum manifest covers hidden source
build files, or post-download evidence will be incomplete even when the
pre-upload gate passed. A retained artifact audit verifies every SHA256SUMS
entry after download; the archive's file set must match the checksum manifest.

## Scenario: explicit function-protection request and runtime evidence

### 1. Scope / Trigger

This contract applies to the managed `protect` command, the merged ELF
function-symbol inventory, the AsmStone-backed AArch64 analysis/rewrite path,
the protection JSON report, and the three-runtime protection smoke. It does
not change the no-op validator or outer packer defaults: protection is never
implicit and never means “all functions”.

### 2. Signatures

```text
urprotect protect INPUT --output OUTPUT
  (--function NAME | --function-id symtab:INDEX|dynsym:INDEX
                    | --function-address 0xADDRESS)+
  (--pass control-flow-flattening | --pass register-permutation)+
  [--json PATH|-]
```

The core request is `FunctionProtectionOptions(Selectors, Passes)`. Selectors
resolve `STT_FUNC` records from both `.symtab` and `.dynsym`; a resolved record
retains its table kind, table index, address, size, and exact name. A valid
request with both passes is normalized to
`control-flow-flattening`, then `register-permutation`.

### 3. Contracts

- A name selector is exact and fails with `FunctionSelectorAmbiguous` when
  more than one valid symbol identity matches. Table/index or address criteria
  must be supplied explicitly to disambiguate; the resolver never picks a
  first match.
- The selected range must be non-empty, instruction-aligned, file-backed, and
  wholly contained in exactly one executable `PT_LOAD`. Unsupported decode,
  unresolved indirect control flow, unsupported PC-relative semantics, and
  reserved-register conflicts are explicit per-function outcomes.
- `AsmStoneAdapter` is the only third-party boundary. Every register-
  permutation instruction is AsmStone decoded, re-encoded, and decoded again
  before emission. Project-owned IR retains semantic operands, implicit
  effects, register views, memory addressing, flags, and control-flow targets.
- The resource plan reserves AArch64 x18 and pass scratch/state registers,
  records used/available registers and pressure, and fails before emission
  when the plan is insufficient. It never selects an arbitrary last-minute
  scratch register.
- The operation is transactional. Any selected-function failure, layout
  failure, structural reparse failure, post-write decode failure, or output IO
  failure publishes no protected output. The writer changes only selected
  function ranges and its reserved program-header slot; all other source bytes
  remain byte-identical.
- The report contains the original input hash, exact selector strings, pass
  order, each selected function identity/range, resource plan, diagnostics,
  transformed status, output hash, and publication status.
- The PR smoke executes standalone register permutation, standalone control-
  flow flattening (including an NZCV branch fixture), and the combined order
  in glibc, musl, and locked Termux/bionic cells. Baseline and protected
  status/stdout/stderr must match; raw fixture executables are removed before
  evidence validation.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| Missing selector or pass | usage/`InvalidArgument`; no output |
| Missing or ambiguous exact symbol | `FunctionNotFound`/`FunctionSelectorAmbiguous`; no output |
| Zero-sized, misaligned, overlapping, or out-of-range selected range | `FunctionResourceUnavailable`; no output |
| AsmStone decode/encode/round-trip failure | explicit analysis/protection diagnostic; no output |
| Reserved register or insufficient resource plan | `FunctionResourceUnavailable` with resource reason; no output |
| No legal executable placement | `ProtectionLayoutUnavailable`; no output |
| Output parse/decode or byte-invariant failure | `WrapperMalformed`; no output |
| Protected process status/streams differ from baseline | runtime E2E failure; evidence gate fails |
| Required glibc, musl, or bionic capability/evidence missing | environment/CI failure; never `not-applicable` |

### 5. Good/Base/Bad Cases

- Good: a unique symbol-bounded function is selected, each requested pass
  completes, the output reparses and re-decodes, and all three runtime smoke
  comparisons are equivalent.
- Base: a normal ELF with no explicit selector performs no transformation;
  a selected function whose layout has no legal placement returns an explicit
  failure and leaves no output file.
- Bad: treating `.symtab`/`.dynsym` name aliases as one implicit selection,
  rewriting an unselected range, or labeling a static parser result as
  `accepted-and-runs`.

### 6. Tests Required

- ELF parser tests assert `.symtab` and `.dynsym` `STT_FUNC` identities,
  non-empty ranges, and stable table/index metadata.
- Protection tests assert ambiguity, explicit identity resolution, pass
  ordering, resource diagnostics, atomic failure, selected/unselected byte
  invariants, output reparse, and post-write decode.
- Adapter tests assert semantic operand projection, SP/ZR roles, register
  permutation round-trip, and NZCV/control-flow classification.
- CLI tests assert selector/pass parsing, JSON selectors/resource plans,
  executable-mode preservation, and no output on failure.
- `run-protection-e2e.sh` plus `check-protection-evidence.py` assert baseline
  equivalence and normalized evidence in glibc, musl, and bionic CI cells.

### 7. Wrong vs Correct

#### Wrong

```text
for every function in the ELF:
    rewrite(function)
publish(output)
```

#### Correct

```text
resolve exact user selectors from .symtab/.dynsym
-> plan CFG, AsmStone semantics, and register resources
-> flatten (if requested), then permute (if requested)
-> write a temporary ELF and reparse/redecode it
-> publish only after all selected functions and runtime checks pass
```

## Scenario: canonical AArch64 semantic-plan handoff

### 1. Scope / Trigger

This contract applies when the AArch64 protection path needs to hand semantic
instruction, address-map, relocation, target-resolution, or post-encode
validation data from the project-owned decoder/rewrite layer to an ELF layout,
Protected Image, or workflow consumer. It is a planning/handoff contract, not
a physical ELF writer and not a replacement for the versioned Protected Image
artifact codec.

The semantic layer must remain independent of final file placement. A later
layout consumer supplies output addresses, veneers, and runtime bindings; it
must not reconstruct semantic meaning by re-reading raw bytes or by importing
AsmStone model types.

A selected dynamic-import `BLR` uses the current typed
`SemanticDynamicImportCall` extension kind. The extension binds one exact call
identity/address and target register, the full bounded producer-address chain
(including ADRP, pointer load, and every register-copy producer), the computed
ADRP page, exact writable file-backed 8-byte GOT source range, relocation-site
identity and complete non-PLT RELA tuple (`r_offset`, `r_info`, addend, PLT
identity, and RELA source-table address), plus the exact dynamic-symbol row
(index/name offset/name/info/bind/type/other/visibility/section/value/size) and
symbol-version index/DT_VERNEED facts when present. The chain is bounded to 64
producer instructions and rehydration never uses `Proof` prose as evidence.

### 2. Signatures

```text
Aarch64SemanticInstructionProjector.Project(
    Aarch64FunctionInstruction instruction,
    IEnumerable<RelaRelocation>? relocations = null)
    -> SemanticInstructionProjectionResult

Aarch64SemanticPlanFactory.Create(
    Aarch64FunctionAnalysis analysis,
    LoadMap? loadMap = null,
    IEnumerable<RelaRelocation>? relocations = null,
    AddressMap? placement = null,
    IEnumerable<ISemanticPlanExtension>? extensions = null)
    -> SemanticRewritePlanResult

SemanticPlanSnapshotCodec.Create(
    SemanticRewritePlan plan)
    -> SemanticPlanSnapshotResult

SemanticPlanSnapshotCodec.Decode(
    ReadOnlyMemory<byte> canonicalBytes)
    -> SemanticPlanSnapshotResult

Aarch64SemanticPlanValidator.Validate(
    SemanticRewritePlan plan,
    SemanticPlanResolutionResult resolutions,
    IAarch64Decoder decoder)
    -> SemanticPlanValidationResult
```

The current canonical handoff representation is version `6`, architecture
`EM_AARCH64` (`183`), magic `URP-SPS6`, and includes a trailing SHA-256 digest.
Versions `1` through `5` are rejected; the managed codec has one current schema
and no historical or dual decoder. Its digest is computed over the canonical
bytes owned by `SemanticPlanSnapshotCodec`. Protected Image producers may bind
this digest; they must not duplicate the semantic serializer. The outer
Protected Image ABI remains v1.

The byte-serialized `SemanticJumpTableOwnership` ordinals retain their
established values: `SelectedFunctionPrivate=0`, `Shared=1`, `External=2`, and
`RuntimeOwned=3`; `Ambiguous=4` remains appended. SPS6 carries the unchanged
external provider-table facts extension at discriminator **8** plus the appended
typed selected-consumer companion at **9**, without changing these ordinals or
the outer Protected Image ABI v1. Existing provider-only SPS6 bytes remain
identical; the companion is not an edit to that record's wire grammar.

The provider reader is a bounded facts reader, not a provider loader. After
rejecting raw input larger than 8 MiB and before hashing or parsing, it copies
the caller input once into a private snapshot. SHA-256 pin verification, the
existing bounded `ElfParser` profile, `BoundedReader`, table bytes, provider
identity, and file-size facts all use that same snapshot; no later byte
observation uses caller-owned memory. A wrong hash returns
`OutputIdentityMismatch` before ELF parsing. The profile requires exactly one
`PT_DYNAMIC` and no `PT_INTERP` before expanded metadata traversal. Ordinary
`ElfParser.Parse` behavior is unchanged; the provider-only strict program
header rule does not become a global parser rule.

The discriminator-8 extension still carries only provider-domain identity,
symbol/range/permission, signed-relative entry and retained table-byte facts.
Those facts alone authorize neither consumer publication nor runtime support.
Managed `protect-image` / `rehydrate-image` additionally require the linked
consumer companion, fresh host-pinned provider bytes, source-rederived exact
proof/instructions/fixups and complete logical/physical output validation;
ordinary unconfigured `protect`/analysis remains fail-closed. Provider paths and
operator pin configuration are not serialized; derived SONAME/build ID/content
hash are provider facts. The semantic reader is not a native loader, and a
managed Native Image is not a transformed-runtime acceptance witness.

Separately, layout-evidence schema v3 uses its own fixed JSON ownership mapping:
`Ambiguous=0`, `SelectedFunctionPrivate=1`, `Shared=2`, `External=3`, and
`RuntimeOwned=4`. This converter mapping is independent of the SPS6 semantic
snapshot enum ordinals above; changing either mapping does not change the other
or layout schema version. The independent shared-table evidence checker
requires ownership to be an exact JSON integer token, rejecting booleans,
floating-point values (including `2.0`), and strings even if numerically equal.

### 3. Contracts

- `SemanticInstruction` is project-owned and retains typed source
  `FileOffset`/`VirtualAddress` ranges, raw encoding, project-owned operands,
  register/flag effects, control-flow classification, PC-relative expression,
  literal reference, relocation bindings, and sibling extension records.
- `SemanticTarget` has exactly one explicit resolution mode: `Exact`,
  `BoundedSet`, `RuntimeResolved`, or `Unresolved`. A bounded set is never
  reduced to one target merely because one address currently maps; selection
  belongs to layout or runtime resolution.
- `AddressMap` is immutable after construction. It maps typed source/output
  ranges for functions, basic blocks, instructions, literals, veneers, tables,
  relocation targets, and relocation sites. Same-kind duplicate or overlapping
  source/output ranges fail closed; nested ranges resolve to the smallest unique
  typed entity where the API permits it.
- `Aarch64SemanticInstructionProjector` is the only decoder-to-IR projection
  owner. It supports the declared `B`, `BL`, conditional/test branch,
  `ADR`/`ADRP`, literal-load, and matching relocation families. `BLR`,
  authenticated indirect calls, and other opaque targets remain explicit
  indirect/runtime/unresolved states unless a separate typed owner proves the
  exact call; the narrow static local callback mode adds such an owner only for
  the bounded same-block ADRP/ADD/stack-spill/reload shape. The projector never
  guesses a destination.
- `RelocationBinding` preserves relocation kind, raw relocation type, raw
  `r_info`, addend, symbol index/name, PLT identity, relocation virtual
  address, and relocation-table address. A nonzero symbol index remains an
  external binding even when stale instruction bits contain a plausible target.
- `SemanticFixup` contains a symbolic target and optional PC-relative or
  relocation expression. The encoder may return `Resolved`, `Deferred`, or
  `Unresolved`; veneer/long-address, bounded-target, and runtime-target cases
  are deferred until their owning resolver supplies the missing decision.
- `SemanticPlanSnapshotCodec` deterministically orders nested entities,
  instructions, fixups, extensions, diagnostics, operands, references, target
  candidates, relocation metadata, and relaxation options. It applies bounded
  limits before allocation and validates strict UTF-8, enum values, identities,
  ranges, and digest before accepting decoded records.
- Current snapshot limits are: canonical bytes `16 MiB`, metadata `2 MiB`,
  strings `4096` UTF-8 bytes, address-map entries/instructions/fixups `131072`
  each, extensions `32768`, diagnostics `16384`, target candidates `4096`,
  operands per instruction `64`, register effects `256`, references `256`,
  relocations per instruction `64`, relaxation options `8`, jump-table targets
  `65536`, and CFI register effects `256`.
- The post-encode validator decodes each final instruction at its planned output
  address and checks instruction family, resolved output target, expression
  place, and low-12 relocation round trips. Relocation-only records are not
  passed to the instruction decoder and are validated by typed width/alignment/
  value-domain rules.
- Snapshot extensions are typed and reserved for sibling domains:
  indirect targets, typed static function-pointer call owners, typed
  dynamic-import call owners, TLS bindings, jump tables, and CFI effects. A
  static-call owner is distinct from `SemanticDynamicImportCall` and
  `RuntimeResolved`: it carries the exact selected caller identity, BLR target
  register, ordered ADRP/ADD/stack-store/stack-load producers, stack slot,
  section-linked RELA table and row identities, full non-preemptible local or
  hidden `STT_FUNC` symbol row, caller/target section facts, and an explicit
  preserve-at-original-VA mapping. It is admitted only when the source CFG has
  one bounded same-basic-block reaching chain, the exact ADRP/ADD relocation
  pair agrees with the symbol value, and the target is file-backed executable
  code in the same image. Local snapshot validation binds the owner to one
  exact indirect-target extension and identity mapping; it rejects missing,
  duplicate, inconsistent, or unsupported owner links.
- Every dynamic-import call owner pairs uniquely with the existing runtime
  indirect-target extension and exactly equal relocation binding; its
  source/output address-map entries must cover the call, each producer, the
  relocation site, and the GOT range. Local snapshot validation rejects
  missing, duplicate, inconsistent, or unsupported owner links.
- Before the non-TLS early return, rehydration independently checks each typed
  import against parsed `RelaRelocations`, the exact `DynamicSymbols` row and
  available symbol-version records, a unique writable file-backed `PT_LOAD`
  GOT owner, the semantic call/producer instructions and source bytes, and the
  decoded canonical source/output `AddressMap`. `ElfParser.ParseRelaRelocations`
  owns only bounded dynamic `DT_RELA`/`DT_JMPREL` records and preserves exact
  source VA plus `IsPlt`; the owner check binds a unique non-PLT row by that
  source address, tuple, and `!IsPlt` without creating a second ELF table
  parser. `DynamicSymbols`/`DynamicMetadata.StringTable` are sourced from
  `DT_SYMTAB`/`DT_STRTAB`, not section symbol tables. Missing or changed links
  fail before Native Image publication.
- Every BLR in a selected Protected Image emit region must retain its exact
  semantic instruction/address-map row and exactly one indirect-target
  extension plus one complete owner class: typed static function-pointer,
  typed dynamic GLOB_DAT import, or an explicitly recognized HostContext
  runtime callback. Publication independently reanalyzes each carried static
  caller against source instruction bytes and section-linked RELA/symtab facts,
  then checks that output call/producers map inside one emitted function and
  re-decodes the final rehydrated ADRP page plus low-12 ADD, same stack slot,
  and returning BLR to the original callback VA. It also compares callback
  bytes and symbol identity at that VA in the final image. It independently
  derives the expected imported-call owner set from selected source instruction bytes and parsed non-PLT
  `R_AARCH64_GLOB_DAT` GOT slots using bounded ADRP/LDR/register-provenance
  scans; it compares `(BLR address, GOT relocation offset)` pairs with typed
  snapshot owners. It must not use a snapshot-supplied runtime-binding string
  as the classifier for whether a source call is an import. Removing a typed
  owner while retaining or substituting a non-import-looking runtime binding
  therefore fails closed. Any selected emit region requires exactly one
  semantic-plan snapshot; the non-TLS no-snapshot fallback is removed.
- A typed import's producer chain must be ordered before BLR. Publication
  validation requires ADRP through BLR to fit one canonical basic block and
  independently decodes every contiguous source instruction in that interval.
  It tracks reaching page/pointer register definitions and fails on an omitted
  producer, unresolved clobber, non-call control-flow edge while page/GOT
  provenance is live (including during owner-set derivation when an owner is
  absent), or alternate path. It bounds each scan to 256 instructions,
  aggregate scans to 16,384 instructions, owners to 256, and producer-address
  work to 4,096.
- The dynamic-import, static function-pointer, provider-facts and linked external
  consumer extensions use the current `URP-SPS6` canonical codec, schema version
  6. Versions 1 through 5 are unsupported rather than dual-decoded; unknown
  extension kinds continue to fail closed. There is no second codec or
  historical dual track, and Protected Image ABI v1 is unchanged. Provider facts
  alone do not imply consumer binding or executable publication; the managed
  pinned path requires the companion and [source/final validation](./external-consumer-proof.md).
  This does not imply native/runtime acceptance. Python evidence consumers
  intentionally treat embedded snapshots as opaque bounded
  bytes plus SHA-256; they validate the outer Protected Image ABI v1 but do not
  parse the nested semantic-snapshot version.
- A semantic plan with an error diagnostic, unresolved required fixup, invalid
  source/output map, duplicate identity, malformed extension, or failed
  post-encode validation cannot proceed to physical layout or publication.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| Invalid/empty entity identity or duplicate candidate | `SemanticPlanMalformed`/`SemanticTargetUnresolved`; no handoff |
| Duplicate or overlapping same-kind address-map range | `SemanticAddressMapDuplicate`; no handoff |
| Source/output range overflow or typed-domain mismatch | `SemanticAddressMapOverflow`/`SemanticAddressMapMalformed`; no handoff |
| Decoder backend failure or malformed source range | stable semantic instruction diagnostic; no fixup emission |
| Unsupported PC-relative family without opaque-preservation contract | `SemanticFixupUnsupported`; no final encoding |
| Bounded, runtime-resolved, veneer, or long-address target | `SemanticFixupDeferred`; layout/runtime resolver must continue |
| Unresolved target or missing target binding | `SemanticTargetUnresolved`; no publication |
| Relocation raw metadata, width, alignment, or value mismatch | `SemanticFixupMalformed`/`SemanticFixupOutOfRange`; no ELF write |
| Snapshot exceeds any count/byte/string limit | `SemanticPlanSnapshotLimitExceeded`; no decode/handoff |
| Raw provider input exceeds 8 MiB | `SemanticPlanSnapshotLimitExceeded` before snapshot copy, memory access, or ELF parsing |
| Provider SHA-256 pin differs from the private input snapshot | `OutputIdentityMismatch` before ELF parsing; no extension |
| Provider input has malformed structure or a mismatched pinned SONAME/build ID | bounded parser or `OutputIdentityMismatch` diagnostic; no extension |
| Provider candidate has zero/multiple valid table facts or invalid ranges/targets | stable provider/symbol/range diagnostic; no extension |
| Snapshot magic/version/architecture/enum/UTF-8 invalid | `SemanticPlanSnapshotMalformed` or `SemanticPlanSnapshotUnsupported` |
| Snapshot trailing digest mismatch | `SemanticPlanSnapshotIntegrityMismatch`; no semantic records accepted |
| Final instruction re-decode or target mismatch | `SemanticFixupValidationFailed`; no publication |
| Missing/duplicate dynamic-import call, producer, GOT, RELA, dynsym/version, or address-map owner | `SemanticDynamicImportOwnerMismatch`; no Native Image |

### 5. Good/Base/Bad Cases

The provider-reader regression set in
`SemanticExternalJumpTableProviderReaderTests` verifies the maximum-plus-one
raw-size gate without touching caller bytes, a wrong hash before parsing, the
one-snapshot mutation case with exact pinned hash/table/target facts, provider-
profile rejection of missing `PT_DYNAMIC`, and unchanged ordinary-parser
behavior for zero `PT_DYNAMIC`. These reader-only checks establish bounded
provider facts. Separate accepted managed consumer/publication tests cover the
pinned integration; neither suite establishes transformed native/runtime
execution.

- Good: a projected function has deterministic typed ranges, exact internal
  targets, preserved relocation metadata, a canonical snapshot digest, and a
  layout consumer can resolve every required fixup before final validation.
  A provider-facts-only SPS6 extension is good only when one immutable bounded
  input snapshot matches its SHA-256/SONAME/build-ID pins and all retained table
  bytes and provider-local symbol/range facts derive from that same snapshot;
  this does not establish consumer or runtime support.
- Base: a plan contains a bounded jump-table target set, runtime PLT binding, or
  veneer-required branch; the snapshot preserves the state as deferred with
  its extension identity and does not claim a final encoding.
- Bad: parse caller-owned provider bytes after hashing a separate observation,
  exceed the provider input bound, or treat provider facts as proof of a
  consumer `GLOB_DAT`/GOT binding or runtime admission; any such input fails
  before extension publication. Also, copy a raw instruction to a new address,
  infer a target from stale
  immediate bits despite a symbolic relocation, collapse an ambiguous target
  set, accept a malformed snapshot after digest failure, or let a layout
  consumer import AsmStone types and recreate classification independently.

### 6. Tests Required

- Projector tests assert typed source ranges, operand/register/flag projection,
  direct-call versus indirect-call classification, PC-relative family mapping,
  literal references, and relocation raw-field preservation.
- Address-map tests assert exact/smallest-range resolution, duplicate/overlap
  rejection, source/output overflow, typed identity validation, and defensive
  collection copies.
- Encoder/validator tests assert direct instruction round trips, stale-target
  rejection, deferred bounded/runtime/veneer states, relocation-only validation,
  low-12 alignment, and unsupported-family diagnostics.
- Snapshot tests assert deterministic bytes for differently ordered equivalent
  inputs, canonical digest verification, mutation rejection, strict bounds,
  extension identity, unresolved/deferred classification, nested relocation
  ordering, and defensive copies.
- Integration tests assert `Aarch64SemanticPlanFactory` rejects incomplete
  analysis, validates `LoadMap` agreement, maps functions/blocks/instructions/
  relocation sites, and passes one canonical plan to the future layout consumer.
- A project-built GLOB_DAT indirect-call fixture must pass producer, canonical
  snapshot, Protected Image, and rehydration. Checksum-refreshed call/GOT/RELA/
  dynsym/address-map/ADRP-target/producer-order tampering, omission of the
  intervening clobber instruction or all owner edges, replacing the import
  owner and relocation with a forged non-import runtime target, and snapshot
  removal must fail before Native Image publication. A multi-owner payload over
  the aggregate validation-work bound must be rejected before per-owner scans.
- One bounded native observation is retained under
  `.artifacts/dynamic-import/recovery-glibc-20261018d/runtime.host-context.dynamic-import.glibc.host-context-entry`:
  on AArch64 glibc 2.43, a project-built `urp_entry` calls `getpid` via its
  non-PLT `R_AARCH64_GLOB_DAT` GOT slot, returns 97 only when that call yields a
  positive PID (otherwise 96), and produces matching source/transformed
  HostContext handoffs with entry/process status 97, successful release, and
  byte-identical empty stdout/stderr. The evidence checker independently binds
  the source and Native Image ELF symbol/RELA/GOT facts and validates producer,
  successful GenericRehydrationEngine publication, retained streams/handoffs,
  and an actual checksum-corrupted Protected Image failure before Native Image
  or loader publication. `DynamicImportOwnerWorkflowTests` separately validates
  the typed snapshot owner relation and refreshed-checksum semantic tampering.
  The report is explicitly `scoped-observation-pending-independent-review`;
  this row is not promotion of generic indirect calls, arbitrary function
  pointers, other imports, TLS/CFI/jump tables, or musl/bionic behavior. Its
  runtime identity gate is producer-runtime-only: the dynamic-import checker
  must run on the native AArch64 producer runtime and call
  `tls_runtime_identity.verify_identity(..., verify_current_process=True)` to
  validate the retained libc/loader files and current mapped runtime. The
  portable `verify_artifact_identity` check alone is insufficient for this row;
  this does not change the TLS-matrix portable identity contract.
- The current managed quality gate remains `dotnet build UrProtect.sln
  --configuration Release --no-restore` plus the full Core test project,
  fixture validation, regression matrix, and `git diff --check`. Runtime
  feature promotion additionally requires separate glibc, musl, and bionic
  evidence owned by the parent workflow.

### 7. Wrong vs Correct

#### Wrong

```text
copy raw instruction bytes to the new address
-> infer a branch target from the copied immediate
-> serialize a second ad-hoc JSON/ABI record
-> let the loader/layout writer guess unresolved targets
```

#### Correct

```text
AsmStone -> project-owned semantic instruction
       -> typed AddressMap + symbolic SemanticFixup
       -> canonical SemanticPlanSnapshotCodec digest
       -> layout/runtime resolver handles deferred states
       -> post-encode decoder/target validation
       -> Protected Image/workflow binds the snapshot digest
```

The semantic layer owns meaning and canonical handoff bytes; the layout layer
owns physical placement; the runtime/evidence layer owns loader-specific
behavior. No layer silently reimplements another layer's contract.


## Scenario: Hermetic full-corpus runtime evidence and bionic Node.js witness

### 1. Scope / Trigger

This contract applies to `scripts/run-real-sample-matrix.sh`, the bionic
Node.js runner and lock, real-sample tier policy, evidence aggregation, and
CI cleanup. It is the cross-layer contract for changes that acquire, execute,
normalize, or validate public real-sample runtime evidence. Registry-only
renders are metadata baselines; they are never execution evidence.

### 2. Signatures

```sh
./scripts/run-real-sample-matrix.sh --tier pr|nightly|release
python3 scripts/check-real-sample-evidence.py MANIFEST \
  --runtime-closures RUNTIME_CLOSURES --tier TIER --artifact-root ARTIFACT_ROOT
python3 scripts/validate-bionic-node-lock.py \
  fixtures/real-samples/bionic-node-runtime-lock.json \
  --manifest fixtures/real-samples/manifest.json --expected-sha256 LOCK_SHA256
```

The bionic witness consumes the already acquired Node.js archive, the reviewed
metadata-only lock, the pinned Termux image, and a host-owned artifact root. It
returns a normalized baseline/outer protocol with `targetStatus`,
`containerStatus`, `dockerStatus`, helper status, lock digest, image identity,
RUNPATH, limits, cleanup authority, and host-captured stream byte counts.

### 3. Contracts

- A dynamic `accepted-and-runs` result requires an attempted target process and
  matching target, Docker, and inspected container exit status. Static
  `validated` never implies process execution. Registry-only dynamic `actual`
  values are `not-applicable` with `actualSource=registry-baseline` and an
  explicit metadata-only reason.
- PR dynamic coverage is limited to the declared BusyBox/musl, GNU coreutils
  `ls`/glibc, and Termux Node.js/bionic witnesses. Nightly and release require
  baseline and outer-wrapper attempts for all 100 identities. Missing closure,
  unsupported profile, or unavailable isolation is an observed
  `environment-unavailable` failure, not a passing expected policy and not
  `not-applicable`.
- The bionic lock is metadata-only (`runtimeEvidence=false`,
  `compatibilityStatus=not-established`). Its SHA-256, immutable image ref and
  ID, `/system/bin/linker64`, exact archive URLs/sizes/digests, base inventory,
  dependency fields, argv, expected status, absolute RUNPATH, outer mode, and
  resource limits are cross-checked by the runner and evidence gate.
- The bionic baseline target is launched directly from the locked
  `execution.argv` inside the prepared Termux root. Baseline argv construction
  must not prepend `execution.loader`: the kernel must honor the Node
  executable's `PT_INTERP` naturally. `/system/bin/linker64` remains a required
  loader identity in the lock/profile and is validated independently; the outer
  invocation continues to replace only `argv[0]` with the packed wrapper.
- Bionic package replay uses direct HTTPS archive acquisition with exact
  size/hash verification. For each package, the locked base Bash runs
  `dpkg-deb --fsys-tarfile` through a `pipefail`-enabled GNU `tar` into a
  fresh user-owned `/tmp/urprotect-package.XXXXXX` staging directory with
  `--no-overwrite-dir --no-same-owner --no-same-permissions --touch`.
  The host-owned setup script then merges the staged payload into `/` without
  changing existing directory metadata: existing regular files are replaced
  by bytes and mode, new directories receive the staged mode, and symlinks
  are recreated from their archive targets. Absolute, traversal, symlink-
  parent, conflicting non-regular, and unsupported special payload paths are
  rejected. The stage is removed after each package; producer, extractor,
  merge, or stage-cleanup failure retains status 74. It does not run apt,
  consult a package index, execute maintainer scripts, or use a mutable host
  library. Base and extracted package inventories use the same canonical
  `${Package}\t${Version}\t${Architecture}\t${Status}` query.
- The Node executable must have exactly one absolute `DT_RUNPATH` equal to
  `/data/data/com.termux/files/usr/lib`, no `DT_RPATH`, no `$ORIGIN`, and no
  relative/multi-component alternative. The pack dispatch remains
  `outer-execveat`, while the policy/evidence mode is
  `outer-path-preserving`; both values are retained and checked.
- Bionic helper statuses are distinct from target statuses: helper 124/125/126
  keep `targetStatus` and `containerStatus` null, with any cleanup observation
  in `cleanupContainerStatus`; a target exit 125 has `helperStatus=null`,
  `targetStatus=125`, `containerStatus=125`, `outcome=target-exit`, and is a
  runtime failure.
- Evidence is host-owned. Target containers have read-only roots and mounts;
  stdout/stderr are captured by the host under the locked output limit. Every
  successful evidence root has `evidence-sanitized.txt`; all regular text
  files are scanned for runner-temp/cache paths and all status/pack markers are
  owned by a matching execution record. Detached workers, named containers,
  and transient images must be proven reaped/absent before temporary roots are
  removed or evidence is accepted.
- The target runner keeps captured stdout/stderr as separate bounded byte-stream returns and log files; baseline/outer protocol dictionaries and all JSON evidence objects must contain only JSON-serializable scalars, arrays, and objects. A raw byte value in a result record is a producer defect and must fail before evidence publication.
- Aggregate CI records and histograms are recomputed from retained fingerprints,
  per-sample results, closures, and policy. Forged record fields, layer counts,
  feature histograms, first-failure values, missing records, and stale marker
  files fail the evidence gate.
- Docker cleanup treats absence as a proof, not a best-effort result: a nonzero `inspect` response is accepted as absent only when it is complete (not timed out or output-limited) and contains Docker's explicit container/image absence marker, including `No such object`. Post-removal inspect responses classified as transient (for example, removal-in-progress or daemon connection races) may be retried within the existing bounded cleanup deadline. Unknown, malformed, live, timed-out, or truncated responses remain cleanup failures, retain the private work root, and prevent transient-image deletion. Diagnostics must distinguish verified absence, transient exhaustion, live resources, and unknown inspection responses.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| Registry-only dynamic render | `actual=not-applicable`, `actualSource=registry-baseline`; never `accepted-and-runs` |
| Missing nightly/release closure or runtime capability | observed `environment-unavailable`; required gate fails |
| Helper timeout/setup/output limit (124/125/126) | helper outcome with null target/container status; no execution success |
| Target exits 124/125 or differs from expected status | `runtime-failure`; helper status remains null |
| Docker attach and inspect statuses differ | environment/protocol failure; no accepted result |
| Bionic image, loader, lock, archive, hash, inventory, or RUNPATH drift | fail closed before accepted execution |
| Stale status, pack, raw-path, unsanitized, or unbound aggregate evidence | evidence gate rejects the artifact root |
| Unreaped worker/container/image or failed sanitizer | cleanup/evidence failure; temporary root is retained when ownership is uncertain |

### 5. Good/Base/Bad Cases

- Good: a native ARM64 runner assembles the reviewed lock, host-captures both
  bionic target streams, verifies statuses and absolute RUNPATH, reaps all
  resources, sanitizes evidence, and the gate binds the aggregate to all
  per-sample records.
- Base: a metadata-only registry render records the 100 identity baseline and
  explicit expected policies but makes no runtime claim.
- Bad: converting a missing closure to expected `environment-unavailable`,
  trusting a target-written status file, accepting a target exit 125 as helper
  setup failure, or reporting aggregate policy values as observed execution.

### 6. Tests Required

- Lock tests mutate image ID/ref, archive digest/size, dependency syntax,
  inventory, argv, expected status, and RUNPATH and require rejection.
- The focused runner test asserts
  `build_direct_baseline_argv(execution["argv"]) == execution["argv"]` and
  that the result is not `[execution["loader"], *execution["argv"]]`; the
  loader remains metadata/profile validation rather than a baseline argv prefix.
- Runner tests cover output/timeout/helper sentinels, target status 125,
  Docker status mismatch, cache symlink traversal, image-removal failure,
  complete `No such object` absence proof, transient inspect retries, rejection
  of timeout/output-limited absence claims, package extraction without apt,
  host-owned streams, cleanup registries, and JSON-safe result dictionaries.
- Evidence tests cover stale baseline/outer/pack/setup markers, missing or false
  sanitizer markers, raw temp paths, bionic identity/path drift, closure drift,
  helper/target status confusion, forged aggregate records/histograms/counts,
  and arbitrary first-failure claims.
- Tier tests assert PR witness scope and 100/100 nightly/release applicable
  baseline+outer policy, with missing runtime closure producing an observed
  failure rather than a passing policy result.
- CI runs the focused bionic lock/runner/closure and worker-cleanup suites on
  every PR, followed by the post-run evidence gate. Native Docker, musl, and
  managed .NET checks remain required environment gates when their toolchains
  are declared available.

### 7. Wrong vs Correct

#### Wrong

```text
if closure_missing:
    result = {"expected": "environment-unavailable", "actual": "environment-unavailable"}
if status_file_exists:
    accept(status_file)
```

#### Correct

```text
attempt the required tier oracle
-> host-capture and inspect target/container status
-> classify helper status separately from target exit
-> bind result, closure, fingerprint, and aggregate evidence
-> sanitize and prove worker/container/image cleanup
-> publish accepted-and-runs only after the target actually ran
```


## Scenario: Real-sample archive identity refresh and registry digest chain

### 1. Scope / Trigger

Apply this procedure when a locked public real-sample archive becomes unavailable,
its upstream index or mirror changes, or a selected package version must be
refreshed. It governs registry provenance and acquisition evidence, not product
runtime support.

### 2. Signatures

```sh
python3 scripts/validate-real-samples.py \
  fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 scripts/validate-runtime-closures.py \
  fixtures/real-samples/runtime-closures.json fixtures/real-samples/manifest.json
python3 scripts/render-real-sample-report.py \
  fixtures/real-samples/manifest.json --tier pr --registry-only \
  --artifact-root fixtures/real-samples \
  --output-json fixtures/real-samples/baseline-aggregate.json \
  --output-markdown fixtures/real-samples/baseline-aggregate.md
```

### 3. Contracts

- Archive URL availability and archive identity are separate facts. An upstream
  404 is an acquisition failure, not an expected runtime result or evidence that
  the product rejects the sample.
- Never repair a 404 by replacing the URL or digest from an unreviewed mirror.
  Retrieve bounded package/index bytes from an authoritative project source or
  reviewed mirror, verify exact archive size and full SHA-256 independently, and
  authenticate the source index/package metadata with the publisher's official
  key when the format provides signatures. For Alpine APKs, the signed
  `APKINDEX` record is metadata evidence: its `C` field is not a substitute for
  the complete APK SHA-256 and byte-size lock.
- If a package release must change, derive its version, archive path, package
  checksum and license from the authenticated source index. Bounded-extract only
  the declared artifact; verify its path remains inside the archive root and
  rederive the executable's size, SHA-256, build ID and ELF identity from the
  extracted bytes. Static validation or inspection does not execute that target.
- Keep the upstream project identity (`projectId`, `identityKey`, and
  `upstreamUrl`), selection rationale, execution policies, expected statuses,
  and compatibility classifications unchanged unless the identity or new
  runtime evidence has been separately reviewed. Package/version changes are
  nested artifact attributes, not new project identities.
- Synchronize every affected current owner in one change: selected manifest
  row, candidate ledger entry and review digest, runtime-closure package-index
  URL/digest/repository root when applicable, the bionic Node.js lock when its
  source package changes, and the manifest SHA-256 in
  `fixtures/evaluator/compatibility-corpus.json` under the matching
  `retainedEvidenceRegistries` entry. The retired
  `fixtures/evaluator/evaluator-protocol.json` is not part of the live chain.
- Keep raw archives and extracted binaries in private temporary storage; do not
  check them into the repository or upload them as compatibility evidence. The
  checked-in real-sample aggregate is metadata-only and may be regenerated only
  with the `--registry-only` renderer. Do not rewrite frozen strict product
  evidence or infer runtime success from registry metadata.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| Locked URL returns 404 | Acquisition fails; no runtime classification or digest refresh follows from the failure alone |
| Package/index signature, full archive SHA-256 or declared size mismatches | Reject before extraction or registry publication |
| Extracted artifact path escapes the package root or target ELF identity/hash differs | Reject the candidate; do not update the selected sample |
| Candidate ledger, resolver lock or evaluator manifest digest is stale | Registry validator/tests fail; update all current owners together |
| Registry-only metadata render succeeds without target execution | Keep all runtime claims and statuses unchanged |

### 5. Good / Base / Bad Cases

- Good: verify publisher metadata and exact archive bytes, inspect the bounded
  declared target, synchronize current registries and digest owners, then wait
  for the required native CI oracle before changing runtime outcomes.
- Base: a different mirror serves identical locked bytes; update only its URL
  after verifying the existing size and SHA-256, leaving package identity and
  statuses unchanged.
- Bad: refresh a hash from whatever a new URL returns, treat an Alpine index
  checksum as the complete APK digest, rewrite a historical baseline, or call
  static validation/runtime-closure assembly a successful target execution.

### 6. Tests Required

- Run `tests/test_real_sample_manifest.py`,
  `tests/test_real_sample_fingerprint.py`, `tests/test_real_sample_evidence.py`,
  `tests/test_real_sample_aggregate.py`, `tests/test_runtime_closures.py`, and
  `tests/test_bionic_node_runtime_lock.py` with `PYTHONPATH` unset.
- Run both validators in the Signatures section and verify the manifest digest
  against the matching retained registry entry in
  `fixtures/evaluator/compatibility-corpus.json`.
- Confirm tests preserve the 100 distinct project identities, package and
  dependency policy, frozen rows, expected execution policy, and no-runtime-
  promotion boundary; confirm the registry-only report matches its renderer.

### 7. Wrong vs Correct

#### Wrong

```text
old package URL returns 404
-> download arbitrary replacement
-> copy its observed SHA into the manifest only
-> treat static inspection as a runtime pass
```

#### Correct

```text
authenticate source index/package metadata and exact bounded archive bytes
-> verify declared artifact path and derive target identity
-> update manifest, candidate, resolver and current evaluator digest owners
-> retain frozen evidence/status policy
-> wait for an actual native runtime oracle before changing runtime outcomes
```


## Scenario: Independent compatibility-only product evidence verification

The active compatibility evidence contract is defined by
`docs/compatibility-evidence-policy.md`. The Scheme-A synthetic six-family
attack evaluator, artificial attack-cost factors and frozen strength baselines
are retired. No numeric reverse-engineering resistance claim can be inferred
from any of these compatibility rows.

- Four native ARM64 shards must collectively retain all 100 required registered units in
  `fixtures/evaluator/compatibility-corpus.json`. Missing, duplicated or
  symlinked product evidence fails the independent gate.
- Run `scripts/check-strict-product-corpus.py --tier pr --runtime glibc
  --shard-count 4 --evidence-root .artifacts/strict-corpus-merge/pr/glibc` to independently
  validate all four exact shard summaries and every registered unit using the existing hash-bound six-stage
  `check-rehydration-evidence.py` verifier. The producer summary is a
  prerequisite, never a substitute for verifying the raw product chain.
- The independent report records each unit's actual product-manifest digest,
  and `securityStrengthClaim` must always be `null`.
- Real-sample, glibc/musl/bionic, HostContext, TLS, fixture, fuzz and runtime
  evidence gates remain distinct and must not be represented as proof of
  quantified attack cost.
- CI retains the `independent-evaluator` job ID solely for compatibility
  with existing required status checks; the job's scope is now limited to
  independently verifying actual compatibility product evidence.

### Regressions

Fail closed on missing required units, bad summary counts, duplicate registry
identities, altered `SHA256SUMS`, failed loader/oracle evidence, or a failed
upstream required platform job. No Scheme-A strength score, attacker-effort
multiplier, or automatic attack-success declaration is emitted.

## Scenario: Protected Image v1 producer evidence

### 1. Scope / Trigger

This contract applies to the explicit `protect-image` command and its additive CI producer evidence. It is a producer-stage contract only: it does not claim that the artifact has been rehydrated, materialized as a Native Image, handed to a loader, or behaviorally executed.

### 2. Signatures

```text
urprotect protect-image INPUT --artifact PATH --role PATH --manifest PATH --stage PATH
  --unit ID --profile outer-execveat|host-context-entry
  (--function NAME | --function-id symtab:INDEX|dynsym:INDEX
                    | --function-address 0xADDRESS)+
  (--pass control-flow-flattening | --pass register-permutation)+
  [--producer-id ID] [--producer-build-sha256 SHA256]
  [--rehydrator ID] [--source-sha256 SHA256] [--request-sha256 SHA256]
  [--provider-file PATH --provider-soname SONAME
   --provider-build-id HEX --provider-sha256 SHA256]
  [--json PATH|-]
```

The provider group is host-only and all-or-none; it is not persisted in the
artifact. See [external consumer publication](./external-consumer-proof.md)
for the exact pins and admission boundary.

The producer emits `protected-image.bin`, `protected-image.json`, `stage.json`, and a closed `SHA256SUMS` file. The stage record is schema v1 with `status`, command/environment/producer/source/request/artifact bindings, bounded diagnostics, transformation identity, and `publicationComplete`.


### TLS runtime projection (additive evidence only)

The producer stage may contain an optional `tlsEvidence` object. This is a
bounded evidence projection consumed by `scripts/check-protected-image-evidence.py`;
it does not change Protected Image v1, the operation grammar, or runtime support
status. Its `schemaVersion` is `1` and its model vocabulary is exactly
`local-exec`, `initial-exec`, `local-dynamic`, `general-dynamic`, and `tlsdesc`.
The object binds one explicit `profile`, `runtime` (`glibc`, `musl`, or
`bionic`), and `lifecycle` (`current-thread`, `registered-worker`, or
`not-run`) to the enclosing stage.

The projection retains source, transformed, and Protected Image paths plus
SHA-256 digests; toolchain and loader identity; bounded PT_TLS template,
`fileSize`, `memorySize`, `zeroFillSize`, alignment, and owning-load facts; and
`perThread`, `zeroFill`, and `teardown` observations. Source and template paths
must be regular files within the evidence root, their digests must match the
files, and transformed/artifact paths and digests must match the enclosing
published Protected Image. PT_TLS template length must equal `fileSize`,
`fileSize <= memorySize`, and `memorySize - fileSize == zeroFillSize`; sizes and
program-header identity are bounded and alignment is a positive power of two.
Unknown fields, unsupported models/profiles/runtimes/results, path traversal,
symlinks, digest mismatches, and malformed numeric facts fail closed.

The result vocabulary is shared with the runtime matrix:
`accepted-and-runs`, `environment-unavailable`, or `runtime-failure`.
All three TLS runtime results require a completely published producer stage and
retained transformed/artifact hashes. `accepted-and-runs` requires measured per-thread/current-thread and image-release
facts with no first failure. Zero-fill is `not-applicable` without a tail and
`not-run` for an unobserved tail; `observed` requires a retained observing oracle.
Accepted rows also bind the Native Image, explicit expected entry status, and
measured runtime identity. See [TLS measured runtime evidence](./tls-evidence-oracle.md)
for the explicit wrapper tuple, real baseline comparison, conditional execution
inputs, and producer-local versus portable consumer identity validation. An
`environment-unavailable` result requires `firstFailureStage=environment`,
`lifecycle=not-run`, and no lifecycle observation. `runtime-failure` describes a
failure after publication and requires a non-environment first-failure stage;
it never substitutes for a failed producer publication. Producer/layout failure
continues to use the existing failed-stage contract, with no artifact or role.
The selected checker runtime argument must equal `tlsEvidence.runtime`, so one
runtime's result cannot promote another runtime.

### 3. Contracts

- The command snapshots explicit selectors and passes, uses the managed `ProtectedImageProducer`, and publishes through `ProtectedImagePublisher`; the current `protect` command and `ProductReport` schema remain unchanged.
- A passed stage binds `artifactRole=protected-image`, `abiId=urprotect.protected-image.v1`, `abiVersion=1`, the role artifact digest/size, the declared rehydrator consumer, and a raw manifest path. A failed stage retains diagnostics and streams but publishes neither artifact nor role.
- The producer artifact is a bounded canonical Protected Image document. It is not a complete source/final ELF and is not counted as a strict compatibility unit until the rehydrator, Native Image, loader, and behavior stages are present.
- CI runs the producer script after build and uploads `.artifacts/protected-image/` with `if: always()`. The script retains failure evidence and the checker recomputes closed manifest hashes; it never relabels a producer pass as compatibility success.
- `commandDigest` and `environmentDigest` are evidence provenance, not authorization or compatibility factors. Their inputs are bounded and stable for the invoking process.

### 4. Validation & Error Matrix

| Condition | Required result |
|---|---|
| Missing/duplicate output path or explicit selector/pass | usage/`InvalidArgument`; no partial publication |
| Source/request/role/ABI mismatch | stable Protected Image diagnostic; failed stage; no artifact/role |
| Truncated, oversized, duplicate, overlapping, unknown, or non-canonical ABI record | codec validation failure before publication |
| Output move, hash, or manifest failure | `OutputIoFailure`; rollback of moved producer outputs; retained failed stage |
| Closed manifest missing a retained stream/stage/role/artifact | producer evidence checker fails |
| Passed producer stage without rehydrator/native/loader/behavior evidence | remains additive producer evidence; strict evaluator unit remains incomplete |

### 5. Good / Base / Bad Cases

- Good: one explicit fixture request emits deterministic role/artifact/stage/checksum records, and repeating the same request produces identical artifact bytes.
- Base: compiler or producer prerequisites are unavailable; the script retains a failed stage, stdout/stderr, and closed checksum manifest without claiming support.
- Bad: treating a direct protected ELF, complete source ELF, or generic PayloadFrame as a Protected Image; accepting a passed stage from a forged role or open manifest; or counting producer emission as end-to-end compatibility.

### 6. Tests Required

- Managed tests cover codec round trips, malformed/overflow/duplicate/overlap/alias cases, role/stage binding, the shared PT_NULL/RX-extension/relocated-table layout planner, and atomic rollback.
- CLI tests cover selector/pass parsing, output path conflicts, success publication, failed source binding, focused JSON reporting, and the current command grammar.
- The producer script/checker tests cover success/failure retention, closed SHA256SUMS, path traversal, digest continuity, and no partial artifact on failure.
- The CI workflow contract asserts additive execution after build, `if: always()` evidence checking/upload, and no change to strict evaluator claim semantics.

### 7. Wrong vs Correct

#### Wrong

```text
protect-image = rename(finalElfBytes)
producerPassed = true
compatibilityUnitComplete = true
```

#### Correct

```text
explicit request -> layout-neutral plan -> canonical Protected Image
-> role/stage/checksum publication -> later bounded rehydration
-> Native Image -> native loader -> behavior oracle
```

## Scenario: Generic rehydration, Native Image, and strict native handoff

### 1. Scope / Trigger

This contract applies when a Protected Image producer result is consumed by the first strict compatibility vertical slice. It covers the managed `rehydrate-image` boundary, deterministic Native Image materialization, the native memfd/`execveat(AT_EMPTY_PATH)` helper, and the retained stage evidence. It does not turn the rehydrator into a dynamic loader.

### 2. Signatures

```text
urprotect rehydrate-image SOURCE --artifact PROTECTED_IMAGE
  --native-image NATIVE_IMAGE --role NATIVE_ROLE --record REHYDRATION_RECORD
  --unit ID --profile outer-execveat|host-context-entry
  --source-sha256 SHA256 --request-sha256 SHA256
  --producer-id ID --producer-build-sha256 SHA256
  --consumer-id ID --consumer-build-sha256 SHA256
  [--provider-file PATH --provider-soname SONAME
   --provider-build-id HEX --provider-sha256 SHA256] [--json PATH|-]

native-image-handoff IMAGE EXPECTED_SHA256 REHYDRATION_SHA256 EVIDENCE_JSON
  STDOUT_FILE STDERR_FILE OUTPUT_LIMIT -- ARG0 [ARG ...]
```

The managed result owns `NativeImage` bytes and `RehydrationRecord`. The native helper owns only sealed memfd creation, bounded streams/resource facts, and `execveat` invocation. The record fields `handoffRecordSha256`, `handoffStatus`, and `preHandoffRecordSha256` bind the completed handoff without creating a mutable hash cycle.

### Current shared workflow and profile ownership

The current `protect`, `protect-image`, and `rehydrate-image` commands use the
same Core `ProtectionWorkflow` owner for request normalization, selected-function
planning, semantic/protection plans, physical layout, profile materialization,
validation, and publication. The commands differ only in which stage/result they
publish. `FunctionProtectionService` is not a production writer.

`OuterExecveat` and `HostContextEntry` select explicit materialization policies
against the shared layout/materialization operations. The HostContext policy
requires a current AArch64 `ET_DYN` entry image without `PT_INTERP`, a bounded
executable declared entry, current v3 profile/ABI/capability metadata, and the
sealed-memfd HostContext handoff. It never invokes or reinterprets the outer
`execveat` policy. Both policies publish only after reparse, profile, digest,
role/stage, and native-image validation succeed.

Every published role, stage, Native Image descriptor, report, and rehydration
record binds `workflowOwner`, profile, ABI, source/request/artifact/output
hashes, and `firstFailureStage`. A failed stage may retain diagnostics and raw
failure evidence, but it must remove or withhold successful artifact, role,
stage, Native Image, report, and evidence publication. Runtime-specific evidence remains
independent; an unavailable musl or bionic lane is recorded as
`environment-unavailable` and never promoted by the glibc HostContext result.

### 3. Contracts

- Rehydration authenticates the Protected Image canonical digest and verifies source/request/unit/profile/producer/consumer bindings before materialization. Unknown operations, invalid executable mappings, overflow, unsupported permission/layout transitions, and incomplete operation streams fail closed.
- A passed Native Image is deterministic, reparses as AArch64 ELF, has a distinct hash from Source and Protected Image, and is atomically published with a native-image role and rehydration record. A failed stage retains diagnostics but no successful Native Image or role.
- Rehydration delegates physical placement to one bounded ELF layout planner/materializer. It deterministically considers a compatible terminal RX `PT_LOAD` extension, an ordinary available `PT_NULL` record, and a relocated/expanded program-header table, then applies typed AArch64 branch decisions and edits before reparsing. A missing slot is not a prerequisite; an occupied table uses the relocated-table candidate or returns `RehydrationLayoutUnavailable` without a direct-protector fallback. The materializer retains the selected strategy and bounded address map in layout evidence.
- Strict handoff requires `memfd_create`, executable mode, `fsync`, required seals where supported, `execveat(AT_EMPTY_PATH)`, bounded host-captured stdout/stderr, and separate helper/target status. A path-based execution is never a strict pass.
- The evidence checker requires a closed `SHA256SUMS`, stage-specific source/protected/native/handoff/rehydration hashes, target-loader and behavioral-oracle records, and matching first-failure stage. Producer success alone remains incomplete compatibility evidence.
- Native loader semantics remain outside the rehydrator: dependencies, dynamic symbols, relocations, TLS, constructors, destructors, and process lifecycle are handled only by the target loader.

### 4. Validation & Error Matrix

| Condition | Required result |
|---|---|
| Source/protected/consumer/request mismatch | stable binding diagnostic; no Native Image publication |
| Tampered/truncated/unknown/overlapping operation or address overflow | bounded decode/materialization failure; failed rehydration record |
| No valid executable mapping or representable output layout | `RehydrationLayoutUnavailable`; no direct protected-ELF fallback |
| Native Image parse/hash/role mismatch | `NativeImageMalformed`/`OutputIdentityMismatch`; rollback all Native Image outputs |
| memfd/seal/fsync/execveat/stream capture failure | failed handoff evidence; target-loader and oracle do not pass |
| Handoff target status/streams differ from frozen oracle | behavioral-oracle failure; strict unit remains incomplete |
| Missing/unsafe/stale evidence or open checksum manifest | rehydration evidence checker fails closed |

### 5. Good / Base / Bad Cases

- Good: a source plus producer artifact produces distinct Native Image bytes, the sealed memfd handoff runs the target, and retained baseline/target status and streams match.
- Base: a producer artifact is valid but native prerequisites or layout capability are absent; the run retains an explicit rehydration/handoff failure and the evaluator keeps the unit incomplete.
- Bad: executing Source or direct protected ELF after rehydration failure, treating a Native Image hash as proof of loader behavior, or accepting helper exit success without sealed memfd/`execveat` evidence.

### 6. Tests Required

- Managed tests cover valid materialization, source/request/consumer mismatch, tamper/overflow/unsupported operation, occupied-table relocation, RX extension, PT_NULL parity, branch-range diagnostics/relaxation, deterministic Native Image hash, atomic publication, and record binding.
- Native helper tests cover digest mismatch before memfd, seal verification, bounded output, target status/signal, and exact `execveat` markers.
- Runner/checker tests cover closed-manifest ownership, source/protected/native/handoff hash continuity, pre-handoff record binding, failed-stage retention, target-loader/oracle continuity, and first-failure classification.
- CI workflow tests assert additive execution/checking after build, always-retained evidence, and no change to evaluator claimability or frozen corpus policy.

### 7. Wrong vs Correct

#### Wrong

```text
if rehydrate_failed:
    execve(source_or_unverified_protected_elf_path)
if handoff_exited_zero:
    claim_loader_behavior()
```

#### Correct

```text
authenticate Protected Image -> materialize -> parse/hash Native Image
-> sealed memfd + execveat -> target-loader record
-> baseline/target behavior oracle -> complete strict unit only then
```

## Historical compatibility baseline and Scheme-A retirement

The previous baseline-zero/v2 strength and compatibility-ratio protocols were
control-plane experiments and are no longer active. They cannot establish
quantified resistance to reverse engineering. Their source and change history
remain recoverable through Git history, but the live CI contract is the
strict compatibility product chain described above.

Compatibility tests must measure retained product behavior and exact evidence;
they must not promote the 100 registered synthetic samples into a claim of
100x real-world compatibility.

## Scenario: External provider managed admission and scoped native evidence

### 1. Scope / Trigger

Use this contract when reporting or extending the bounded external-table
provider path. **Managed Slice B and one scoped native AArch64/glibc
source-versus-rehydrated-Native-Image observation are retained.** The row
`runtime.host-context.external-table-provider` remains `unknown` and
`scoped-observation-not-promoted` until the required hosted CI gate passes and
any review/registry gates are complete. The local observation is one project-
built dependency-free provider DSO and one consumer; it does not establish
arbitrary provider, dependency-graph, table-family, indirect-call, musl, or
Bionic support.

### 2. Signatures

Managed `protect-image` and `rehydrate-image` accept only the complete optional
host group shown above: `--provider-file`, `--provider-soname`,
`--provider-build-id`, `--provider-sha256`. Paths/configuration are not serialized
into SPS6; publication requires independent provider/source validation. See
[the executable managed contract](./external-consumer-proof.md).

The native host supplies provider configuration explicitly:

```c
urp_status urp_host_adapter_init_with_provider(
    urp_host_adapter_v1 *adapter,
    const urp_host_provider_config_v1 *provider);
```

`urp_host_provider_config_v1` has `path`, `expected_soname`,
`expected_build_id_hex`, `expected_sha256_hex` (`const char *`); initialization
copies values. This is not a new HostContext ABI or payload-selected provider.
The current controlled native contract fixes SONAME
`liburprotect-jump-table-provider.so.1` and symbol `urp_external_jump_table`;
its build-ID storage is 41 bytes (40 hex characters plus terminator), whereas
managed CLI syntax allows 8–128 even hex characters. A managed pin accepted
syntactically is not therefore native-contract acceptance.

Existing native test/helper interfaces and evidence commands are:

```text
host-context-external-provider-self-test
  provider consumer bad-size wrong-soname bad-dependencies conflict
  symbol-conflict wrong-consumer versioned-libc

host-context-external-provider-image-handoff
  PROVIDER SONAME BUILD_ID SHA256 IMAGE ENTRY_SYMBOL INDEX RECORD_JSON

scripts/run-external-provider-e2e.sh
  --tier pr|nightly|release --artifact-root ROOT

scripts/run-external-provider-rollback-oracle.sh --artifact-root ROOT
```

The unconfigured `host-context-image-handoff IMAGE ENTRY_SYMBOL RECORD_JSON`
helper is not the provider-aware execution path.

### 3. Contracts

- SPS6/version 6 is the only nested schema; kinds **8** (unchanged provider
  facts/wire bytes) and **9** (typed consumer companion) cross-validate against
  exact source-derived owner/fixup and emitted output facts. Protected Image
  ABI remains **v1**. No provider-domain VA becomes a local consumer mapping;
  only the selected consumer is rewritten, with its GOT identity-preserved.
- Managed input is one bounded private snapshot with SHA checked before parse,
  read through the supported Linux safe-file adapter. Linux/AArch64 executed
  tests versus Linux/x64/unsupported-host static review must be stated
  separately. This host-helper support does not add an x64 ELF backend.
- The native adapter uses a sealed provider and consumer in one isolated glibc
  namespace, verifies the provider link map/table and consumer GOT binding before
  handle publication, and keeps the provider alive through consumer release.
  Provider bytes are host-pinned by exact SONAME, GNU build ID and SHA-256;
  the dependency-free provider and its four-entry signed-relative table are
  bounded by the independent 8 MiB parser-work limit. The native source-loader
  self-test remains a separate observation from the managed Native Image run.
- The retained scoped run executes **source and managed-rehydrated Native
  Image**, selected `urp_entry` and unselected `urp_observer`, at indices 0, 1,
  2, 3 with entry statuses `17, 103, -7, 91`, and safe-default index 4 with
  status `-1`. Process/helper status and signed entry status are separate
  evidence. For each source/transformed entry/observer/index handoff, the
  checker binds exact stdout/stderr bytes and hashes, image/provider identities,
  release status/order, and absence of a positive failure stage; a zero helper
  exit alone is not target-selection evidence.
- The source and transformed Native Image chain is retained with provider,
  source, Protected Image and Native Image hashes; request/producer/consumer
  build IDs; commands, stages, build provenance, runtime identity and a closed
  SHA256SUMS inventory. The checker independently parses provider dynsym/table/
  entries/targets and consumer dependency/dynsym/RELA/GOT facts, follows the
  source entry stub to the complete emitted 92-byte live dispatcher, verifies
  the observer's original provider-table binding, and relates measured load
  biases, link maps, sealed mappings, read-only provider-table bytes, GOT value
  and each target address back to the retained ELFs. It rejects partial,
  duplicate, conflicting-permission and BSS-only `PT_LOAD` intersections over
  the emitted code and entry stub; ASLR addresses or claim booleans alone are
  insufficient.
- Three failures remain distinct: the wrong-provider-SHA negative is rejected
  during rehydration (`OutputIdentityMismatch`, no Native Image and no loader);
  the separate source-loader rollback oracle injects a one-shot failure after
  verified provider/consumer binding and proves cleanup plus a successful
  reload/release; and the transformed Native Image rollback record proves the
  same post-binding cleanup/retry boundary for the exact Native Image. Event
  overflow, descriptors/references/mappings, statuses and retained streams are
  checked. Tamper tests refresh the full closed manifest and dependent claims so
  they fail on semantic inconsistency, not stale hashes.
- No arbitrary/multiple provider, provider dependency, search path, external
  target, alternate encoding, veneer or runtime-translation admission follows.
  Existing libc singleton/pair rules remain unchanged; no musl/Bionic runtime
  claim can be inferred from glibc or from managed tests.

### 4. Validation & Error Matrix

| Evidence / boundary | Required classification |
|---|---|
| Managed Slice B publication without the retained source/transformed oracle | managed evidence only; no runtime promotion |
| Retained local source/transformed root and passing exact-root checker, but no hosted CI result | scoped glibc observation; feature remains `unknown` / not promoted |
| Older native provider self-test or the separate provider-loaded rollback root | source-loader lifecycle evidence only; not selected/transformed positive behavior |
| Missing host provider, mismatched pins/dependencies/owners, or wrong hash | fail closed before the applicable publication/loader boundary; preserve exact first failure and no-publication evidence |
| Helper success without exact entry statuses for both symbols and all five indices | insufficient behavioral evidence |
| Missing/invalid closed-root manifest, source/output owner proof, runtime identity, complete output map, or rollback record | evidence checker rejects; no acceptance promotion |
| Partial, duplicate, conflicting or BSS-only `PT_LOAD` overlap with emitted code or live entry stub | evidence checker rejects the ambiguous physical mapping |
| Refreshed-checksum dead chain, table/GOT/target/status/stream/identity forgery | evidence checker rejects semantic inconsistency |
| No native AArch64/glibc toolchain or architecture | explicit environment failure; no emulator or other-runtime substitution |
| No official hosted `build-and-test` result / branch-protection confirmation | local observation remains scoped and unpromoted |

### 5. Good / Base / Bad Cases

- Good: preserve the exact-root local source/transformed observation and
  separate provider-loaded rollback record; independently rederive the selected
  live output chain, observer binding, provider targets, hashes, mappings,
  statuses, streams and release state. Keep the row unknown until the required
  hosted gate is observed.
- Base: managed publication and native source-loader checks pass, but no
  transformed Native Image execution root or no official hosted result is
  available; record the available scoped evidence without promoting the row.
- Bad: run the source fixture twice and label one transformed, infer target
  identity from a constant name array, trust absolute ASLR addresses or helper
  exit 0, treat the source-loader rollback root as transformed execution, or
  generalize the one glibc provider fixture to arbitrary providers or runtimes.

### 6. Tests Required and Slice C execution inventory

The following numbered inventory is the preserved pre-execution gap analysis;
its statements that the runner/checker/evidence did not yet exist are historical,
not the current status. The current implementation, retained evidence, CI
wiring, tests, and remaining hosted/promotion gates follow it below.

1. **Reusable native loader/harness:**
   `host_context_external_provider_self_test.c` takes the consumer at `argv[2]`,
   parses its dynamic metadata rather than a hardcoded source instruction
   offset, calls `load_image`, resolves both `urp_entry` and `urp_observer`,
   dispatches all five indices through `launch_args.argc`, checks runtime
   GOT/table/provider mappings and release/unmapping. Thus it is structurally
   capable of taking the produced Native Image as its consumer input, subject
   to its existing fixture/profile predicates; that capability is **not yet
   verified by a fresh transformed run**. The Makefile target currently supplies
   the source consumer fixture and its eight companion inputs, not a managed
   Native Image. It auto-derives provider pins from the supplied file for the
   self-test, so a Slice C evidence chain must independently bind that identity
   to the managed host pins.
2. **Evidence capture gaps in that self-test:** its JSON uses
   `sourceEntryStatuses` even for a caller-supplied image; it has no
   source/Protected/Native Image or rehydration binding. `capture_dispatch`
   combines selected and observer streams in one per-index capture. Target
   addresses are computed from table displacements and checked provider-local,
   but the printed target names are a fixed array, not exact independently
   resolved symbol-row bindings. It emits mapped paths/addresses and release
   facts, not a complete measured libc/loader identity, separate per-call process
   records, retained stream files, stage chain or closed evidence root. These
   omissions require an evidence owner/checker, not a support claim from JSON.
3. **Generic handoff/runner gap:** `host_context_image_handoff.c` initializes an
   unconfigured adapter and fixes `launch_args.argc = 1`; it has neither provider
   pins nor an index argument. `scripts/run-host-context-rehydration-e2e.sh`
   accepts neither provider flags nor provider-aware handoff inputs. Existing
   static-callback/shared-table runners cannot execute this provider family
   unchanged. Reuse the bounded owners; do not add an unverified path loader.
4. **Provider runner/checker gap:** no provider-specific managed→rehydration→
   native entry/observer E2E runner, exact-root provider evidence checker or
   associated Python tamper suite exists under `scripts/` / `tests/test_*.py`.
   Required assertions include source/output live entry chain and observer
   bytes, exact table-entry↔target-symbol mapping, measured runtime bindings,
   signed statuses/streams/release and observed failure stages/rollback. Include
   coordinated checksum-refreshed dead-copy and metadata forgeries, not just
   table hashes or successful compilation.
5. **Registry/CI gap:** `fixtures/manifest.json`, `tests/regression-matrix.json`
   and CI have ordinary/shared-table rows and the external-table fail-closed
   negative, but no provider transformed positive or exact-root gate. Do not
   mark a runtime row validated until Slice C evidence/review exists. Any future
   fixture-registry edit must update only the matching current
   `retainedEvidenceRegistries` digest in
   `fixtures/evaluator/compatibility-corpus.json`; the retired
   `evaluator-protocol.json` is not a live digest owner. Keep frozen
   product-evidence baselines intact. Full Python/evidence discovery and Slice
   C's managed/native/metadata gates remain future execution work; the accepted
   review ran boundary Python tests,
   not the full evidence suite.

#### Current retained evidence, CI declaration, and remaining gates

1. **Transformed managed/native positive:**
   `scripts/run-external-provider-e2e.sh --tier pr --artifact-root ROOT` drives
   source → `protect-image` → `rehydrate-image` → Native Image, then invokes
   `host-context-external-provider-image-handoff` for source/transformed
   `urp_entry` and `urp_observer`, indices 0–4. The retained current local root
   is
   `.artifacts/indirect-control/provider-rollback-native-image-implementation-20261020-4/runtime.indirect-control.external-provider.glibc.host-context-entry`.
   It reports direct native AArch64/glibc 2.43 execution, no emulation, and
   `acceptanceState=scoped-observation-not-promoted`. Provider identity is
   SONAME `liburprotect-jump-table-provider.so.1`, GNU build ID
   `a82d6ab982fab000f733cb631639b28f16f0bdb6`, SHA-256
   `30efdbcd717c30a518bc7c83851ed3b43ba57a9e130064be04d176d0764e1746`.
   The defined 16-byte read-only table is at VA/file offset `0x20000`, with
   signed entries `-65536, -65528, -65520, -65512` reaching four provider-local
   functions at VAs `0x10000, 0x10008, 0x10010, 0x10018`. Source/Protected/
   Native Image SHA-256 values are `2dd8122e8a07aad02db477fc1928c61969785aa049a11c6c9b0a5300c46f41fa`,
   `b1eb4bc73792e69e4bb306eb24f082dc88a8d136b6cc750061a409588beff73a`, and
   `196dcb608ebcb1a87ae7280b2bee77a5e6f4c69c8135ac95e9476e5066cfc74a`.
   Its closed SHA256SUMS is
   `aa4a5725f2797b5b5115ac701ee0a2de7c9653fd02a2c025fffdc574f1bd5abb`.
2. **Exact report/checker boundary:**
   `external-provider-evidence.json` is schema version 1 and carries
   `acceptanceState`, `artifacts`, `buildProvenance`, producer/consumer IDs and
   build hashes, `execution`, `providerFacts`, `sourceElfFacts`,
   `nativeElfFacts`, `observerSourceBinding`, `selectedFunction`, `handoffs`,
   `rollbackNegative`, and `transformedNativeRollback`. Each source/transformed
   lane has ten handoffs (both entry symbols × five indices) binding process and
   signed entry status, byte-exact stdout/stderr and hashes, image/provider
   identities, runtime mappings/target addresses, and release. The checker
   follows the entry stub to the complete 92-byte emitted dispatcher and
   requires one file-backed executable owner with no other PT_LOAD memory-range
   intersection. Refreshed-root tests cover partial/duplicate/conflicting-
   permission/BSS-only overlaps and semantic dispatch/metadata tampering without
   executing a mutated image.
3. **Distinct negatives and rollback:** the positive root's `rollbackNegative`
   binds a wrong-provider-SHA failure at rehydration (`OutputIdentityMismatch`,
   exit 5, no Native Image and no loader). Its transformed rollback record is
   schema version 2 with a one-shot failure after actual provider acquisition,
   consumer `dlmopen`, and verified GOT binding but before handle publication;
   its checked trace has 21 events and proves cleanup, no failed handle, a
   successful retry through entry/observer, and release. The separate native
   source-loader oracle has its fresh root
   `.artifacts/indirect-control/provider-loaded-rollback-ci-validation-20261020T153308Z-18193`,
   schema version 1, 21 checked lifecycle events, successful cleanup/reload/
   release, SHA256SUMS digest
   `1e386bcd644adfb8e5024cb86504191fecccddd82f3a8902562488a2bb18c38e`, and
   report digest
   `fa3d2a2c6d1e5c9fbf03380f43ffd15b8122064aa02d49688bcafe88353be6b0`.
   The older `20261020T152000Z` source-loader root has a current-checker hash
   mismatch and remains historical; it was not rewritten or substituted.
4. **Independent tests and local gates:** current root-bound transformed
   provider tests passed 26/26, source-loader rollback tests 5/5, and focused
   fixture/digest-chain/regression tests 3/3. The retained local gate reports
   Release build 0 warnings/errors, managed tests 754/754, native runtime suite
   exit 0, full Python discovery 458/458 with no skips, 39 evaluator tests,
   13 fixtures, 27 regression cases, and 100 evaluator rows. The independent
   integration review
   `/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/41606f2f-bbdf-4150-8757-2428ab7fc6cf_trellis-check_output.md`
   (SHA-256 `04461a5761415abff30396ab7fcb036916abf102970336e7bf996bf1edca7a17`)
   rechecked the exact current roots and reported a scoped integration pass.
   These are local retained results, not a hosted Actions run.
5. **CI and registry:** provider producer/checker gates are wired in the
   mandatory `protection-and-tls` job on `ubuntu-24.04-arm`, timeout 40 minutes,
   and use `if: always()` with run-keyed markers/logs/statuses. Exact `current` roots are
   `.artifacts/indirect-control/external-provider/current` and
   `.artifacts/indirect-control/provider-loaded-rollback/current`; upload runs
   under `if: always()` with `include-hidden-files: true`. Both regression rows
   are required on `native-arm64` at 1200 seconds. The evaluator digest chain is
   current, but the fixture row remains `unknown`; no official hosted workflow
   has exercised this uncommitted YAML, and branch-protection status mapping is
   not inspectable here.
6. **Remaining scope:** hosted CI/branch-protection confirmation, the final
   general target-resolution/address-map report, owner policy for incomplete
   table inventories, independent musl/Bionic rows, arbitrary providers/
   dependencies, other table encodings/indirect-call families, and general
   runtime promotion remain open. The historical Bionic staged-merge Python
   failures recorded in the task gap audit are unexplained; a later green suite
   does not erase them.

### 7. Wrong vs Correct

```text
Wrong: local scoped provider E2E + source-loader rollback + green local suites
       => runtime.host-context.external-table-provider validated everywhere.
Correct: retain the scoped evidence as non-promoted; require the hosted native
         CI/checker gate, preserve separate rollback provenance, and keep
         musl/Bionic and general indirect-control acceptance open.
```

## Scenario: Native runtime identity and PT_LOAD ownership for ordinary indirect-control evidence

### 1. Scope / Trigger

This evidence-only contract applies to the ordinary signed-relative-32 jump-table
source/transformed HostContext row and its native handoff, runner, and independent
root checkers. It does not change the HostContext ABI, Protected Image or Native
Image format, product `urprotect` command grammar, resolver/publication behavior,
shared-table runner, or provider admission. It is an independent consistency
check of retained process/ELF/maps facts, not an authenticity mechanism or a
runtime-support promotion. The ownership proof distinguishes page-rounded file
offset candidates from page-rounded virtual-memory owners: a partial file-range
candidate may be skipped under the unique complete-owner rule below, while
virtual-memory containment remains strict.

The ordinary native AArch64/glibc root is locally retained and independently
checked. This environment has no `musl-gcc`, Docker, or Podman, so no local
ordinary-musl execution is claimed; the pinned hosted musl producer/checker gate
remains pending. Bionic, shared-musl, provider, and other indirect-control rows
are separate evidence slices (see [shared-table musl
evidence](#scenario-native-shared-table-musl-evidence)); this ordinary-row
implementation does not cover or promote them.

### 2. Signatures

```sh
scripts/run-indirect-control-e2e.sh --tier pr|nightly|release \
  [--runtime glibc|musl] [--unit UNIT] [--artifact-root ROOT]
scripts/run-host-context-rehydration-e2e.sh \
  --tier pr|nightly|release --runtime glibc|musl \
  [--require-runtime-identity] [--unit UNIT] [--source ELF]
python3 scripts/check-rehydration-evidence.py ROOT \
  --tier pr|nightly|release --runtime glibc|musl --unit UNIT \
  [--require-runtime-identity]
python3 scripts/check-indirect-control-evidence.py ROOT \
  --tier pr|nightly|release --runtime glibc|musl --unit UNIT \
  [--require-runtime-identity]

int urp_native_process_identity_capture(
    const char *directory_path,
    const char *relative_directory,
    const char *role,
    const char *image_sha256,
    char *identity_relative_path,
    size_t identity_relative_path_capacity,
    char identity_sha256[65]);
```

`--runtime` and `--require-runtime-identity` belong only to evidence runners
and checkers; neither is a product compatibility setting or a `urprotect`
command option. The indirect-control runner selects `glibc` by default and
passes the required-identity option to fresh handoffs/checkers. Musl always
requires the identity, even if the optional flag is omitted. These signatures
and the identity carrier schema are unchanged by the file-candidate rule; no
new owner field, schema version, or runtime-support claim is introduced.

### 3. Contracts

- The native handoff's `runtimeIdentity` carrier is either `null` or exactly
  `{ "schemaVersion": 1, "path": RELATIVE_PATH, "sha256": LOWERCASE_SHA256 }`.
  The bounded retained identity JSON has exact keys `schemaVersion`, `runtime`,
  `architecture`, `role`, `processId`, `imageSha256`, `runtimeVersion`,
  `runtimeVersionSource`, `interpreter`, `maps`, `helper`, `libc`, and `loader`.
  Schema versions and numeric facts require exact integer values (booleans,
  floats, and strings are not integers). Its architecture is `aarch64`; runtime
  is `glibc` or `musl`; role is `source` or `target`; and the image digest binds
  the exact image bytes consumed by that handoff process.
- `interpreter` has exactly `declaredPath`, `resolvedPath`, `deviceMajor`,
  `deviceMinor`, and `inode`. `maps` has `retainedPath` and `sha256`. Each of
  `helper`, `libc`, and `loader` has exactly `mappedPath`, `deviceMajor`,
  `deviceMinor`, `inode`, `size`, `sha256`, and `retainedPath`. Retained paths
  are safe evidence-root-relative paths. The helper's retained ELF `PT_INTERP`
  must equal `declaredPath`; realpath resolution and device/inode must identify
  the actual mapped loader. Glibc libc and loader are distinct mapped files;
  musl records its combined loader/libc identity consistently in both fields.
  Glibc runtime version is recomputed from retained libc bytes using exactly
  one `glibc-libc-release-version-marker`, unchanged from the existing glibc
  identity contract. Musl runtime-version admission is deliberately scoped to
  the exact reviewed combined libc/loader ELF of 711,128 bytes with SHA-256
  `4fe353b2b485ffc2905b400ca8ab364b88d402ca11adec3553cb5f8928bb01b9`.
  Native capture compares the digest it computed for the mapped libc bytes;
  the independent checker recomputes the digest from retained libc bytes and
  requires it to equal both the identity's libc digest and this fixed pin
  before accepting `runtimeVersion`. For this exact artifact, static
  disassembly ties its unique `Version %s\n` format string to the `dprintf`
  argument `1.2.3`; this does not establish generic musl token linkage. The
  synchronized `runtimeVersionSource` value is
  `musl-reviewed-libc-sha256-pinned-version-marker`. Other musl artifacts fail
  closed pending code/data linkage proof or a separately audited exact digest
  pin. Source and target family, version, interpreter, and helper/libc/loader
  file identities must agree.
- Native capture and Python validation are bounded before allocation or reads:
  `/proc/self/maps` is at most 1 MiB, each maps line at most 8192 bytes, each
  retained runtime/helper ELF at most 32 MiB, identity JSON at most 16 KiB,
  the ELF has at most 4096 program headers, and all maps/helper/libc/loader/
  identity bytes for one process total at most 96 MiB. The C capture reads
  stable regular-file descriptors and the checker independently verifies
  retained SHA-256, device/inode, ELF, interpreter, and maps facts.
- Map ownership has two independent proofs over strict half-open intervals.
  For the file proof, derive each checked page-rounded `PT_LOAD` file interval
  and consider its relation to the VMA's file interval. A candidate that only
  partially intersects the VMA is not an owner and may be skipped. Accept the
  file proof only when exactly one candidate fully contains the complete VMA,
  its `PT_LOAD` permissions are compatible, and its checked load bias agrees
  with the process mapping. Reject when no complete candidate survives or when
  two or more complete candidates survive, even if both appear individually
  compatible; do not choose between two full file owners by VA or bias.
- Independently, subtract the proven load bias from the VMA address and require
  its complete half-open virtual interval to be contained by exactly one
  checked page-rounded `PT_LOAD` memory interval derived from `p_vaddr +
  p_memsz`. This strict memory owner must be the same `PT_LOAD` as the unique
  file owner. Reject every partial memory intersection, second/overlapping
  virtual owner, file-disjoint VA alias, zero-`p_filesz` BSS overlap, and
  arithmetic or page-rounding overflow. The file-candidate skip never applies
  to this virtual-memory proof. Adjacent half-open ranges remain valid. Kernel
  RELRO protection splits remain valid when each split independently satisfies
  both proofs. Unrelated bounded bracketed kernel maps labels are not
  runtime-file identities and cannot satisfy a mapped-file proof.
- The standalone rehydration checker rejects a symlink evidence root or path
  component and scans with no-follow, descriptor-relative directory/file opens
  after `stat(..., follow_symlinks=False)`. Its explicit limits are 512
  directories including the evidence root, 1024 entries, 1000 regular files,
  and 256 MiB aggregate file bytes, in addition to the existing per-file
  bounds. It rechecks descriptor and tree identity during reads and before
  completion. Checker helper modules are loaded from the sibling file resolved
  from `__file__` through bounded `O_NOFOLLOW | O_NONBLOCK` reads, not ambient
  `PYTHONPATH`/module discovery; a replaced FIFO is rejected without blocking.
- Historical glibc evidence without a carrier remains readable in default
  compatibility mode. A present carrier is always validated, even when it is
  optional. Fresh ordinary glibc producer/checker invocations require it, and
  musl requires it unconditionally. The requirement comes from the trusted
  runner/checker option and is not inferred from mutable retained JSON. No host
  paths or identity configuration are serialized into product snapshots or
  artifacts. These checks establish internal consistency only; they do not
  cryptographically attest a process or host.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| Historical glibc carrier absent and identity is not required | Accept the historical evidence shape; validate any carrier that is present |
| Fresh glibc identity required but carrier is absent | Reject the evidence root; no successful evidence result |
| Musl carrier absent, malformed, bound to glibc, or claiming a runtime version from any combined libc/loader digest other than `4fe353b2b485ffc2905b400ca8ab364b88d402ca11adec3553cb5f8928bb01b9` | Reject; no musl identity fallback or generic-token admission |
| Schema has missing/extra fields, wrong version, or non-exact integer types | Reject the identity record, including refreshed-checksum mutations |
| Image, role, runtime/version marker, interpreter, maps path, device/inode, retained bytes, or source/target identity differs | Reject the evidence root |
| A VMA only partially intersects a page-rounded `PT_LOAD` file interval, but exactly one permission-compatible full file owner with a consistent load bias remains | Skip that partial file candidate; continue to the independent memory-owner proof |
| No fully containing file owner remains, or two or more fully containing file owners remain | Reject; file ownership must be unique, including the conservative two-full-candidate case |
| A VMA only partially intersects a page-rounded `PT_LOAD` memory interval from checked `p_vaddr + p_memsz`, or a second segment aliases the virtual pages | Reject before accepting the runtime identity; memory ownership requires one complete owner matching the file owner |
| A second owner is BSS-only/zero-`p_filesz`, or arithmetic/page rounding overflows | Reject before accepting the runtime identity |
| Adjacent half-open VMAs or valid RELRO splits have unique file and memory owners | Accept the mapping proof |
| Root/path component is a symlink, an entry is non-regular, or directory/entry/file/aggregate limit is exceeded | Reject before accepting or hashing an out-of-bound evidence tree |
| Required runtime, architecture, helper, or mapped file is unavailable | Fail the required lane; do not substitute another runtime or publish successful evidence |

No new product diagnostic code is introduced; these are evidence-validation
failures. A failed required identity or root scan must not be represented as a
successful handoff, behavior comparison, or runtime-evidence row.

### 5. Good/Base/Bad Cases

- Good: a partial rounded file-interval candidate is skipped when exactly one
  complete permission-compatible file owner with a consistent load bias
  remains; the independent page-rounded `p_memsz` proof then establishes that
  same unique owner. A fresh ordinary glibc run also retains native source and
  target identities, exact-root manifests, and passing source/transformed
  behavior. This remains a scoped glibc observation only.
- Base: an older glibc root without `runtimeIdentity` remains readable when the
  caller did not require the new carrier; if the carrier exists, it is still
  fully validated. Adjacent half-open mappings and valid RELRO splits remain
  acceptable only when each has unique complete owners in both domains.
- Bad: accept when only a partial file candidate exists, choose between two
  fully containing file candidates, allow any partial/multiple/BSS/VA-alias
  `p_memsz` owner, accept a self-reported runtime version without checking the
  retained libc/loader bytes, treat a local glibc pass as musl evidence, or
  convert missing musl tooling into a passing or `not-applicable` result.

### 6. Tests Required

- `native_process_identity_test.c` must keep its `-Werror` self-test for
  distinct-VA reuse of partially overlapping rounded file pages when one full
  file owner remains; permission excess; no complete file owner; and two full
  file-owner candidates that still reject. It must separately retain strict
  page-rounded `p_memsz` negatives for partial intersections, duplicate and
  file-disjoint virtual aliases, zero-file-size BSS overlap, checked memory-end
  and page-rounding overflow, plus adjacent half-open pages and a valid
  musl-shaped RELRO split.
- `tests/test_rehydration_evidence.py` must verify the matching Python
  file-candidate behavior (including conservative two-full-candidate refusal),
  strict memory-owner cases, exact schema/integer types,
  required-versus-optional historical glibc policy, mandatory musl identity,
  source/target agreement, retained-file/version/interpreter/maps binding,
  checksum-refreshed virtual-owner and overflow rejection, and adjacent-page
  acceptance. The standalone tree tests cover the exact 512-directory bound,
  the first over-limit directory before descent, and symlink root/path guards.
- Run focused evidence tests and full Python discovery without ambient
  `PYTHONPATH`; the loaders must use owned file-relative imports. Keep exact-root
  checker and SHA256SUMS verification separate from producer success. Current
  scoped review passed: ten C identity cases, four focused Python ownership
  cases, 29 provider-positive tests, eight rollback tests, and 487 Python tests
  with no skips; retained ordinary-glibc and provider-rollback exact roots also
  passed. The review found no blocking findings. The local musl E2E remains
  unrun because `musl-gcc` and a container runtime are unavailable; the hosted
  musl gate remains pending.

### 7. Wrong vs Correct

#### Wrong

```text
reject every partial rounded file-interval candidate even when another
complete owner uniquely contains the VMA
-> or skip a partial page-rounded p_memsz intersection / choose between two
   complete file candidates
-> trust a runtime label or self-reported version
```

#### Correct

```text
bind the handoff to its exact image and native process
-> for FILE ownership, skip partial candidates and require exactly one complete,
   permission-compatible owner with a consistent load bias
-> independently require exactly one full page-rounded VIRTUAL p_memsz owner
   for the complete VMA, identical to the file owner; reject partial, multiple,
   BSS, VA-alias and overflow cases
-> verify retained helper/libc/loader bytes, interpreter and maps identity
-> require the trusted runtime-specific identity policy and pass the closed-root
   checker before recording successful evidence
```

## Scenario: Native shared-table musl evidence

### 1. Scope / Trigger

Apply this evidence-only contract to the controlled shared signed-relative-32
jump-table HostContext slice when `scripts/run-shared-jump-table-copy-e2e.sh`
selects `--runtime musl`. It proves selected-consumer clone dispatch and
unselected-observer preservation for one native AArch64/musl fixture only. It
does not change ELF resolution, layout, Protected Image, Native Image, HostContext
ABI, or product CLI behavior; it does not promote shared-table support on musl,
other table encodings, Bionic, or general indirect control. The row remains
`unknown` / non-promoted. A passing hosted producer/checker gate permits retaining
this scoped observation only; promotion still requires explicit review of the
task-wide three-runtime acceptance criteria and remaining required gates.

### 2. Signatures

```sh
scripts/run-shared-jump-table-copy-e2e.sh --tier pr|nightly|release \
  --runtime musl \
  --unit runtime.indirect-control.shared-table.musl.host-context-entry \
  --artifact-root .artifacts/indirect-control/musl-<run>-<attempt>/shared

make -C native/urprotect-runtime \
  "CC=$(command -v musl-gcc)" "LD=ld" \
  HOST_ADAPTER_CFLAGS=-mno-outline-atomics \
  BUILD_DIR=build/musl-shared-jump-table \
  shared-jump-table-fixture host-context-image-handoff

python3 scripts/check-rehydration-evidence.py ROOT \
  --tier pr|nightly|release --runtime musl \
  --unit runtime.indirect-control.shared-table.musl.host-context-entry \
  --require-runtime-identity
python3 scripts/check-shared-jump-table-evidence.py ROOT \
  --runtime musl \
  --unit runtime.indirect-control.shared-table.musl.host-context-entry \
  --selected-function dynsym:<urp_entry-index>
```

### 3. Contracts

- Use a fresh run-specific evidence root under
  `.artifacts/indirect-control/`; refuse a pre-existing root. Build the shared
  fixture and HostContext helper with a distinct `build/musl-shared-jump-table`
  directory, selected `musl-gcc` as `CC`, direct `LD=ld`, and
  `HOST_ADAPTER_CFLAGS=-mno-outline-atomics` only for `host_adapter.o`. Do not
  share that build directory with an independent Make process.
- The outer Make sidecars are `<run-root>/native-build.command.txt`,
  `native-build.stdout`, `native-build.stderr`, and numeric `native-build.status`.
  On failure, preserve them, propagate the exact Make status, and stop before
  `readelf`, handoff, or positive-evidence checks. The nested HostContext build
  sidecars are outside the positive unit root but inside the run root at
  `<run-root>/<unit>.native-build-diagnostics/host-context-image-handoff/` with
  the same command/stdout/stderr/status set. Upload both roots even on failure.
- A successful positive root contains measured selected `urp_entry` source and
  transformed handoffs plus measured unselected `urp_observer` source and
  transformed handoffs. It retains source and Native Image bytes, process exit
  statuses, stdout/stderr bytes, `shared-table-behavior.json`, and a closed
  `SHA256SUMS` manifest. The independent checker reparses source and output
  ELF, verifies every declared table target was selected in the retained
  execution, proves the selected consumer reads the distinct PF_R-only clone,
  and proves the observer and original source table remain unchanged.
- Musl mode requires independently checked native runtime identity on all four
  handoffs: selected source (`role=source`, source-image digest), selected
  transformed (`role=target`, Native Image digest), observer source, and
  observer transformed. Bind each identity to its own process, image, helper,
  loader/interpreter, mapped files, maps, and retained bytes. All four must
  independently identify the expected pinned musl runtime, and their common
  runtime family/version/interpreter/helper/libc/loader identity must agree.
  Retain separate role/image bindings; do not require the four process IDs or
  image digests to be equal.
- The shared checker scans a bounded no-follow evidence tree before reading,
  hashing, or allocating; file reads are descriptor-anchored and bounded by
  the preflight snapshot. It loads `evidence_load_range.py`,
  `check-rehydration-evidence.py`, and `native_runtime_identity.py` through
  explicit sibling-file `O_NOFOLLOW | O_NONBLOCK` bounded reads, never ambient
  `PYTHONPATH`; a replaced FIFO is rejected without blocking. ELF symbol
  projection is additionally limited to 16,384 total records, a 4 KiB maximum
  decoded name, and 4 MiB aggregate decoded name bytes; search for each
  terminator is bounded to the per-name limit and symbol entries are unpacked
  without copying an entire table. It checks the tree remains unchanged through
  validation and requires the manifest to name exactly the preflighted files
  other than itself. In musl mode it requires identities regardless of whether
  a mutable evidence JSON field requests them; glibc's historical optional-
  identity rule remains separate.
- `--runtime` and the musl unit are evidence-runner/checker selectors only.
  Missing `musl-gcc`, wrong host architecture, build failure, identity mismatch,
  missing handoff, tree mutation, or checker failure is a required-lane failure,
  not a skipped/pass result. Neither a green local glibc row nor fixture
  presence substitutes for the hosted native musl gate.

### 4. Validation & Error Matrix

| Condition | Required result |
|---|---|
| Musl compiler/toolchain or native AArch64 runtime is unavailable | Explicit environment failure; no positive evidence or compatibility promotion |
| Outer or nested Make fails | Preserve exact command, cwd/runtime, both streams and numeric status; propagate status and stop before positive checks |
| Any of the four handoffs lacks identity or binds the wrong role/image/runtime | Reject at that handoff; do not let the first missing record mask untested consumers |
| Handoffs independently validate but runtime identities disagree | Reject the evidence root |
| Root/path contains symlink, non-regular entry, exceeds tree/read limit, or changes after preflight | Reject before accepting success |
| Manifest omits, duplicates, forges, or adds a path outside the preflighted tree | Reject the closed evidence root |
| Selected consumer does not read the distinct read-only clone, observer changes, or one target is not executed | Reject the positive evidence |
| All four identity proofs, table/reference/target proofs, process results and exact-root checks pass on the pinned hosted lane | Retain scoped observation only; do not promote automatically; keep runtime/feature status unknown pending review of the task-wide compatibility criteria and remaining required runtime gates |

### 5. Good / Base / Bad Cases

- Good: a fresh AArch64/musl job builds with the pinned `musl-gcc` configuration,
  retains outer and nested build provenance, executes all four measured handoffs,
  proves the selected clone and unchanged observer, and passes both exact-root
  checkers.
- Base: native AArch64/glibc shared-table evidence remains its separate row and
  historical evidence shape; musl identity is never inferred from the glibc
  host or from a container tag.
- Bad: silently skip for missing musl tooling, re-use the glibc build directory,
  run only the selected consumer, accept three of four identity records, trust
  self-reported JSON without parsing retained maps/ELFs, read mutable files by
  path after tree preflight, or call a local observation `validated` support.

### 6. Tests Required

- `tests/test_shared_jump_table_evidence.py` checks the selected and both
  observer handoffs, missing identity individually for all four, each role/image
  mutation, cross-handoff runtime mismatch, exact root, symlink rejection,
  preflight/read mutation, `os.replace()` file replacement, root replacement,
  refreshed-manifest tampering, and symbol-record/name-byte budget boundaries.
- `tests/test_regression_matrix.py` requires the separate musl row, its exact
  command/unit/runtime, native AArch64-container platform and budget, all four
  identity witnesses, and outer/nested build-diagnostic artifacts.
- `tests/test_protected_image_workflow.py` ties the CI step to the musl runner,
  explicit runtime/unit, `--require-runtime-identity` rehydration checker and
  shared-table checker. `tests/test_rehydration_evidence.py` covers scoped
  musl compiler/linker/adapter-only flags and retained/propagated nested build
  failure behavior.
- Run `PYTHONPATH= python3 -m unittest discover -s tests`, the focused shared,
  rehydration, matrix, and workflow tests, JSON/regression-matrix validation,
  shell syntax checks, `git diff --check`, and the separate native glibc
  regression. Native musl execution and exact-root validation must run in the
  pinned hosted AArch64 job; absence of a local toolchain is not a test pass.

### 7. Wrong vs Correct

```text
Wrong: infer musl from an OCI label, validate only the selected source identity,
       then treat three missing observer/transformed identities as acceptable.
Correct: bind every measured handoff to its exact image and pinned native musl
         identity, compare the shared runtime identities while preserving each
         process/role/image binding, and pass the closed-root checker on the
         hosted AArch64/musl job before recording the scoped observation.
```
