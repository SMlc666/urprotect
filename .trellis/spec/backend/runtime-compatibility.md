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
During migration, an older path may remain as explicitly named historical
evidence, but new packaging must not select it silently and the compatibility
matrix must not count it as current support. A stale version or profile/
launcher mismatch must produce a clear version or unsupported result.

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

`urp_host_context_v1` is version `1`, requires a declared size of at least
`56` bytes, and requires `load_image`, `lookup_symbol`, and
`release_image` capabilities. `urp_launch_args_v1` is version `1` with a
minimum declared size of `32` bytes. The legacy payload frame is v1; the
HostContext frame is v2 and adds the ABI version, required capability bits,
and a bounded UTF-8 entry-symbol name to the common 112-byte header. The v2
header is 136 bytes and uses a frame-relative encoded offset because the
standalone runtime receives the frame slice directly. Legacy v1 retains its
wrapper-absolute encoded offset for the existing launcher.

The legacy managed/native standalone handoff retains its v1 sequence:

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
  path ends in a recognized AArch64 glibc or musl loader name, and no
  `DT_RPATH` or `DT_RUNPATH`.
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
  validated runtime cell is native AArch64 glibc; accepting a musl interpreter
  path is not a musl runtime claim without its own native oracle and retained
  evidence.

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
  image; legacy v1 defaults to `urp_entry` and HostContext v2 carries the
  bounded symbol name explicitly.
- `urp_entry` is called at most once per successful frame execution.
- The runtime releases the image after entry dispatch, including a nonzero
  entry status. Host callbacks must not be invoked after release returns.
- The optional thread-lifetime capability appends `create_image_thread` and
  `join_image_thread` at offsets 56 and 64 (72-byte current table); the 56-byte
  legacy minimum remains valid. The capability requires both appended fields
  and callbacks. Launch args retain their 32-byte legacy minimum and append
  the opaque image handle at offset 32 (40-byte current view). Runtime
  projection copies only caller-declared legacy bytes and supplies the active
  image handle to entry.
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
- The same `libc.so.6` dependency slice accepts only import-side GNU
  version requirements recorded as
  `runtime.host-context.dependency-symbol-version-requirements`: `DT_GNU_HASH`
  is required, SysV `DT_HASH` and `DT_SYMBOLIC` are rejected, and `DT_VERSYM`, `DT_VERNEED`, and
  `DT_VERNEEDNUM` must be complete; the bounded `Verneed` and
  `Vernaux` chains must terminate at their declared counts, all version names
  and hashes/indices must be valid, and every `vn_file` must exactly match the
  `DT_NEEDED` basename `libc.so.6`. Weak-version requirement flags and version
  requirements attached to recognized musl/bionic sonames are rejected. Native
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
  The first slice accepts structurally bounded AArch64 initial-exec TLS with
  `R_AARCH64_TLS_TPREL64`; the system loader owns per-thread module allocation
  and initializes the `p_filesz` template plus zero-fill through `p_memsz`. The
  retained current-thread oracle returns status 43 on native glibc.
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
  exercises concurrent independent dispatches. Dynamic/general-dynamic,
  local-dynamic, TLSDESC, unmanaged workers, recursive worker dispatch, and
  musl/bionic threaded claims remain outside scope; malformed TLS and
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
  markers are validated before frame encoding and stale v1/v2 behavior remains
  migration evidence only. `runtime.host-context.production-pack` is validated
  by the retained managed HostContext pack/dispatch oracle on the native
  AArch64 glibc lane.
- `runtime.wrapper-v1-baseline` keeps Wrapper 0.2 framing and launcher tests as
  migration evidence only; the Android `android.jni.native-bridge` row is an
  unwrapped JNI baseline. Neither row upgrades HostContext runtime support.

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
container kernel/page-size facts and refuse AVD, Waydroid, QEMU, native bridge,
and non-ARM execution rather than silently falling back. The bionic lane now
builds and runs the native HostContext self-test: a current HostContext frame
exercises the real bionic adapter, verifies required memfd seals, dispatches
the entry, releases the image, and retains its log and fixture ELF. This makes
only `runtime.host-context.bionic-handoff` validated for that adapter slice.
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
- Base: a standalone PIE passes parser and legacy wrapper checks but lacks the
  HostContext entry contract; report it as parser/legacy evidence, not as an
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

The locked corpus contains exactly 20 distinct upstream identities. Every pull
request runs the full set, including provenance/hash verification, static
fingerprint, and UrProtect JSON validation. Nightly and release reuse the same
set and runner; they may repeat or retain more evidence but never replace PR
coverage with a subset. Runtime/build/libc variants do not add identities.

The CI fingerprint is authoritative for observed facts. The registry locks and
compares only ELF64, little-endian, AArch64, `ET_DYN`, and the declared
interpreter invariants. Relocation/RELR/PLT details, symbol versions, TLS, GNU
properties, RELRO, GNU_STACK, stripped state, dependencies, file size, and
feature tags are emitted by the bounded CI `readelf` inspection and retained
as evidence rather than guessed support claims. Hash drift stops acquisition
before extraction or execution.

Layer policy uses the fixed result vocabulary
`accepted-and-runs`, `expected-rejected`, `unexpected-rejection`,
`unexpected-acceptance`, `runtime-failure`, `environment-unavailable`, and
`not-applicable`. Static evidence is required for all projects. An applicable
baseline/outer/HostContext oracle runs with network disabled, read-only inputs,
a bounded temporary filesystem, dropped capabilities, resource/time/output
limits, and cleanup. A normal ELF without the declared `urp_entry` ABI is
`not-applicable` to HostContext; loader acceptance is not HostContext proof.
The current BusyBox Alpine record is the explicit musl baseline: its policy
command must name the extracted `/bin/busybox` artifact and runs only inside
its archive-derived rootfs, never through a host fallback.

For future compatibility work, the plan must include a real-sample impact table
(project IDs, feature, layer, oracle, expected classification, and artifact
path). An unexpected result blocks completion. Support expansion additionally
requires real observation, controlled positive and nearest-negative fixtures,
stable diagnostics, and synchronized contract, documentation, and evidence
updates. Real-sample count is ecology evidence and cannot substitute for a
feature invariant or controlled negative boundary.
