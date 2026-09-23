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
- Unknown ABI versions, truncated tables, missing mandatory capabilities, and
  null mandatory callbacks fail closed before payload dispatch.

#### Frame and ELF

- Frame version, architecture, `ET_DYN` identity, bounds, encoded digest,
  exact decompression size, and source digest are checked before loading.
- AArch64 program headers and `LoadMap` define runtime layout; section headers
  may be absent. Unknown relocation or lifecycle semantics remain `unknown` or
  `rejected` until an invariant and oracle exist. The first native adapter
  slice accepts only checked `RELATIVE`/`RELR` targets, permits only immediate
  binding dynamic flags, and delegates relocation application to the system
  loader.
- The constructor/destructor lifecycle boundary is the rejected feature row
  `runtime.host-context.constructor-destructor`. The first native adapter
  rejects `DT_INIT`, `DT_FINI`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY`,
  `DT_INIT_ARRAYSZ`, `DT_FINI_ARRAYSZ`, `DT_PREINIT_ARRAY`, and
  `DT_PREINIT_ARRAYSZ` with `URP_STATUS_UNSUPPORTED` before constructor or
  destructor execution and image-handle creation. HostContext v1 and the
  current system-loader adapter define no constructor/destructor ordering,
  callback or reentrancy behavior, teardown, or lifecycle ownership semantics.
  The native self-test mutates one bounded `DT_NULL` tag at a time, preserves
  surrounding bytes, initializes a nonzero sentinel, and requires a zero
  output handle.
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
- Unsupported dynamic relocation-table tags are an independently rejected
  HostContext v1 feature recorded as
  `runtime.host-context.unsupported-relocation-table`. It covers `DT_REL`,
  `DT_RELSZ`, `DT_RELENT`, `DT_JMPREL`, `DT_PLTRELSZ`, and `DT_PLTREL`; the
  current system-loader contract defines only the checked AArch64
  `RELATIVE`/`RELR` path, so these forms are rejected before relocation
  processing or image-handle creation. The native self-test mutates one
  bounded `DT_NULL` tag at a time, preserves surrounding bytes, initializes a
  nonzero sentinel, and requires `URP_STATUS_UNSUPPORTED` with a zero output
  handle. The unchanged `RELATIVE`/`RELR` fixture remains the positive
  baseline; no broader relocation-table support is claimed.
- A validated adapter image may retain a non-empty `PT_GNU_RELRO` file range
  when that range is inside the image and `p_memsz >= p_filesz`; the real
  adapter must still dispatch the entry. The native system loader owns the
  resulting memory protection semantics, so this row is implementation
  evidence rather than proof of a custom RELRO loader.
- The first native adapter accepts `PT_GNU_STACK` only when `PF_X` is clear;
  an executable-stack request returns `URP_STATUS_UNSUPPORTED` before an
  image handle is created. Protection semantics for the accepted
  non-executable case remain delegated to the native system loader.
- `PT_TLS` is an explicit rejected feature row
  (`runtime.host-context.pt-tls`). HostContext v1 does not define TLS module
  allocation, per-thread initialization, TLS relocation models, thread
  creation/reentrancy, or TLS teardown relative to `release_image`. The adapter
  therefore returns `URP_STATUS_UNSUPPORTED` before `dlopen` for a structurally
  bounded PT_TLS mutation; a paired mutation with `p_filesz > p_memsz` returns
  `URP_STATUS_LOAD_FAILED`. Generic program-header range, file/memory-size,
  alignment, and congruence checks still run before rejection. The adapter
  clears the output handle before validation and leaves it zero on every
  failure path. The self-test's
  unchanged entry fixture is only the positive non-TLS HostContext baseline; no
  positive TLS fixture or support claim exists.
- `PT_GNU_PROPERTY` is a separate rejected feature row
  (`runtime.host-context.gnu-property`). HostContext v1 and the current
  system-loader adapter define no property negotiation or BTI/PAC/instruction-
  state obligations, so acceptance of a property note by `dlopen` alone does
  not establish support. The self-test keeps the unchanged entry image as the
  positive baseline, changes only a bounded PT_LOAD-covered metadata program
  header type to `PT_GNU_PROPERTY`, and requires `URP_STATUS_UNSUPPORTED` with
  a zero image handle before loader handoff.
  `runtime.host-context.dependency-resolution` is a separate rejected
  boundary for `DT_NEEDED`, `DT_AUXILIARY`, and `DT_FILTER`: HostContext v1
  and the current system-loader adapter define no dependency-resolution,
  search-path, symbol-scope, or dependency-lifetime semantics, so a loader
  that can resolve a library does not establish support. The bounded mutations
  keep the unchanged non-dependency entry fixture as the positive baseline and
  require a zero image handle before loader handoff.
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
- The production managed pack path intentionally emits legacy frame v1 for
  the legacy launcher. `runtime.host-context.production-pack` is an explicit
  `unknown` migration boundary until the missing HostContext entry-image
  adapter, v2-capable launcher, and managed pack/dispatch oracle are retained;
  no v2 frame may be forced into the legacy path.
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
container kernel/page-size facts, refuse AVD, Waydroid, QEMU, native bridge,
and non-ARM execution rather than silently falling back, and keep both the
bionic HostContext handoff and production package oracle rows `unknown` until
their dedicated sealed-image/managed-pack oracles are retained. The concrete
next evidence is a v2 HostContext entry image executed through the bionic
adapter with sealed-image and no-fallback artifacts.

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
