# Design: AArch64 ELF Compatibility and Runtime Semantics

## 1. Design goal

Build a single current AArch64 packaging contract that can carry explicitly
selected execution profiles while keeping the two fundamentally different
launch semantics honest:

```text
outer-execveat
    standalone AArch64 PIE
    -> verified bytes in anonymous memfd
    -> execveat(AT_EMPTY_PATH)
    -> kernel/native interpreter starts the original image

host-context-entry
    declared AArch64 ET_DYN entry image
    -> verified bytes in sealed anonymous memfd
    -> HostContext adapter loads through the system loader
    -> lookup declared entry symbol
    -> call urp_entry once
    -> release image
```

The design deliberately avoids presenting these as one loader algorithm. They
share a versioned packaging envelope and evidence vocabulary, while each
profile owns its image contract, launcher/adapter ABI, and runtime oracle.

## 2. Current baseline

The repository already contains the following evidence and implementation
boundaries:

- Managed `PayloadFrameCodec` encodes legacy frame v1 and HostContext frame v2.
- Native `runtime.c` parses both existing frame versions and dispatches a
  HostContext entry through `urp_runtime_execute_frame`.
- `host_adapter.c` performs sealed-memfd `dlopen`/`dlsym` loading for a narrow
  AArch64 ET_DYN slice.
- `urprotect-launcher/launcher_main.c` implements the legacy outer
  `execveat` handoff and carries the v1 launcher marker.
- `ElfPackService` currently validates a standalone PIE with a supported
  interpreter and emits the legacy frame to the static launcher.
- The production managed HostContext pack row remains `unknown`; the native
  HostContext self-test and bionic adapter evidence do not upgrade it.

The design therefore treats P0 as a real cross-layer contract cut, not as a
small option added to the existing legacy pack call.

## 3. Contract decisions

### 3.1 Architecture and evolution

- Product scope is AArch64/ARM64 only.
- The project is 0.x and accepts coordinated breaking changes.
- A frame, HostContext, launcher, CLI, report, or fixture contract changes only
  when all producers, consumers, tests, and evidence declarations change in the
  same phase.
- Old frames and stale launcher/profile combinations fail with a stable
  version or unsupported result. There is no implicit compatibility fallback.

### 3.2 One packaging contract, explicit profiles

The current packaging contract carries a dispatch profile. P0 should introduce
the next frame version rather than overload the meaning of the existing v1/v2
formats; the working recommendation is a new v3 envelope with an explicit
profile field. The exact field offsets and reserved bytes belong to the P0
contract owner and must be generated into the managed/native layout checks.

The current envelope must represent, at minimum:

- frame version and header size;
- dispatch profile;
- AArch64 ELF identity and declared file kind;
- source name, source size, encoded size, and encoded offset;
- source and encoded SHA-256 digests;
- compression identifier;
- HostContext ABI version, required capabilities, and entry name when the
  profile is `host-context-entry`;
- zero-valued reserved fields and bounded strict UTF-8 names.

`outer-execveat` and `host-context-entry` are mutually exclusive profile values.
Profile-specific metadata is invalid when supplied to the wrong profile.

### 3.3 Profile contracts

#### `outer-execveat`

- Input: a packable standalone AArch64 ELF64 PIE with a declared interpreter.
- Launcher: a static AArch64 launcher whose marker and ABI version match the
  current frame contract.
- Handoff: verify frame and source ELF, write source bytes to an anonymous
  memfd, preserve argv[0]/argv/envp, and call `execveat(AT_EMPTY_PATH)`.
- Source bytes are never published as an executable temporary pathname.
- The kernel and declared native interpreter remain responsible for the source
  image's dynamic loading and process entry semantics.

#### `host-context-entry`

- Input: a declared AArch64 ELF64 `ET_DYN` entry image exposing the frame's
  bounded entry symbol, initially `urp_entry`.
- Adapter: a profile-matched HostContext adapter with ABI version, capability,
  immutable-image, symbol-lookup, and release checks.
- Handoff: verify frame and source digest, write bytes to a sealing-enabled
  memfd, add and verify the required seals, load through the adapter, resolve
  the entry symbol, dispatch exactly once, release the image, and preserve the
  returned status.
- The first accepted slice continues to reject dependencies, lifecycle tags,
  TLS, GNU property semantics, unsupported relocation tables, and other forms
  until the later phase defines and proves them.

### 3.4 Compatibility layers

Every matrix feature is assigned to exactly the layer it proves:

1. parser/model: bounded AArch64 ELF representation and validation;
2. outer wrapper: baseline/wrapped behavior through the native interpreter;
3. HostContext: in-process image loading, symbol lookup, entry, and release;
4. runtime fact: a retained result for glibc, musl, bionic, or another named
   AArch64 environment.

A lower-layer result never upgrades a higher-layer feature. A successful
`dlopen` is not dependency, TLS, constructor, GNU property, or symbol-version
support until the corresponding HostContext semantics and oracle exist.

## 4. Cross-layer data flow

```text
CLI pack options
    -> profile-specific input validation
    -> read source + profile launcher/adapter metadata
    -> encode current frame
    -> validate wrapper ELF and frame round-trip
    -> atomic publish
    -> profile launcher discovers its frame
    -> verify frame, encoded digest, decompressed size, source digest
    -> profile dispatch
    -> status/report/evidence artifact
```

Contract owners:

| Boundary | Owner | Required consumers |
| --- | --- | --- |
| Current frame layout | managed `PayloadFrameCodec` plus native `payload_frame.h` | packer, launcher/runtime, layout tests, contract probe |
| HostContext ABI | `HostContextContract.cs` plus `host_context.h` | managed metadata, native runtime, adapter, entry fixture |
| Profile/launcher match | `LauncherContract.cs` plus native marker/header | CLI pack, launcher, profile tests |
| ELF acceptance | `ElfTypes`, `ElfParser`, `ElfValidator`, `LoadMap` | pack profiles, HostContext adapter, fixture oracles |
| Evidence claim | `fixtures/manifest.json` and `COMPATIBILITY.md` | fixture scripts, evidence gate, rendered matrix |

Validation belongs at the earliest boundary that owns the invariant. The
runtime repeats security-critical frame and digest checks because it receives
untrusted wrapper bytes; it does not rely on managed validation having run.

## 5. Phase architecture

### P0 — Current contract cut

P0 owns the frame/profile model, profile-specific pack selection, launcher
matching, managed end-to-end oracles, and removal of implicit legacy behavior.
It must settle the v3 layout recommendation, stable profile diagnostics, and
the exact accepted HostContext entry-image input contract.

### P1 — Outer wrapper expansion

P1 extends only the `outer-execveat` acceptance and evidence boundary. It may
add static PIE, static ET_EXEC, or other input classes only when the launcher
and execution oracle define how they start. Shared objects remain a separate
declared entry-image concern.

### P2 — Relocation and symbol semantics

P2 extends the `host-context-entry` adapter contract in a priority order. Each
relocation family gets model rules, writable-target checks, symbol scope and
binding rules, positive fixtures, negative mutations, and runtime evidence.

### P3 — Dependency, path, and lifecycle semantics

P3 defines dependency ownership and path search before enabling `DT_NEEDED`,
RPATH/RUNPATH, or constructors/destructors. The implementation must be
deterministic under explicit roots and must define rollback and release order.

### P4-A — TLS semantics

P4-A defines TLS module/thread ownership, relocation models, thread creation and
teardown, reentrancy, and unload safety. It requires concurrent fixtures, not
only static metadata mutations.

### P4-B — GNU property semantics

P4-B defines the bounded AArch64 GNU property subset, including BTI/PAC and
instruction-state obligations, before accepting property-bearing images.

P4-A and P4-B may be designed in parallel after P3, but each has an independent
runtime oracle and matrix row.

## 6. Evidence and operational design

Each accepted feature requires:

1. a named contract owner;
2. a positive real or synthetic fixture;
3. a paired malformed or unsupported boundary;
4. a deterministic oracle at the claimed execution layer;
5. retained logs, hashes, toolchain/runtime facts, and CI evidence paths;
6. a manifest row whose status is `proven` or `validated` only after the
   evidence gate passes.

`unknown` means the obligation remains open. `rejected` means the boundary is
deliberately fail-closed. Neither status counts as support.

## 7. Rollout and rollback

- Implement one child phase at a time; the parent remains in planning until all
  child plans are reviewed.
- A phase publishes no new matrix support row until its full oracle and evidence
  postcondition passes.
- A failed phase rolls back its contract and source changes together, or keeps
  the feature explicitly rejected/unknown. Partial frame/profile behavior is
  never silently retained.
- The old v1/v2 paths may remain in historical tests/artifacts during P0, but
  the final current launcher and packer must have one explicit version/profile
  selection path.

## 8. Main trade-offs

| Choice | Decision | Reason |
| --- | --- | --- |
| One universal execution algorithm vs profiles | Explicit profiles | `execveat` and HostContext have different loader/lifetime contracts and runtime dependencies. |
| Reuse v2 offsets vs new current frame version | New current version, recommended v3 | Adding profile semantics without a version boundary would make old v2 interpretation ambiguous. |
| Custom in-process loader vs system loader | System loader behind a declared adapter | Keeps the project focused on contract validation and evidence instead of recreating the dynamic linker. |
| Broad whitelist vs feature evidence | Feature-covering matrix | Prevents a loader anecdote from becoming a compatibility claim. |
| Cross-architecture abstraction vs deep AArch64 rules | AArch64-only | Maximizes ABI, relocation, runtime, and fixture depth during 0.x. |
