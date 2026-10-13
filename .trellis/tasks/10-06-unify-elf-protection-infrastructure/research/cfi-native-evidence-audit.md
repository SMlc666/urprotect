# CFI Native Evidence Audit

## Result

The archived CFI child deliberately leaves transformed native behavior unpromoted. Its PRD requires backtrace/unwind, exception propagation, cancellation/signal unwind, and transformed register/frame state, but also records that the dedicated glibc, musl, and bionic rows are not promoted until native fixtures exist (`.trellis/tasks/archive/2026-10/10-06-cfi-unwind-rewriter/prd.md:7-25`). The design assigns execution evidence to native scripts/fixtures and requires separate runtime rows (`.../design.md:12-16,122-142`). The parent still has the CFI runtime criterion open and calls the native rows out as unfinished (`.trellis/tasks/10-06-unify-elf-protection-infrastructure/prd.md:84-97`).

There is no existing native transformed-image fixture that proves CFI behavior. The smallest reusable base is the existing HostContext entry shared object, not the synthetic managed ELF fixture:

- Source: `native/urprotect-runtime/host_context_entry_fixture.c:1-20`.
- Build: `native/urprotect-runtime/Makefile:167-170,269-272`; the linker emits `--eh-frame-hdr`.
- Current generated image observed with `aarch64-linux-gnu-readelf -hW -SW -lW --debug-dump=frames native/urprotect-runtime/build/host-context-entry-fixture.so`: AArch64 `ET_DYN`, `.eh_frame_hdr` and `.eh_frame`, and two FDEs covering the small text ranges `0x280..0x288` and `0x288..0x2c0`.
- Current handoff: `scripts/run-host-context-rehydration-e2e.sh:80-123` selects `urp_transform_target` for protection but invokes `urp_entry` in the native handoff. The fixture's `urp_entry` only validates arguments and returns a global value (`host_context_entry_fixture.c:12-20`).
- Current oracle: `scripts/run-host-context-rehydration-e2e.sh:158-215` records entry status, empty streams, hashes, and release order. `scripts/check-rehydration-evidence.py:427-470` checks status/stream/hash equivalence; it has no backtrace, CFI register, frame, exception, or cancellation field.

Thus this existing image is the right smallest base for a future row, but it is not evidence of transformed unwind behavior today. A minimal proof needs a native probe path that executes the selected transformed function while an unwind is captured, plus a producer/re-hydrator path that actually changes its FDE.

## Current CFI Path

### Parser and model

`UnwindMetadataParser.Parse` locates `.eh_frame` and optionally `.eh_frame_hdr` through section names (`src/UrProtect.Core/UnwindMetadata/UnwindMetadataParser.cs:10-67`). A missing `.eh_frame` produces `UnwindMetadataUnavailable` (`:15-22`); sectionless images therefore do not enter the current CFI rewrite path. Bounded record lengths, CIE/FDE references, augmentation data, common CFA instructions, and `.eh_frame_hdr` table bounds are parsed (`:172-269,328-460,462-547,549-743,759-879`). The parser retains unsupported opcodes as opaque data with a warning, but a selected FDE containing one is rejected by the rewriter.

The current managed fixture is synthetic: `tests/UrProtect.Core.Tests/UnwindMetadata/UnwindMetadataParserTests.cs:118-218` constructs bytes in memory, and `UnwindMetadataRewriterTests.cs:15-225` tests identity, a same-size relocated range, a same-width CFI replacement, layout ownership, and fail-closed diagnostics. These tests prove parser/layout mechanics only. They do not launch an AArch64 transformed image or ask a native unwinder for a frame.

### Rewriter limits that block the first native proof

`UnwindMetadataRewriter.Rewrite` only transforms FDEs whose mapped output range has the same size as the source (`src/UrProtect.Core/UnwindMetadata/UnwindMetadataRewriter.cs:56-131`, especially `:85-91`). That is incompatible with the current transformations: register permutation emits an entry swap and a return swap (`src/UrProtect.Core/Application/Protection/FunctionProtectionCodeEmitter.cs:496-528`), while flattening adds state/dispatcher code (`:533-700`). A real FDE covering either transformed function will normally have a larger output range and receive `UnwindMetadataUnsupported` before publication.

The rewriter also keeps `.eh_frame` record length fixed (`UnwindMetadataRewriter.cs:219-235`), requires fixed-width header/FDE encodings (`:301-365`), and only encodes `nop` or `cfa=sp+N` effects (`:536-563`). It does not yet generate full prologue/epilogue rules for a transformed frame, dispatcher, veneer, or register permutation. The design requirement to emit generated CFI is therefore ahead of the current implementation (`.../design.md:88-106`).

### Missing producer-to-rewriter link

The most direct current gap is before rehydration:

1. `FunctionProtectionService.Plan` calls `BuildTlsSemanticSnapshot` (`src/UrProtect.Core/Application/Protection/FunctionProtectionPlanning.cs:45-65`).
2. That method only visits selected functions with TLS relocation facts (`:142-145`), creates TLS bindings, and returns null when no bindings were found (`:514-547`). It never constructs a `SemanticCfiEffectExtension`; the only production construction found by repository search is snapshot decoding (`src/UrProtect.Core/SemanticPlanning/SemanticPlanSnapshotDecoding.cs:1078`).
3. `GenericRehydrationEngine.BuildUnwindEdits` returns no edits when the snapshot is null or contains no CFI effects (`src/UrProtect.Core/Application/Rehydration/GenericRehydrationEngine.cs:710-737`). The ordinary non-TLS protection fixture therefore skips CFI rewriting even when its ELF has FDEs.
4. If CFI edits do exist, they do flow through the shared layout owner: the planner bounds and validates typed unwind edits (`src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs:35-95,1224-1267`), the plan/evidence carry `UnwindEdits` (`src/UrProtect.Core/ElfLayout/ElfLayoutContracts.cs:345-380`), and materialization applies, reparses, and byte-validates them (`src/UrProtect.Core/ElfLayout/ElfLayoutMaterializer.cs:63-112,1578-1593`). This is structural/layout evidence, not behavior evidence.

The snapshot codec and validator do support a project-owned CFI extension (`src/UrProtect.Core/SemanticPlanning/SemanticPlanExtensions.cs:70-103`, `SemanticPlanSnapshotEncoding.cs:378`, `SemanticPlanSnapshotValidation.cs:624`), but current protection planning does not populate it for a normal transformed function. This is the smallest real implementation link missing before a native behavior row can be meaningful.

## Native Fixture Inventory

### Closest transformed fixture: HostContext entry image

`native/urprotect-runtime/host_context_entry_fixture.c` is preferable to the existing managed `GccShapedElf` because it is compiler/linker-produced AArch64, has `.eh_frame`/`.eh_frame_hdr`, and is already consumed by the Protected Image and Native Image workflows. The Makefile explicitly links it with `--eh-frame-hdr` (`native/urprotect-runtime/Makefile:167-170`). The current built image's FDEs are tiny and contain `DW_CFA_nop` rules, so it is a good first bounded fixture after adding an actual frame and unwind capture.

Current limitations:

- `urp_transform_target` is selected by the HostContext runner but never called by `host_context_image_handoff`; only `urp_entry` is looked up and invoked (`scripts/run-host-context-rehydration-e2e.sh:80-123`, `native/urprotect-runtime/host_context_image_handoff.c:160-185`).
- `urp_entry` has no call chain, frame marker, signal interruption, or unwind output (`host_context_entry_fixture.c:12-20`).
- The HostContext `Makefile:test` target checks status 23 and release (`native/urprotect-runtime/Makefile:117-125`), not the selected function's behavior or frames.
- The bionic lane builds the same simple C entry and `target.S`, then checks direct/linker status and streams (`scripts/run-bionic-fixture.sh:254-267,339-354`); it has no CFI oracle.

### Existing protection fixture

`fixtures/samples/protection/main.c:4-18` and `target.S:1-23` are the smallest existing executable transformation fixture. `scripts/run-protection-e2e.sh:91-123` builds it natively for glibc or musl, and `:139-197` runs register permutation, flattening, and combined transforms against a baseline while comparing status/stdout/stderr and retaining hashes. The assembly is leaf code with no `.cfi_startproc`/`.cfi_*` directives (`target.S:1-23`). The script never inspects or executes unwind behavior. `scripts/check-protection-evidence.py:23-80` validates only selected-function/pass fields, exit status, hashes, and readelf output.

This is the best executable harness to extend for a first outer-execveat row, but the HostContext shared object is the smaller existing image with a known `.eh_frame_hdr` and an existing rehydration handoff. Do not treat either current path as a CFI behavior witness.

### Other current fixtures are not CFI behavior fixtures

- `fixtures/samples/cxx/main.cpp:1-16` is a checksum/output fixture. It has no throw/catch or exception oracle. `scripts/run-fixture-matrix.sh:231-245` builds C++ cases, but the generic runner compares process status/stdout/stderr only (`:84-196`).
- `fixtures/samples/c/outer_exec_probe.c:1-53` raises `SIGTERM` only as a process-termination probe (`:47-50`). Existing packed-fixture checks compare signal status and streams; they do not unwind a signal frame.
- `native/urprotect-runtime` has TLS/thread lifecycle fixtures, but their README explicitly scopes threaded claims to a glibc slice and does not mention unwind execution (`native/urprotect-runtime/README.md:32-44,54-110`).
- `fixtures/manifest.json` has runtime, loader, TLS, handoff, and protection rows (`:20-811`) but no `cfi`, `unwind`, `backtrace`, `exception`, or cancellation feature row. The CI feature checks likewise contain no CFI row (`.github/workflows/ci.yml:328-345`).

## Smallest Real Fixture Proposal

Use the existing HostContext entry shared object as the base and add one dedicated native probe mode. Keep the first row narrow: one transformed leaf/frame function, one native runtime, one unwind oracle. The fixture should contain:

1. `urp_transform_target` with a real AArch64 frame and retained CFI directives for `sp`, `x29`, `x30`, and any saved callee-saved register. It must still fit the selected-function transformation subset. The function should have a deterministic register/result contract and a bounded loop or other way to remain active while the harness captures an interrupted PC; adding a direct unwinder call inside the selected function would currently hit the direct-call rejection in `FunctionProtectionCodeEmitter.cs:328-357`.
2. `urp_entry` dispatch that actually executes `urp_transform_target`, or a dedicated exported probe symbol invoked by a new native handoff mode. The existing `urp_entry` status-only call is not enough.
3. A native AArch64 harness that runs the source image and transformed Native Image under the same loader, captures a backtrace while the selected function is active, and emits a bounded machine-readable record. A signal-interruption route is the smallest way to exercise a leaf transform without adding an unsupported call edge; a later call-based route should use `_Unwind_Backtrace`/libunwind from a helper and exercise full call-site CFI.
4. A caller-side register/frame check. Preserve and verify a callee-saved register and frame/return state, and verify the transformation's x9/x10 data result. The existing protection fixture already checks returned values (`main.c:9-18`), but it does not check a frame or an unwind register state.
5. Baseline and transformed records containing: status, stdout/stderr hashes, frame count, normalized PCs, selected-function identity/range, CFA/SP/FP/return-address observations where the unwinder exposes them, restored register values, source/protected/native SHA-256 values, `.eh_frame`/`.eh_frame_hdr` hashes and counts, toolchain/loader identity, and first-failure/publication status.

A practical first row can be named `runtime.cfi.transformed-backtrace-registers.glibc.outer-execveat` and remain glibc-only until the same fixture has independent musl and bionic runs. The row must bind the selected source function to the transformed address map and must show that the transformed FDE and header entry cover the actual PC observed by the native unwinder. A `readelf --debug-dump=frames` comparison alone is not sufficient.

### Required fixture build/inspection commands

These are the commands the future native row should retain, with paths adapted to its artifact root:

```sh
aarch64-linux-gnu-gcc -std=c11 -O0 -fPIE -pie -fno-omit-frame-pointer \
  -fasynchronous-unwind-tables -Wl,--build-id=none -Wl,--eh-frame-hdr \
  TARGET.c TARGET.S -o baseline

aarch64-linux-gnu-readelf -hW -SW -lW --debug-dump=frames baseline

# Run the same native probe against baseline and transformed Native Image.
timeout 30 ./unwind-probe baseline baseline-record.json
timeout 30 ./unwind-probe transformed-native-image transformed-record.json
```

The repository's existing producer/rehydrator commands to reuse are:

```sh
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc --profile host-context-entry
make -C native/urprotect-runtime test
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr --execution native-linux
```

No `run-cfi-*` command exists today. The new row needs a dedicated runner and checker; adding a CFI label to the existing process oracle would not establish unwind behavior.

## Behavior Requirements Beyond Backtrace

### Exception propagation

A separate exception row is needed; it should not be inferred from a backtrace row. Use a C++ fixture with a throw/catch boundary that crosses the transformed function and retain `.eh_frame`, `.eh_frame_hdr`, `.gcc_except_table`, personality, LSDA, call-site ranges, landing pads, and destructor ordering. Compare caught exception type/value, catch site, cleanup markers, status, and streams against baseline. The current C++ fixture is only checksum output (`fixtures/samples/cxx/main.cpp:1-16`), and the current emitter rejects ordinary direct calls (`FunctionProtectionCodeEmitter.cs:328-357`), so this requires both semantic call/exception-edge support and a native oracle.

### Cancellation

Use a pthread fixture with a cancellation point inside or across the transformed call chain, `pthread_cleanup_push`/`pthread_cleanup_pop` markers, a controlled canceller, and a join result. Retain cleanup order, cancellation result, frame/backtrace record if available, and no leaked worker/image state. This is distinct from the existing TLS worker lifecycle: `native/urprotect-runtime/README.md:32-44` covers worker join/TLS teardown, not cancellation unwind.

### Signals

The existing signal coverage is termination equivalence only. `fixtures/samples/c/outer_exec_probe.c:47-50` raises `SIGTERM`, and packed/runtime scripts compare the resulting status and streams. The CFI signal row needs an asynchronous signal while the transformed function is active, a bounded `sigaction`/alternate-stack setup, a native unwind/backtrace capture from the handler or a controlled post-handler unwinder, normalized interrupted PC/SP/FP, and baseline/transformed equality. Signal delivery and unwinding must be recorded independently from process termination.

## Runtime Matrix Requirements

The runtime registry already defines independent glibc, musl, and bionic cells (`fixtures/runtime-matrix.json:1-190`), but none is a CFI row.

- **glibc:** retain native AArch64 compiler/linker versions, loader path/version, kernel/page size, `libgcc_s`/unwind support used by the probe, source/protected/native hashes, and the full positive/negative behavior record. Current CI runs glibc protection and HostContext rehydration (`.github/workflows/ci.yml:78-139`) but no CFI probe.
- **musl:** use the pinned musl 1.2.4 toolchain/runtime from `scripts/install-runtime-musl-toolchain.sh` and the native/container lanes in `scripts/run-runtime-matrix.sh:105-183`. Record the actual unwinder implementation and C++ runtime if used; current installer/runtime commands cover `musl-gcc` and loader identity, not C++ exception or backtrace support. The current rehydration runner explicitly accepts glibc only (`scripts/run-rehydration-e2e.sh:35-48`), so transformed musl CFI needs its own profile-aware runner.
- **bionic:** run inside the pinned native arm64 Termux container with locked Clang/LLD packages and `/system/bin/linker64` (`scripts/run-bionic-fixture.sh:217-267`). Record libc++/libunwind package identity and linker flags, including the current `--pack-dyn-relocs=none` HostContext build setting. The existing bionic protection path builds `fixtures/samples/bionic/main.c` with `target.S` and checks only status/streams (`run-bionic-fixture.sh:254-256,339-354`); it does not prove bionic CFI. A bionic CFI row must be independently `validated` or `environment-unavailable`, never promoted from glibc or musl.

For all three runtimes, retain nearest negative cases: malformed `.eh_frame` length/CIE/header table, missing or sectionless metadata, unsupported CFI opcode/augmentation, missing address-map coverage, and a runtime-level failure (unwinder reports a frame mismatch or exception/cancellation result differs). Each negative must show no Native Image publication or no loader invocation as appropriate.

## Missing Links, Ordered

1. **Producer semantics:** construct CFI effects for the selected transformation, including generated prologue/epilogue, dispatcher, veneer, and register/frame rules; create a semantic snapshot for ordinary non-TLS transforms. Current `BuildTlsSemanticSnapshot` is TLS-gated and no production code constructs CFI effects.
2. **Variable-size CFI rewrite:** map source FDE instruction boundaries to generated offsets, emit new FDE rules and header entries, and coordinate section growth/relocation. Current rewriter requires unchanged FDE code size and unchanged `.eh_frame` section length.
3. **Actual transformed execution:** make the native handoff invoke the selected transformed symbol or an entry chain that reaches it. Current HostContext handoff selects one symbol for the producer but invokes `urp_entry` only.
4. **Native unwind oracle:** add backtrace/register/frame records and compare them to baseline; process status/stdout/stderr comparison is not enough.
5. **Exception/cancellation metadata:** preserve and test LSDA/personality/call-site/cancellation behavior separately from synchronous backtrace.
6. **Evidence registration:** add a manifest feature row, per-runtime row schema, native runner, checker, retained artifact hashes, and CI commands. Current manifest and CI have no CFI feature ID.
7. **Runtime closure:** add independent musl and bionic transformed CFI runners, including their unwinder/C++ runtime packages and environment-unavailable records. Current rehydration is glibc-only and current bionic/musl paths are status/stream or no-op validation paths.

## Commands Executed During Audit

- `python3 ./.trellis/scripts/task.py current --source` -> active task `.trellis/tasks/10-06-unify-elf-protection-infrastructure`.
- Repository `rg` searches over `src`, `tests`, `native`, `fixtures`, `scripts`, `.github`, and CFI child artifacts for CFI/unwind/backtrace/exception/cancellation/signal links.
- `aarch64-linux-gnu-readelf -hW -SW -lW --debug-dump=frames native/urprotect-runtime/build/host-context-entry-fixture.so` -> native AArch64 `ET_DYN` with `.eh_frame_hdr`, `.eh_frame`, two small FDEs, and NOP-only rules.
- The same readelf frame inspection on `tests/UrProtect.Core.Tests/Fixtures/SymbolVersions/liburp-versioned.so` -> compiler/linker-produced AArch64 image with bounded CFI, but not a native transformed-image behavior fixture.
- `git status --short --untracked-files=all` -> pre-existing parent/task worktree changes observed; no code, spec, or task-state files were changed by this audit.

Managed/parser/materializer tests are intentionally not used as runtime CFI evidence. The archived child’s own verification count and the current focused test files establish structural support only; they do not establish native backtrace, exception, cancellation, signal, or register/frame restoration.
