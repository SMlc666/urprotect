# R6 CFI cross-runtime feasibility audit: musl and Bionic

## Finding

**The typed C++ exception CFI oracle is not currently build-and-run demonstrated for either declared musl or Bionic.** This is a tooling/integration and evidence gap, not proof that porting the oracle is technically impossible. The only registered and retained transformed typed-exception row is native AArch64 glibc. The current CFI runner, rehydration runner, and checker all select or require glibc; the musl and Bionic lanes exercise other C-only runtime fixtures, not this CFI oracle.

The existing glibc artifact is substantive transformed evidence: `cfi-behavior.json` records baseline and mapped-transformed executions with `cppBoundaryStatus=1`, `cppCaughtSpecificType=1`, the required token, `cppRaiiCleanupCount=1`, `cppRegisterCallReturned=0`, `cppTargetNormalReturned=0`, and `cppThrowSiteTargetFrameObserved=1`. The transformed target is invoked through the rehydration address map (source VA 500/size 84 to output VA 131464/size 160). This evidence is explicitly bound to the glibc runtime identity; it does not establish musl or Bionic execution.

## Current oracle and exact commands

- `native/urprotect-runtime/host_context_cfi_fixture.c` defines a C target with a frame anchor and aliases `urp_entry` to the selected function. The fixture intentionally does not acquire a C++ runtime dependency.
- `host_context_cfi_exception_bridge.cpp` throws a typed C++ exception from the HostContext callback and catches that exact type at a caller boundary; the token and a destructor counter distinguish real exception unwinding from normal return. `host_context_cfi_register_call.S` supplies an assembly frame with explicit `.cfi_*` rules and a named post-`blr` return PC.
- `host_context_cfi_runtime_test.c` loads the source/native image through the HostContext adapter, observes frames/registers, and runs separate signal, `setjmp`/`longjmp`, cancellation, and C++ exception cases. The C++ exception is not the longjmp boundary. The same file directly includes `<execinfo.h>` and calls `backtrace()` (`:6,256-260`); availability/behavior of that API is not established by the musl or Bionic rows.
- Current CFI invocation in CI is:
  ```sh
  ./scripts/run-cfi-host-context-e2e.sh --tier "$tier"
  python3 scripts/check-cfi-evidence.py \
    ".artifacts/cfi/${tier}" --tier "$tier" --runtime glibc \
    --unit runtime.cfi.transformed-backtrace.glibc.host-context-entry
  ```
  The runner defaults to `CC=cc`, `CXX=g++`, calls `make -B -C native/urprotect-runtime ... cfi-fixture cfi-runtime-test`, requires AArch64 compiler targets, identifies the C++ dependencies with `ldd`, records `libstdc++.so.6` and `libgcc_s.so.1`, and calls `tls_runtime_identity.py`. It then invokes `run-host-context-rehydration-e2e.sh --runtime glibc`. That rehydration runner rejects every runtime except glibc. The checker has `--runtime` choices `("glibc",)` and validates the retained glibc identity plus GNU libstdc++/libgcc unwinder identities (`scripts/check-cfi-evidence.py:115-118,382-383`).

## Available toolchain and runtime identities

### Read-only facts from this audit environment

- Host architecture is `aarch64`.
- `cc`, `gcc`, `g++`, `c++`, `clang`, `clang++`, `ld`, `ld.lld`, and `readelf` resolve under `/usr/bin`.
- `cc`/`gcc`/`g++` report Ubuntu GCC 15.2.0-16ubuntu1, target `aarch64-linux-gnu`. The available `clang`/`clang++` report Ubuntu Clang 21.1.8 (6ubuntu1), target `aarch64-unknown-linux-gnu`; this is the host GNU/Linux toolchain, not a Bionic-target identity.
- `musl-gcc`, `musl-g++`, `musl-clang`, `aarch64-linux-musl-gcc`, and `aarch64-linux-musl-g++` are unavailable locally. `docker` and `podman` are also unavailable locally, so neither the declared musl container nor the Termux/Bionic container can be exercised in this audit environment.
- Local Clang identity queries returned literal unresolved names for `libc++.so` and `libunwind.so`; the current local Clang setup therefore supplies no resolvable libc++ or LLVM libunwind identity. `g++ -print-file-name` resolves GNU `libstdc++.so` and `libgcc_s.so.1` for the host glibc toolchain.

### Retained glibc CFI toolchain (not a musl/Bionic toolchain)

The checked-in retained CFI identity at `.artifacts/cfi/proof-binding-fix-20261014T202700Z/cpp-runtime-identity.json` identifies the working glibc oracle as follows:

| Component | Retained identity |
|---|---|
| C compiler | `/usr/bin/aarch64-linux-gnu-gcc-15`; `cc (Ubuntu 15.2.0-16ubuntu1) 15.2.0`; target `aarch64-linux-gnu`; SHA-256 `5b06a5b85cab901e2af3e8f351a6d4e8e6a93af24797bd8c01e5391ac6b4e63b`; build ID `09b9f6f443e5df30b4bdb459c3e28f8a655e7e04` |
| C++ compiler | `/usr/bin/aarch64-linux-gnu-g++-15`; `g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0`; target `aarch64-linux-gnu`; SHA-256 `1b6148236631210472bf87126432464b8c694acd02fb27e11eb8c607820fc817`; build ID `f3e051990c9de369db8b07cd8b975bc9da917692` |
| C++ library | SONAME `libstdc++.so.6`; resolved file `/usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.35`; SHA-256 `d604f900ea3d02c57ad0a97b48b1666262759be4accc08bf37150b36715d48ef`; build ID `74e5051e9bf2e80c2f04af1821833645108880fc` |
| Unwinder | SONAME `libgcc_s.so.1`; `/usr/lib/aarch64-linux-gnu/libgcc_s.so.1`; SHA-256 `a886d874bfcc27b5b3de47504eb861af8f15cf8c2aea160bd3b973e1a1a95255`; build ID `208154f16bc55a2f824338a7c99ebeb8fe08c6c0` |
| Runtime | glibc 2.43; `/usr/lib/aarch64-linux-gnu/libc.so.6`; loader `/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`; identity digest `46aa3acac72ca86358bed9d411b3160038aa068ea1531cae58905b76b590f208` |

These are the required exact identities for the existing glibc proof only. They must not be relabeled as musl or Bionic identities.

### Declared musl lane

`fixtures/runtime-matrix.json` declares native musl 1.2.4 (nightly/release) and Alpine 3.22.2/musl 1.2.5 (nightly/release). `scripts/install-runtime-musl-toolchain.sh` builds musl 1.2.4 from the source archive using native GCC and `--enable-wrapper=gcc`, and requires/records `musl-gcc`; its tool list and outputs do not include a C++ compiler, libstdc++, or an unwinder identity. `scripts/run-runtime-matrix.sh` builds/runs C no-op probes with `musl-gcc`; the Alpine 1.2.5 cell runs those same C binaries. Neither command builds the CFI C++ bridge or harness.

Consequently, the declared lane has a pinned C producer and libc/loader evidence, but no declared matched `musl-g++`/C++ ABI/unwinder bundle. It also has not established that the CFI harness's `execinfo.h`/`backtrace()` dependency is provided. The existing glibc `g++` is not a safe substitute: its target is `aarch64-linux-gnu` and its standard library/unwinder are glibc-linked.

### Declared Bionic lane

The Bionic registry row pins the Termux ARM64 image and `/system/bin/linker64`; the eight package artifacts include `clang=21.1.8-3`, `libcompiler-rt=21.1.8-3`, `libllvm=21.1.8-3`, `libxml2=2.15.4-1`, `lld=21.1.8-3`, `llvm=21.1.8-3`, `ndk-sysroot=30`, and `make=4.4.1-1` (with package SHA-256s in `fixtures/manifest.json`). `scripts/run-bionic-fixture.sh` runs `clang --version`, builds the C fixture with `clang`, and invokes the HostContext self-test with `CC=clang LD=ld.lld`; it never builds the CFI targets or invokes `CXX`/`clang++`.

The Bionic package closure/evidence does not retain a CFI-linked `clang++`, libc++/libc++abi, or unwinder identity. A separate Bionic Node runtime lock records `libc++=29`, but that is not evidence of the libraries used by the CFI harness or of a CFI run. In particular, this audit cannot identify the exact Bionic unwinder (or confirm whether the Termux CFI process would load a shared or static C++ runtime) from the declared CFI lane.

## Concrete blockers to cross-runtime claims

1. **Runner/checker are glibc-only.** No runtime flag exists in the CFI runner; its identity capture calls glibc-only `tls_runtime_identity.py`, its dependency probe is glibc `ldd`, and it requires GNU `libstdc++.so.6`/`libgcc_s.so.1`. Its downstream HostContext rehydration runner accepts only `--runtime glibc`. The checker rejects any runtime other than glibc.
2. **No declared musl C++ toolchain.** The musl installer creates only the C wrapper `musl-gcc`; the matrix's musl cells are C-only smoke tests. There is no locked `musl-g++`, musl-built `libstdc++`, or matching exception unwinder identity to bind to a CFI harness.
3. **Bionic C++ build path is unspecified.** Bionic CI locks/uses `clang` and `ld.lld` for C but does not pass `CXX` or `AS`, nor run `cfi-runtime-test`. The Makefile compiles the exception bridge with `$(CXX)` but assembles `host_context_cfi_register_call.S` with `$(AS)` (default `as`). The lane does not retain proof that these commands resolve to the expected Termux/Android toolchain.
4. **Bionic dynamic metadata needs an explicit CFI build contract.** The adapter rejects `DT_RELR` on Bionic and rejects Android packed relocation tags (`host_image_validation.c:1428-1432,1577-1586`). The current Bionic HostContext entry-fixture recipe explicitly passes `ENTRY_FIXTURE_LDFLAGS=--pack-dyn-relocs=none`, but the CFI fixture recipe does not consume that variable (`native/urprotect-runtime/Makefile:342-344`). A Bionic CFI image must be linked and inspected so it stays in the adapter's supported dynamic-tag/relocation subset.
5. **The C harness has unverified runtime API dependencies.** It calls `backtrace()` via `<execinfo.h>` and tests `pthread_cancel`; neither current musl nor Bionic evidence establishes these APIs for this harness. For each runtime, either prove their exact providers/behavior or replace the backtrace dependency with a portable unwinder path and preserve the typed-exception witness.
6. **No transformed evidence exists for those rows.** `fixtures/manifest.json` has only `runtime.cfi.transformed-backtrace.glibc.host-context-entry`; `fixtures/runtime-matrix.json` records runtime smoke cells, not CFI. CI's CFI step runs only on the glibc build job. The separate musl job runs C probes, while the Bionic job runs the C adapter and optional C protection fixture. Neither job invokes a CFI producer/checker. `.trellis/tasks/10-06-unify-elf-protection-infrastructure/prd.md:88,93,97` explicitly leaves musl/Bionic transformed CFI unpromoted.

## Minimal authoritative per-runtime E2E plan

Toolchain availability and transformed behavior must be separate gates. A successful compiler invocation or ordinary `throw/catch` smoke test is **toolchain evidence only**; it is not transformed CFI evidence.

### Shared acceptance shape for each runtime row

1. Pin and retain the runtime-specific C compiler, C++ compiler, assembler/linker, actual C++ ABI library, actual unwinder, libc, and loader identities. Record target triple, version/package version, resolved path, package/source lock, SHA-256, and ELF build ID where applicable. Confirm the CFI harness has the intended runtime dependencies; do not infer runtime from `aarch64*` alone.
2. Build the C CFI image and C++ host harness for the same runtime. First run the **untransformed source image** under that runtime's own loader and require the exact C++ type/token catch, one RAII cleanup, no normal target return, the target FDE frame at the throw site, and successful release.
3. Feed the same source through the existing protected-image/rehydration producer; execute the **transformed Native Image** using the same runtime-specific adapter/loader. Require the runtime-observed throw-site PC and target frame to lie in the transformed range from the recorded address map, and require the transformed FDE to cover that range. Compare source/transformed status and frame/exception observations.
4. Retain source/protected/native hashes, ELF dynamic and unwind inspections, address-map and FDE/header coverage, exact compiler/runtime identities, baseline/transformed machine records, and closed checksums. Run the malformed `.eh_frame` negative and require deterministic failure with no image publication or loader invocation.
5. Add an independent manifest row/checker case and a CI command in the lane that actually ran the target runtime. Do not promote either row from the glibc evidence.

### Musl 1.2.4 native (nightly/release)

- **Toolchain gate:** extend the pinned native musl toolchain with a musl-targeted C++ driver and its matching C++ ABI/exception unwinder, or bring an equivalently pinned native AArch64 musl C++ toolchain. Record exact C and C++ driver paths/versions/targets/build IDs, musl 1.2.4 loader/libc identity, and the actual C++ runtime/unwinder shared objects and hashes. Establish the `execinfo.h`/`backtrace()` provider or change the harness to the supported unwinder API. Existing `install-runtime-musl-toolchain.sh` alone does not satisfy this gate.
- **Transformed gate:** build `cfi-fixture` and `cfi-runtime-test` with the musl C/C++ toolchain, run baseline and transformed binaries on the native musl 1.2.4 lane, and add a runtime-specific rehydration/handoff path (the current one rejects musl). Use the exact musl loader/runtime for both runs and checker input. Keep the CFI source image free of C++ runtime dependencies as it is now.
- **Musl 1.2.5 cross-runtime cell:** if the requirement is to cover the full declared musl covering set rather than only native 1.2.4, add a separate run in pinned Alpine 3.22.2. Use a pinned producer and provide/lock the C++ runtime and unwinder required by the harness inside that image; record Alpine's actual musl 1.2.5 loader identity. The current matrix only runs C probes in that cell.

### Bionic Termux (all declared tiers)

- **Toolchain gate:** inside the existing pinned ARM64 Termux image, verify the actual `clang` and `clang++` commands/target, then pin and identify the C++ standard library/ABI and unwinder actually linked and loaded (likely LLVM/Termux components, but the current CFI lock does not establish which). Record their package versions, archive hashes, runtime file hashes/build IDs, and `/system/bin/linker64` identity. Check the `execinfo` and cancellation dependencies.
- **Build gate:** build the C fixture and C++ harness with the in-container C/C++ drivers, use the Termux integrated assembler (or explicitly locked assembler), pass the Bionic platform flags to HostContext validation, and add a CFI-fixture-specific `--pack-dyn-relocs=none` setting. Inspect `readelf -dW` to prove the image contains no adapter-rejected `DT_RELR`/Android-packed-relocation tags. The existing Bionic make invocation only demonstrates `CC=clang LD=ld.lld self-test`, not these CFI targets.
- **Transformed gate:** run source and transformed Native Image through the Bionic adapter under `/system/bin/linker64`, catch the same typed exception/token with one cleanup through both the mapped target FDE and register-call assembly FDE, and retain loader, C++ runtime, unwinder, address-map/FDE, hashes, and malformed-CFI rollback evidence. Add a separate `runtime.cfi...bionic.host-context-entry` checker/manifest row; do not reuse the glibc identity schema.

### CI wiring

- Keep the existing glibc command as the glibc row.
- Add the musl 1.2.4 CFI build/evidence/check to `runtime-matrix-native-arm64` after the pinned musl C++ toolchain gate; add a distinct Alpine 1.2.5 CFI run only if that runtime cell is in scope for R6.
- Add the Bionic CFI build/evidence/check to `bionic-native-arm64` inside the pinned Termux container after package-lock verification.
- Make the CFI runner/checker runtime-neutral only where each row provides a real runtime-specific identity and native execution. Replacing `--runtime glibc` text without a matched C++ runtime, loader run, transformed target FDE observation, and distinct evidence row is insufficient.

## Audit constraints and commands

This was a read-only audit. No compilation, tests, CI scripts, package installation, environment mutation, or system-path changes were performed. Queries were limited to task resolution, `uname`, `command -v`, compiler version/target and runtime-file identity queries, and repository/artifact reads. The local tool availability checks found no `musl-gcc`, `musl-g++`, Docker, or Podman. The retained glibc artifacts were read, not regenerated.
