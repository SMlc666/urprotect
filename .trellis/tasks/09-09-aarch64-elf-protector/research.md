# Planning Research

## AsmStone

Source: `https://gitlab.com/ursafe/AsmStone`

Observed repository facts:

- Managed C# AArch64 encoder/decoder targeting .NET 8.
- Generated, data-driven instruction metadata sourced from a pinned LLVM TableGen checkout.
- Feature-aware decode, raw and semantic views, PC-relative targets, memory operands, and control-flow/memory-effect metadata.
- Text assembly/disassembly syntax is intentionally outside the project boundary.
- ELF parsing and object-file rewriting are explicitly outside its first-slice scope.
- License is MIT, with LLVM and AARCHMRS source/license provenance documented for generated inputs.

Decision: consume AsmStone behind a project adapter and pin a known revision. Do not copy its generated opcode catalog or add local opcode-specific paths for upstream gaps.

## Android and bionic

Relevant sources:

- `https://android.googlesource.com/platform/bionic/+/master/linker/linker.cpp`
- `https://android.googlesource.com/platform/bionic/+/d990f7d7d495430875b023538881c9b7a7e81c23/linker/linker_relocate.cpp`
- `https://developer.android.com/guide/practices/page-sizes`
- `https://developer.android.com/ndk/guides/sdk-versions`

Planning conclusions:

- Android must be modeled as a separate bionic/profile target, not merely generic Linux.
- `DT_RELR` and Android-specific relocation forms need explicit recognition and preservation in the ELF model.
- API level, NDK version, `DT_NEEDED`, linker namespace, RELRO, page alignment, and JNI loading path are independent compatibility inputs.
- Container page size follows the host kernel; a container cannot by itself prove a 16 KiB Android kernel profile.

## Android container feasibility

Relevant sources:

- `https://docs.waydro.id/`
- `https://docs.waydro.id/debugging/getting-essential-information`
- `https://docs.waydro.id/usage/install-on-desktops`
- `https://docs.waydro.id/development/compile-waydroid-using-android-generic-project`

Planning conclusions:

- Waydroid-like execution uses Linux containers/LXC rather than KVM, so it may provide a native ARM64 bionic userspace on a GitHub ARM64 host.
- Binder/BinderFS, memfd or ashmem support, namespaces/cgroups, matching ARM64 system/vendor images, and a Wayland/graphics path are prerequisites.
- GitHub-hosted runner kernel capabilities must be probed; installation success alone is not evidence that the container can boot.
- Container E2E is useful for bionic/JNI/native-library loading but does not prove Android OEM, device-kernel, or hardware behavior.

## GitHub ARM64 runners

Reference: `https://docs.github.com/en/actions/reference/runners/github-hosted-runners`

Planning conclusions:

- Use an explicit versioned ARM64 Linux label such as `ubuntu-24.04-arm`, subject to availability for the repository and current GitHub image policy.
- The native Linux gate must run directly on the ARM64 host; an x86 runner plus QEMU is not an equivalent result.
- Android ARM64 AVD software emulation is a separate profile and must be labeled as software emulation. The project does not claim physical Android device support. The released emulator rejects an `arm64-v8a` system image on an x86_64 host, so the practical hosted experiment uses an x86_64 guest in TCG mode with the image's `libndk_translation.so` native bridge for an `arm64-v8a` APK.
- Runner, kernel, libc, page size, toolchain, and acceleration-mode metadata must be retained with every compatibility result.

Observed hosted-runner probe:

- On the first GitHub ARM64 workflow dispatch, `aarch64`, Linux namespaces, and cgroups were available, but Binder/BinderFS, LXC, and a Wayland/headless compositor were absent.
- The Android container probe therefore remains informational and non-gating. The workflow records the missing capabilities rather than claiming container E2E coverage or failing the Linux build/test gate.

Fixture/AVD implementation evidence:

- The ARM64 host has native GCC/Clang, Rust, and Go available. CI installs pinned native ARM64 musl packages (`musl`, `musl-dev`, and `musl-tools` version `1.2.4-2`) from Ubuntu Noble and Zig 0.13.0 from the official tarball with SHA-256 verification; their nightly profiles are required and fail closed if installation or execution is unavailable.
- The Android AVD script records host architecture, page size, KVM status, SDK/tool paths, emulator mode, native-bridge properties, logs, and APK artifacts. The guest path uses an x86_64 system image, `-accel off`, and software graphics; it never labels TCG/native bridge as native hardware or a full ARM64 guest.
- The current ARM64 environment has `adb` but no Android SDK manager, AVD manager, emulator, or Gradle, so the ARM64-hosted probe correctly emits `ANDROID_AVD_UNAVAILABLE`. The runtime experiment targets a GitHub x86_64 runner, where Android host tools are practical, and keeps the APK library ABI `arm64-v8a` while using the x86_64 image's native bridge.
- The first x86_64 hosted attempt installed the Android host tooling successfully; its initial unavailable result was caused by probing unsupported `avdmanager --version`, not by missing SDK infrastructure. Use `avdmanager --help` for the capability probe before creating the AVD.
- The next x86_64 attempt passed the SDK and AVD-manager probes but the emulator binary could not load `libpulse.so.0`; the workflow now installs and records the Ubuntu `libpulse0` host dependency before running the emulator.
- After the host-library fix, the emulator reached its launch step but could not find the AVD created by `avdmanager`. The script now sets explicit shared `ANDROID_AVD_HOME`/`ANDROID_SDK_HOME` paths, lets `avdmanager` select the default device profile, and verifies the named AVD before boot.
- The following hosted run proved the AVD directory and APK build, then failed with `Avd's CPU Architecture 'arm64' is not supported by the QEMU2 emulator on x86_64 host`. This confirms that `-accel off` selects software CPU execution but does not add cross-architecture support to the released Android Emulator. The manifest and workflow now use the supported x86_64 API 35 image and require `libndk_translation.so`, `ro.dalvik.vm.isa.arm64=x86_64`, and an arm64-only APK before reporting native-bridge coverage.
- The first x86_64 native-bridge attempt reached the x86_64 emulator and completed the arm64-only APK build, but the 300-second `adb wait-for-device` window expired while TCG boot was still in progress. The emulator log showed no ABI or linker failure. The script now records a 900-second boot budget for software-emulation startup; KVM remains disabled with `-accel off`.
- The next manual GitHub Actions run succeeded end to end (`34563456686`): the x86_64 API 35 guest reported `guest_abis=x86_64,arm64-v8a`, `native_bridge=libndk_translation.so`, and `native_bridge_isa_arm64=x86_64`; the arm64-only APK installed, `System.loadLibrary` resolved the library, JNI emitted the expected result, and the job reported `PASS android-arm64-native-bridge-on-x64`.
- CI cache design decision: use `actions/setup-dotnet`'s lockfile-keyed NuGet cache for all .NET jobs, retain `gradle/actions/setup-gradle` as the sole Gradle cache owner, and cache only the pinned Android SDK package directories. Do not cache `bin/obj`, Gradle outputs, APKs, or dirty AVD state; collect cache hit/miss and timing evidence before evaluating clean snapshot caching.
- Cache validation: the first Android SDK cache archive was ineffective because it targeted the root-owned preinstalled SDK and restored with tar permission errors; the job then redownloaded packages. Moving `ANDROID_HOME`/`ANDROID_SDK_ROOT` to `${RUNNER_TEMP}/android-sdk` and bumping the cache schema produced an exact writable cache hit on run `34594255238` (about 3.0 GB restored without permission errors). The full build, fixture, benchmark, container probe, and native-bridge JNI jobs passed. The cache summary expression now uses bracket notation for hyphenated step/output names.
- NativeAOT fixture repair: remove the incompatible `PublishSingleFile` setting because .NET rejects it alongside `PublishAot`; NativeAOT already emits the single native executable used by the runner.
- The first Zig 0.13 nightly build produced a statically linked `ET_EXEC`, outside the MVP input boundary. The Zig fixture now requests `-dynamic -fPIE -lc` for a musl-linked PIE so it exercises the same dynamically linked `ET_DYN` path as the other supported fixtures.
- Manual CI dispatches now default the slow native-bridge AVD job to off via the typed `run_android_native_bridge` input; scheduled runs retain automatic coverage, and the core jobs remain independent of AVD boot time.
- The workflow now also maps published GitHub releases to the release fixture/benchmark/Android tier; the manual boolean keeps the slow AVD opt-in only for manual runs.
- Native ARM64 build, fixture, and benchmark jobs now record atomic environment reports containing architecture, kernel/libc, page size, toolchain versions, and emulation indicators. The Android native-bridge job records its x86_64 host and translated execution mode separately; mismatch checks fail closed instead of relabeling a fallback as native.
- The fixture harness now retains `readelf -hW -lW -dW` reports and checks the external header model for ELF64 little-endian AArch64 `ET_DYN` output with a dynamic section. `readelf` is kept outside the product runtime dependency graph.
- The benchmark harness now reports parse, LoadMap, validation/metadata, analysis, memory-copy, disk-copy, allocation, and peak-working-set measurements. CI retains the results alongside the runner environment, Git SHA, and fixture-manifest hash; Android software-emulation timing is excluded from this baseline.
- The parser fuzz path now combines a deterministic malformed corpus, mutated valid ELF seeds, bounded random input sizes/iterations, and a 120-second default process timeout. It runs in the nightly fixture job and retains a TRX result without adding a runtime fuzzing dependency.
- The ELF model now recognizes Android legacy packed `DT_ANDROID_REL`/`DT_ANDROID_RELA` tables as bounded raw payloads, alongside RELR variants, without decoding, applying, or rewriting them. Unknown dynamic tags remain in the raw dynamic-entry list.
- AArch64 analysis candidates now include relocation target addresses in addition to the entry point and dynamic-symbol starts, while retaining executable-segment and alignment checks.
- ELF note and GNU-property program segments now have a bounds-checked note view that preserves names/descriptors and enforces four-byte note alignment. Malformed note payloads fail with a typed diagnostic rather than being guessed.
- Dynamic metadata now resolves bounded `DT_STRTAB` values for `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and `DT_RUNPATH`; invalid offsets are rejected while raw dynamic entries and string-table bytes remain available.
- Common AArch64 relocation numbers now map to project-owned semantic kinds, while unknown types remain preserved and produce no-op warnings instead of being applied.
- Symbol-version metadata now exposes bounded `DT_VERSYM` indices and `DT_VERNEED`/`DT_VERNEEDNUM` dependency chains, preserving raw record bytes while rejecting truncated, cyclic, backwards, or invalid-name chains.
- The independent musl-container profile uses the platform-specific ARM64 manifest digest `sha256:2a4ce54f70cde53d58db3face36aeb5cf4aa272c2e4676ffc3586021413b14b4` for `mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim` (resolved through the digest-only image reference). It installs pinned Debian musl tooling, bootstraps source with git inside the container, builds a musl PIE, runs the product CLI no-op path, and retains the digest/environment evidence.
