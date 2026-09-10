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
- Android ARM64 AVD software emulation is a separate profile and must be labeled as software emulation. The project does not claim physical Android device support. The planned runtime experiment uses an x86_64 host with an `arm64-v8a` guest in TCG mode.
- Runner, kernel, libc, page size, toolchain, and acceleration-mode metadata must be retained with every compatibility result.

Observed hosted-runner probe:

- On the first GitHub ARM64 workflow dispatch, `aarch64`, Linux namespaces, and cgroups were available, but Binder/BinderFS, LXC, and a Wayland/headless compositor were absent.
- The Android container probe therefore remains informational and non-gating. The workflow records the missing capabilities rather than claiming container E2E coverage or failing the Linux build/test gate.

Fixture/AVD implementation evidence:

- The ARM64 host has native GCC/Clang, Rust, and Go available in the current environment; Zig and musl tooling are optional and are reported explicitly when absent.
- The Android AVD script records host architecture, page size, KVM status, SDK/tool paths, emulator mode, logs, and APK artifacts. The guest path uses `arm64-v8a`, `-accel off`, and software graphics; it never labels TCG as native hardware.
- The current ARM64 environment has `adb` but no Android SDK manager, AVD manager, emulator, or Gradle, so the ARM64-hosted probe correctly emits `ANDROID_AVD_UNAVAILABLE`. The runtime experiment should target a GitHub x86_64 runner, where Android host tools are practical, while keeping the guest image `arm64-v8a`.
- The first x86_64 hosted attempt installed the Android host tooling successfully; its initial unavailable result was caused by probing unsupported `avdmanager --version`, not by missing SDK infrastructure. Use `avdmanager --help` for the capability probe before creating the AVD.
