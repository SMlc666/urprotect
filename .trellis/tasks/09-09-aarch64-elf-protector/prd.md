# AArch64 ELF binary protection platform

## Goal

Define and plan a C# infrastructure tool for analyzing, validating, and safely preparing Linux/Android AArch64 ELF binaries. The project must own the ELF parsing, validation, address mapping, relocation model, and writing foundation, while using a pinned AsmStone revision for AArch64 instruction encoding and decoding.

The immediate deliverable is a reviewed, executable MVP plan. The first implementation is infrastructure-only: it must not change program semantics, inject runtime logic, encrypt code, virtualize control flow, or claim to provide a protection transformation. Implementation must not begin until the input boundary, no-op behavior, validation contract, and CI profiles are explicit.

## User Value

The tool should provide a conservative, reproducible way to analyze and safely prepare binaries produced by several native toolchains, while proving that the validated input and any byte-identical no-op artifact remain structurally valid and executable in the supported runtime profiles. Unsupported or ambiguous inputs must be rejected rather than producing a potentially corrupted binary.

## Confirmed Constraints

- Implementation language: C#/.NET.
- Primary format and architecture: ELF64, AArch64, little-endian; the initial product is not a PE, Mach-O, or .NET assembly protector.
- ELF handling: implement the runtime-required ELF subset in the project instead of depending on a general-purpose ELF library.
- Instruction handling: use AsmStone through a project adapter; do not duplicate its complete AArch64 encoder/decoder validation suite.
- Runtime profiles: Linux AArch64 with glibc and musl, plus Android AArch64/bionic.
- Initial input boundary: ELF64 little-endian `EM_AARCH64` user-space binaries, limited to `ET_DYN` PIE executables and dynamically linked shared objects; both stripped and unstripped inputs are in scope.
- No-op output: when the infrastructure pipeline emits an output artifact, it must be byte-for-byte identical to the validated input; it must not rebuild or discard unmodeled data.
- Execution infrastructure: GitHub-hosted ARM64 runners are the official native Linux execution environment; no contributed physical Linux or Android devices are assumed.
- Android constraints: GitHub ARM64 runners are assumed not to provide KVM or a usable Android SDK/emulator stack. Android validation may use an ARM64 Android container (Waydroid-like) and an `x86_64` GitHub runner hosting an x86_64 AVD in TCG software emulation with Android's `arm64-v8a` native bridge, with each mode labeled accurately. A full `arm64-v8a` system image on an x86_64 host is not assumed to work.
- CI quality: E2E behavior, compiler/toolchain coverage, benchmarks, coverage, fuzzing, reproducibility, and failure artifacts are first-class requirements.
- MVP behavior: provide parsing, structural validation, address/control-flow analysis foundations, AsmStone integration, and a safe no-op validation pipeline; defer all actual protection transformations.
- Dependency policy: pin AsmStone and all compiler, SDK, NDK, image, and container inputs; preserve relevant licenses and provenance.
- Safety boundary: the project is for authorized software protection, integrity, and compatibility testing. Stealth, detection evasion, and malware-oriented behavior are not product requirements.

## Requirements

### R1. Conservative ELF model

The planned MVP must define the supported program headers, dynamic tags, symbol data, relocation forms, notes/properties, TLS, exception metadata, and page-alignment profiles for the agreed `ET_DYN` PIE and shared-object boundary. Program headers and load mappings are authoritative for runtime behavior; stripped files must not depend on section headers being present.

### R2. Address and relocation correctness

The design must keep file offsets, ELF virtual addresses, and runtime addresses distinct. PC-relative references, AArch64 branch ranges, dynamic relocations, Android relocation encodings, and future layout changes must be represented by checked fixups. Overflow, unsupported relocation, unknown code, and unresolved target cases must fail closed for any rewrite-eligible analysis; the current no-op path must report these conditions without guessing.

### R3. AsmStone integration boundary

The project must pin a known AsmStone revision and expose only a local adapter to the rest of the codebase. Project tests must cover the adapter and the instruction categories used by current analysis and future rewriting, including branch, conditional branch, ADR/ADRP, literal load, and common load/store forms. Full AArch64 ISA correctness remains an upstream AsmStone responsibility.

### R4. Toolchain and language fixture matrix

The plan must define prioritized fixture profiles for GCC, upstream LLVM/Clang, Android NDK Clang, Rust, Go, Zig, and C# NativeAOT where the selected SDK supports the target. Fixtures must cover representative ELF shapes rather than claim language-specific compiler integration. Apple LLVM is only in scope when it is proven to emit the target ELF; Darwin/Mach-O is separate scope.

### R5. Runtime E2E validation

For every required runtime profile, the test flow must build a baseline artifact, run it, validate the ELF and its no-op output, prove byte identity, run the output through the real loading path, and compare observable behavior such as exit status, output, generated files, and JNI results. Future transformation work must extend this flow with a separate transformed-artifact comparison. Android E2E must use an APK and `System.loadLibrary`/JNI path rather than only executing an extracted `.so`.

### R6. Android execution tiers

The CI plan must distinguish static Android ELF/APK validation, ARM64 Android container validation, and `x86_64` host plus x86_64 AVD TCG validation with the `arm64-v8a` native bridge. The native-bridge path is specifically intended to exercise bionic, the Android linker, `System.loadLibrary`, and JNI with an AArch64 native library; it must use `-accel off`/software rendering and be placed in nightly/manual/release tiers rather than the fast PR gate until runtime is proven stable. A full ARM64 guest remains a separate capability target and must not be implied by the native-bridge result. A container job is eligible for the primary bionic E2E gate only after checking Binder/BinderFS, namespaces/cgroups, LXC, headless Wayland/graphics prerequisites, and matching ARM64 system/vendor images. Neither TCG, native-bridge, nor container execution may be labeled as native hardware validation.

### R7. CI and reproducibility

CI must use explicit runner labels and pinned inputs, fail rather than silently fall back to emulation or unsupported toolchains, save environment/toolchain metadata, and preserve minimized failing ELF/APK inputs and logs. PR, nightly, and release tiers must be separated so core correctness gates remain usable while exhaustive matrices run regularly.

### R8. Quality evidence

The plan must include unit, property, malformed-input, fuzz, integration, and E2E tests; module-sensitive coverage thresholds; and benchmarks for parsing, mapping, relocation/fixup indexing, analysis, no-op copying, allocations, and peak memory. Future rewriting/serialization benchmarks remain deferred with the mutation scope. Android software-emulation performance must not be used as a native performance baseline.

### R9. Infrastructure-only MVP

The first implementation must not change executable semantics or add runtime behavior. Its observable output is validated analysis data and an optional byte-identical copy of the input. It must not rebuild or discard unmodeled data. Any future transformation capability must be a separately planned scope with its own correctness and runtime acceptance criteria.

## Acceptance Criteria

- [ ] A PRD-approved MVP boundary names the agreed `ET_DYN`/shared-object ELF kinds, required relocations/properties, infrastructure-only behavior, and explicit non-goals.
- [ ] A technical design separates ELF parsing/modeling, AsmStone adaptation, analysis, fixup/layout planning, writing, and validation.
- [ ] A prioritized compiler/language/runtime fixture manifest defines PR, nightly, and release coverage without requiring a full Cartesian product.
- [ ] The CI design has a verified GitHub ARM64 Linux path for glibc and musl and a capability-gated Android container/AVD strategy that does not claim physical-device support.
- [ ] The correctness contract requires structural validation, byte-identity proof, runtime E2E comparison of baseline and no-op output, and fail-closed behavior for unsupported inputs.
- [ ] The no-op artifact path proves byte-for-byte identity in addition to structural validation.
- [ ] Benchmark, coverage, fuzzing, reproducible-build, dependency-pinning, and failure-artifact policies are measurable and reviewable.
- [ ] `prd.md`, `design.md`, and `implement.md` pass the final planning review before the task is activated for implementation.

## Out of Scope for the Initial Plan

- PE, Mach-O, A32/T32, non-AArch64 architectures, and .NET assembly protection.
- A promise of compatibility with physical Android devices, OEM ROMs, or vendor-specific hardware behavior.
- Reimplementing or exhaustively revalidating AsmStone's generated AArch64 instruction catalog.
- Full compiler-version/runtime Cartesian coverage on every pull request.
- Stealth, anti-analysis, detection bypass, or malware concealment features.

## Planning Status

The MVP is infrastructure-only. It will not implement a protection transformation or runtime protection mechanism. The initial input boundary is `ET_DYN` PIE executables and dynamically linked shared objects, and the no-op output contract is byte-for-byte identity. Technical details that remain are implementation design choices or explicitly deferred compatibility work, not product-blocking decisions.
