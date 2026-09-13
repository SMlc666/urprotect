# Technical Design

## 1. Upstream Runtime Source

The first bionic evidence host is based on the Termux Docker AArch64 image:

- repository: https://github.com/termux/termux-docker
- source commit: 7033c7639eb86107a4fdf8b72bd6388c07b1284a
- ARM64 image: termux/termux-docker@sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4
- documented runtime linker: /system/bin/linker64

The pinned upstream Dockerfile constructs the image from scratch and copies a
Termux rootfs containing AOSP libraries, including bionic libc and linker. It
links /system to the AOSP subtree inside the Termux prefix. The upstream
README explicitly says that the image does not contain Android runtime
components such as DalvikVM or OpenSLES.

The published digest is the primary CI input. The source commit is retained
for provenance and review. A source rebuild must not be called reproducible
merely because the repository commit is pinned: the upstream generator
downloads a bootstrap archive, reads current package indexes, and performs an
upgrade. A rebuild lane therefore also records exact bootstrap/package URLs,
SHA-256 values, package versions, and the generated rootfs digest. It cannot
replace the digest-pinned CI lane until those inputs are locked.

## 2. Native ARM64 Execution

The CI job runs on the existing ARM64 runner with the pinned OCI image. The
container command uses the image's root entrypoint only for setup that requires
root; fixture execution runs as the Termux system user where possible. The
job records:

- uname architecture and kernel release;
- host/container page size from getconf;
- image reference and resolved digest;
- Termux source commit and bootstrap/rootfs identifiers;
- /system/bin/linker64 identity and checksum;
- fixture ELF interpreter and dynamic dependencies;
- presence or absence of qemu-aarch64, qemu-system, native-bridge, AVD, and
  Waydroid mechanisms.

The lane fails if uname is not aarch64, if the fixture is not ELF64 AArch64,
if the interpreter is not the bionic linker, or if a forbidden fallback is
detected. Host glibc is recorded as the outer kernel host fact only; it is not
accepted as the fixture runtime.

The job should use the least privileged container configuration that permits
the image to start. Termux Docker documents that some ARM containers need
personality-related seccomp adjustment. If such an adjustment is required, it
is pinned and recorded as a host fact. An implicit privileged, emulated, or
alternate-libc fallback is never allowed to turn a failed bionic case green.

## 3. Fixture and Oracle

Add a minimal C fixture that has deterministic stdout, stderr, exit status,
and a small observable value from the bionic runtime. Build it inside the
Termux userspace with a pinned Termux compiler/package set, or consume a
separately pinned bionic-linked artifact whose interpreter and dependencies
are verified before execution. The selected method must emit package
provenance; an unpinned apt upgrade is not evidence.

The fixture flow is:

1. inspect the ELF header, program headers, interpreter, dynamic tags, and
   architecture;
2. execute the unwrapped baseline through /system/bin/linker64;
3. execute the unified HostContext/packaged form once the runtime child
   provides that entry path;
4. compare declared output, exit status, diagnostics, and relevant digest
   metadata;
5. publish the environment and oracle files under the matrix case evidence
   directory.

The current legacy temporary-file/execve wrapper may be retained as a baseline
comparison, but it cannot satisfy the new no-temporary-path Host Contract
claim. The bionic child must not silently turn that legacy result into a
proven unified runtime result.

## 4. Matrix Scope

The case uses:

    runtime: bionic
    execution: native-arm64-bionic-container
    host.environment: termux-userspace
    host.androidRuntime: false

It maps to bionic linker, AArch64 ET_DYN, dynamic dependency, page-size, and
HostContext features that the oracle actually exercises. The existing Android
JNI case also has a bionic runtime fact, but its execution witness includes an
x86_64 Android guest and native bridge; the two cases remain separate. Neither
case alone proves every bionic version, Android framework service, OEM loader
policy, SELinux policy, or device kernel.

## 5. Failure and Evidence Semantics

The case is:

- validated when the deterministic native lane passes but a host behavior is
  still conditional;
- proven only for static/model obligations already closed by the Host Contract
  and ELF feature tasks;
- unknown when an input, package, linker, page-size, or host capability is not
  pinned or observed;
- rejected when a forbidden fallback or unsupported ELF/runtime feature is
  encountered.

Reports distinguish bionic userspace evidence from Android framework evidence
and never aggregate them as one undifferentiated platform result.
