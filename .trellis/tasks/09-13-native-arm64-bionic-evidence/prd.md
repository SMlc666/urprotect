# Add native ARM64 bionic host evidence

## Goal

Run a pinned bionic userspace natively on the ARM64 CI runner without AVD, Waydroid, QEMU, or native bridge and feed its evidence into the unified compatibility matrix.

## Requirements

- Treat bionic as a runtime/userspace fact parallel to glibc and musl, not as
  a Linux/Android product profile or a vendor mode.
- Use the AArch64 Termux Docker source commit
  7033c7639eb86107a4fdf8b72bd6388c07b1284a and pin the ARM64 OCI image to
  digest sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4.
  Record the source commit, image digest, bootstrap/rootfs provenance, and
  package/tool versions in the evidence artifact.
- Prove directly that the lane is native AArch64: check uname, ELF machine,
  requested interpreter, bionic linker availability, kernel, and page size.
  A missing or contradictory fact must fail the case rather than falling back
  to the host glibc.
- Run a small dynamically linked AArch64 PIE fixture in the Termux userspace
  and later run the unified HostContext/package oracle when that runtime slice
  is available. Capture baseline behavior, packaged behavior, exit status,
  stdout, stderr, ELF metadata, and loader diagnostics.
- Do not use AVD, Waydroid, QEMU user/system emulation, Android native bridge,
  or a different libc image to satisfy this case. Record and reject forbidden
  fallback paths.
- Represent the case in the matrix as runtime bionic plus execution
  native-arm64-bionic-container. The case must identify the Termux userspace
  as not being a complete Android framework/device.
- Keep page size and kernel facts as evidence dimensions. A 4 KiB runner
  result must not silently claim 16 KiB device-kernel compatibility.

## Acceptance Criteria

- [ ] CI runs the pinned ARM64 Termux Docker image on an ARM64 runner without
      AVD, Waydroid, QEMU, or native bridge.
- [ ] The lane fails closed unless architecture, bionic linker, image/source
      pin, kernel, and page-size evidence are present and consistent.
- [ ] A bionic PIE fixture executes with a direct /system/bin/linker64 check
      and a deterministic baseline/packaged or HostContext oracle.
- [ ] The matrix contains a bionic case alongside glibc and musl cases, with
      feature references, status, evidence paths, and explicit scope limits.
- [ ] The report states that Termux Docker supplies bionic userspace but not
      DalvikVM, framework services, OEM behavior, SELinux policy, or a device
      kernel.
- [ ] The test remains reproducible from pinned inputs; dynamically changing
      package metadata or an implicit host fallback is recorded as a failure.

## Notes

- This complex child has design and implementation artifacts; implementation
  still waits for the parent planning review and task start.

- Keep `prd.md` focused on requirements, constraints, and acceptance criteria.
- Lightweight tasks can remain PRD-only.
- For complex tasks, add `design.md` for technical design and `implement.md` for execution planning before `task.py start`.
