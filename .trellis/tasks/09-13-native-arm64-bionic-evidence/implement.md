# Implementation Plan

## Preconditions

- Keep this child in planning until the parent task starts.
- Freeze the matrix field names and HostContext version with the dependent
  child tasks before editing CI or fixture code.
- Preserve the existing Android JNI/native-bridge evidence as a separate case.

## Ordered Work

1. [ ] Add a pinned Termux Docker source/image record and provenance helper.
2. [ ] Add a native ARM64 bionic environment probe that records architecture,
       kernel, page size, linker, image digest, rootfs/package inputs, and
       forbidden fallback checks.
3. [ ] Add the smallest bionic-linked PIE fixture and lock its compiler/package
       inputs, or record a separately pinned artifact with equivalent proof.
4. [ ] Add the baseline and HostContext/packaged execution oracle, including
       ELF metadata, output, status, diagnostics, and digest evidence.
5. [ ] Add the matrix case and connect it to bionic linker, ET_DYN, dynamic
       dependency, page-size, and runtime handoff feature IDs.
6. [ ] Add the ARM64 CI lane using the pinned OCI image, least-privilege
       container settings, and artifact upload.
7. [ ] Add drift checks ensuring image digest, source commit, linker path, and
       no-fallback assertions remain synchronized across manifest, scripts, CI,
       and generated reports.
8. [ ] Update README/release evidence language to describe bionic as a runtime
       fact and to keep complete Android claims separate.

## Risk and Rollback Points

- If the public image changes or becomes unavailable, mark the case unknown
  and retain the last evidence digest; do not silently use the latest tag.
- If Termux package indexes cannot be locked, use the digest-pinned image
  only for the already included runtime tools and keep compiler-dependent
  fixture evidence unknown until package provenance is fixed.
- If seccomp restrictions require a broader setting, record the exact setting
  and review it as host evidence; do not replace it with privileged mode or
  emulation without an explicit decision.
- If the bionic fixture exposes an unsupported loader, relocation, TLS, or
  dependency behavior, preserve the parser result and mark the matrix row
  rejected or unknown instead of weakening the runtime contract.
- Removing the lane is recoverable: leave its matrix row unknown and keep
  existing glibc, musl, and Android evidence unchanged.

## Validation

    python3 scripts/validate-fixtures.py --tier nightly
    ./scripts/run-bionic-fixture.sh
    ./scripts/run-fixture-matrix.sh --tier nightly
    PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release
    rg -n 'termux-docker|native-arm64-bionic-container|linker64|qemu|native.bridge|waydroid' .github scripts fixtures README.md

The bionic command must fail closed on a non-AArch64 host, an unpinned image
or package set, a non-bionic interpreter, missing page-size evidence, or any
forbidden fallback. Its report must state that the result is Termux bionic
userspace evidence, not full Android/device evidence.
