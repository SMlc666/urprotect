# Implementation Plan

Do not broaden the source ELF boundary or start custom loading during this
task. Start implementation only after the planning artifacts are reviewed and
the task is explicitly activated.

## 1. Freeze contracts and source provenance

- [ ] Finalize static-PIE launcher classification in the ELF model.
- [ ] Freeze frame v1 offsets, raw-deflate flag, limits, basename rules,
  launcher ABI, and stable diagnostics.
- [ ] Vendor pinned miniz tinfl source at commit
  `77d0dce8627735138c51770d1799a1ef48f2117d` with MIT notice and checksums.
- [ ] Add native source/license/provenance under `native/urprotect-launcher/`.
- [ ] Define static-PIE compiler/linker flags and deterministic build manifest.

Validation:

```text
python3 ./.trellis/scripts/task.py validate .trellis/tasks/09-12-aarch64-elf-wrapper-native-launcher
git diff --check
```

Rollback: retain Wrapper 0.1 C# launcher and do not route `pack` to an
unverified native artifact.

## 2. Native cryptographic and decompression primitives

- [ ] Implement project-owned SHA-256 update/finalize code without libc crypto.
- [ ] Add standard vectors, block-boundary tests, and managed parity.
- [ ] Integrate only miniz tinfl raw-deflate APIs; exclude compressor, ZIP,
  stdio, time, optional heap, and zlib-header paths.
- [ ] Add managed-generated vectors and exact output/consumption tests.
- [ ] Bound native allocations/maps and reject decompression bombs, truncated
  streams, invalid Huffman data, and trailing bytes.

Validation:

```text
dotnet test --filter Category=LauncherCodec
<native-compiler> -Wall -Wextra -Werror <native sources> <codec tests>
```

Rollback: keep frame generation managed-only until native vectors are identical.

## 3. Native launcher runtime

- [ ] Implement `/proc/self/exe` discovery, fixed trailer/frame parsing, and
  checked little-endian loads.
- [ ] Verify version, flags, architecture/type, basename, sizes, both digests,
  raw-deflate output, and minimal recovered-ELF identity before extraction.
- [ ] Implement fixed private temporary directory/file creation with exclusive
  creation, restrictive permissions, `O_NOFOLLOW`, `fsync`, and pre-exec cleanup.
- [ ] Preserve `argv[1..]`, stored basename as `argv[0]`, original `envp`, cwd,
  inherited descriptors, exit status, and standard streams through `execve`.
- [ ] Emit stable diagnostics and non-zero statuses for every pre-exec failure;
  never invoke a shell or environment-controlled path.
- [ ] Build a static AArch64 PIE with no interpreter or dynamic dependencies.

Validation:

```text
<native-launcher> --self-test
file <native-launcher>
readelf -hW -lW -dW <native-launcher>
```

Risk: static PIE startup/syscalls may differ between toolchain versions. Record
the exact compiler/linker and run on both claimed profiles.

## 4. Managed model and packer integration

- [ ] Add explicit static-PIE launcher classification without misclassifying
  shared objects.
- [ ] Update `ElfPackService` to accept only a validated native launcher,
  append frame/trailer without rewriting program headers, and validate wrapper.
- [ ] Require `--launcher` or package-local native launcher configuration;
  remove silent .NET launcher fallback for Wrapper 0.2.
- [ ] Keep managed v1 frame byte-compatible and harden basename validation
  (`.`/`..`, separators, UTF-8, limits).
- [ ] Extend pack JSON reports with launcher ABI, launcher hash, codec, and
  provenance fields.
- [ ] Keep atomic publication and source immutability.

Validation:

```text
dotnet restore UrProtect.sln --locked-mode
dotnet build UrProtect.sln --configuration Release --no-restore
dotnet test --filter Category=PackWrapper
dotnet test --filter Category=PackCli
```

## 5. Native and managed test suites

- [ ] Add C# tests for all frame fields, malformed bounds, wrong ABI/flags,
  basename traversal, digest mismatch, and deterministic output.
- [ ] Add native tests for frame parsing, codec, ELF guard, temp-file failure,
  exec failure, and no-launch-on-failure.
- [ ] Add checked-in Wrapper 0.1 frame compatibility fixture.
- [ ] Add fixtures for argv, environment, cwd, generated files, signal behavior,
  non-zero exit, and stderr.
- [ ] Add managed/native fuzz/property tests with fixed size/time budgets.

Validation:

```text
dotnet test UrProtect.sln --configuration Release --no-build
python3 scripts/check-coverage.py
```

## 6. Native ARM64 runtime E2E

- [ ] Extend `scripts/run-packed-fixture-matrix.sh` to select the native
  launcher and record launcher metadata.
- [ ] Run baseline and packed GCC/Clang C/C++, Rust, and Go fixtures on native
  ARM64 glibc; compare status, stdout, stderr, signals, cwd, environment, and
  declared file outputs.
- [ ] Extend `scripts/run-musl-container-smoke.sh` to build/use the static
  launcher and execute the recovered musl payload through the musl interpreter.
- [ ] Verify required jobs never fall back to C# launcher, QEMU, glibc, or
  another host architecture.
- [ ] Upload launcher/wrapper/frame/log/environment evidence on failure.

Validation:

```text
PATH=/root/.dotnet:$PATH ./scripts/run-packed-fixture-matrix.sh --profile pr
./scripts/run-musl-container-smoke.sh
```

## 7. Release, reproducibility, and documentation

- [ ] Package native launcher alongside C# packer and update release smoke to
  use `--launcher` explicitly.
- [ ] Add native source, miniz notice, compiler manifest, SBOM component,
  source hashes, and launcher hash to release artifacts.
- [ ] Compare repeated native launcher and wrapper builds byte-for-byte.
- [ ] Record launcher size/startup measurements against Wrapper 0.1.
- [ ] Update README/backend specs with command, limits, cleanup policy, and
  no-custom-loader boundary.

Validation:

```text
./scripts/package-release.sh 0.2.0 .artifacts/release
./scripts/release-smoke.sh .artifacts/release
git diff --check
```

## 8. CI gates and final review

- [ ] Add codec/unit tests to the PR gate.
- [ ] Add native ARM64 glibc packed E2E to the integration gate.
- [ ] Add pinned ARM64 musl packed E2E to nightly/release.
- [ ] Preserve Wrapper 0.1 compatibility evidence until 0.2 is promoted.
- [ ] Run final task-context validation and full quality review.
- [ ] Update PRD acceptance only after observable evidence is recorded.
- [ ] Archive after commit/push and successful CI verification.
