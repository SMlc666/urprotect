# Implementation Plan

Do not broaden the source ELF boundary or start custom loading during this
task. Start implementation only after the planning artifacts are reviewed and
the task is explicitly activated.

## 1. Freeze contracts and source provenance

- [x] Finalize static-PIE launcher classification in the ELF model.
- [x] Freeze frame v1 offsets, raw-deflate flag, limits, basename rules,
  launcher ABI, and stable diagnostics.
- [x] Vendor pinned miniz tinfl source at commit
  `77d0dce8627735138c51770d1799a1ef48f2117d` with MIT notice and checksums.
- [x] Add native source/license/provenance under `native/urprotect-launcher/`.
- [x] Define static-PIE compiler/linker flags and deterministic build manifest.

Validation:

```text
python3 ./.trellis/scripts/task.py validate .trellis/tasks/09-12-aarch64-elf-wrapper-native-launcher
git diff --check
```

Rollback: retain Wrapper 0.1 C# launcher and do not route `pack` to an
unverified native artifact.

## 2. Native cryptographic and decompression primitives

- [x] Implement project-owned SHA-256 update/finalize code without libc crypto.
- [x] Add standard vectors, block-boundary tests, and managed parity.
- [x] Integrate only miniz tinfl raw-deflate APIs; exclude compressor, ZIP,
  stdio, time, optional heap, and zlib-header paths.
- [x] Add managed-generated vectors and exact output/consumption tests.
- [x] Bound native allocations/maps and reject decompression bombs, truncated
  streams, invalid Huffman data, and trailing bytes.

Validation:

```text
dotnet test --filter Category=LauncherCodec
<native-compiler> -Wall -Wextra -Werror <native sources> <codec tests>
```

Rollback: keep frame generation managed-only until native vectors are identical.

## 3. Native launcher runtime

- [x] Implement `/proc/self/exe` discovery, fixed trailer/frame parsing, and
  checked little-endian loads.
- [x] Verify version, flags, architecture/type, basename, sizes, both digests,
  raw-deflate output, and minimal recovered-ELF identity before extraction.
- [x] Implement fixed private temporary directory/file creation with exclusive
  creation, restrictive permissions, `O_NOFOLLOW`, `fsync`, and pre-exec cleanup.
- [x] Preserve `argv[1..]`, stored basename as `argv[0]`, original `envp`, cwd,
  inherited descriptors, exit status, and standard streams through `execve`.
- [x] Emit stable diagnostics and non-zero statuses for every pre-exec failure;
  never invoke a shell or environment-controlled path.
- [x] Build a static AArch64 PIE with no interpreter or dynamic dependencies,
  including an explicit no-dynamic-linker override for older musl specs.

Validation:

```text
<native-launcher-self-test>
file <native-launcher>
readelf -hW -lW -dW <native-launcher>
```

Risk: static PIE startup/syscalls may differ between toolchain versions. Record
the exact compiler/linker and run on both claimed profiles.

## 4. Managed model and packer integration

- [x] Add explicit static-PIE launcher classification without misclassifying
  shared objects.
- [x] Update `ElfPackService` to accept only a validated native launcher,
  append frame/trailer without rewriting program headers, and validate wrapper.
- [x] Require `--launcher` or package-local native launcher configuration;
  remove silent .NET launcher fallback for Wrapper 0.2.
- [x] Keep managed v1 frame byte-compatible and harden basename validation
  (`.`/`..`, separators, UTF-8, limits).
- [x] Extend pack JSON reports with launcher ABI, launcher hash, codec, and
  provenance fields.
- [x] Keep atomic publication and source immutability.

Validation:

```text
dotnet restore UrProtect.sln --locked-mode
dotnet build UrProtect.sln --configuration Release --no-restore
dotnet test --filter Category=PackWrapper
dotnet test --filter Category=PackCli
```

## 5. Native and managed test suites

- [x] Add C# tests for all frame fields, malformed bounds, wrong ABI/flags,
  basename traversal, digest mismatch, and deterministic output.
- [x] Add native tests for frame parsing, codec, ELF guard, temp-file failure,
  exec failure, and no-launch-on-failure.
- [x] Preserve Wrapper 0.1 frame compatibility through the unchanged v1 frame
  vectors and native integration path.
- [x] Add fixtures for argv, environment, cwd, generated files, signal behavior,
  non-zero exit, and stderr.
- [x] Add managed bounded-random frame tests and deterministic native malformed
  frame coverage with fixed size/time budgets.

Validation:

```text
dotnet test UrProtect.sln --configuration Release --no-build
python3 scripts/check-coverage.py
```

## 6. Native ARM64 runtime E2E

- [x] Extend `scripts/run-packed-fixture-matrix.sh` to select the native
  launcher and record launcher metadata.
- [x] Run baseline and packed GCC/Clang C/C++, Rust, and Go fixtures on native
  ARM64 glibc; compare status, stdout, stderr, signals, cwd, environment, and
  declared file outputs.
- [x] Extend `scripts/run-musl-container-smoke.sh` to build/use the static
  launcher and execute the recovered musl payload through the musl interpreter.
- [x] Verify required jobs never fall back to C# launcher, QEMU, glibc, or
  another host architecture.
- [x] Upload launcher/wrapper/frame/log/environment evidence on failure.

Validation:

```text
PATH=/root/.dotnet:$PATH ./scripts/run-packed-fixture-matrix.sh --profile pr
./scripts/run-musl-container-smoke.sh
```

## 7. Release, reproducibility, and documentation

- [x] Package native launcher alongside C# packer and update release smoke to
  use `--launcher` explicitly.
- [x] Add native source, miniz notice, compiler manifest, SBOM component,
  source hashes, and launcher hash to release artifacts.
- [x] Compare repeated native launcher and wrapper builds byte-for-byte.
- [x] Record launcher size/startup measurements against Wrapper 0.1.
- [x] Update README/backend specs with command, limits, cleanup policy, and
  no-custom-loader boundary.

Validation:

```text
./scripts/package-release.sh 0.2.0 .artifacts/release
./scripts/release-smoke.sh .artifacts/release
git diff --check
```

## 8. CI gates and final review

- [x] Add codec/unit tests to the PR gate.
- [x] Add native ARM64 glibc packed E2E to the integration gate.
- [x] Add pinned ARM64 musl packed E2E to nightly/release.
- [x] Preserve Wrapper 0.1 compatibility evidence until 0.2 is promoted.
- [x] Run final task-context validation and full quality review.
- [x] Update PRD acceptance only after observable evidence is recorded.
- [x] Archive after commit/push and successful CI verification.
