# Outer-execveat expansion audit

## Selection and contract

- The real-sample CI artifact from run `36107714022` contains 20 distinct
  project fingerprints and two `ET_EXEC` images (Caddy and Python), i.e. 10% of
  identities. Both are dynamic AArch64 glibc executables with
  `/lib/ld-linux-aarch64.so.1`; the feature therefore crosses the 5% review
  threshold.
- The first slice accepts ELF64 little-endian AArch64 dynamic `ET_EXEC` with
  an executable entry in `PT_LOAD`, bounded `PT_DYNAMIC`, one terminated
  absolute recognized `PT_INTERP`, and no `DT_RPATH`/`DT_RUNPATH`. It rejects
  static `ET_EXEC`, shared objects, missing/duplicate/unrecognized interpreters,
  and path-search tags. HostContext and frame v3 are unchanged.
- Parser/model classification is separately `proven` by
  `elf.identity.aarch64-et-exec`; only dynamic ET_EXEC with the native process
  oracle is `validated` as `elf.outer.dynamic-et-exec`.
- The real-sample policy now expects static parser acceptance for Caddy and
  Python (`accepted-and-runs`), while baseline/outerWrapper/HostContext remain
  `not-applicable` for those single-package files because their dependency
  closure is absent. The raw/typed ET_EXEC dispositions and registry baseline
  aggregate were regenerated to reflect this layered contract.
  In the preceding CI artifact, both were rejected at the prior parser type
  gate (`UnsupportedFileType @0x10`), which is the exact static boundary this
  task changes.
- The generated C fixture is linker-produced with `gcc -no-pie`; readelf
  reports `Type: EXEC`, `/lib/ld-linux-aarch64.so.1`, `PT_DYNAMIC`, and
  `DT_NEEDED`. Its process probe records argc/argv, source-name `argv[0]`,
  environment, cwd, fd 3 contents, a declared file, and signal termination.
- CLI JSON now reports the canonical `ET_EXEC` type and `DynamicExecutable`
  kind, while human pack/validation summaries no longer claim every payload is
  an ET_DYN PIE.

## Verification

- `dotnet test UrProtect.sln --configuration Release --no-restore`: 136 passed,
  including separate `DT_RPATH` and `DT_RUNPATH` no-publication regressions.
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`
  and `--tier release`: passed; shell syntax, manifest JSON, task manifest,
  and `git diff --check`: passed.
- `python3 scripts/validate-real-samples.py ... --tier pr`, fixture (24),
  regression (5), and real-sample manifest/fingerprint/evidence/security/
  aggregate (13/2/3/3/5) unit suites passed, as did registry baseline
  regeneration. The PR evidence gate checked all seven declared generated
  artifact paths.
- `PATH=/root/.dotnet:$PATH ./scripts/run-fixture-matrix.sh --tier pr`:
  passed, including `c-gcc-glibc-et-exec` baseline/no-op byte identity.
- `PATH=/root/.dotnet:$PATH NATIVE_LAUNCHER_CC=gcc
  ./scripts/run-packed-fixture-matrix.sh --tier pr`: passed on native AArch64.
  The launcher self-test, native launcher integration tests, managed anonymous
  handoff, and all packed fixtures passed. The ET_EXEC probe matched baseline
  and wrapper output exactly; both `DT_RPATH` and `DT_RUNPATH` no-publication
  tests passed; signal termination matched between baseline and wrapper. The
  PR CI runner recorded status 143 through `timeout`, while local GNU timeout
  returns status 15 for the same self-SIGTERM child; the oracle accepts these
  two documented signal-status forms and rejects timeout status 124. The
  declared-file outputs matched.
- The packed-matrix static launcher was built with an explicit `CC=gcc`
  override because `musl-gcc` is absent in this environment. This run proves
  the native AArch64 glibc outer cell only. Recognizing the musl loader path is
  not a musl runtime claim.
- The early `--execution native-linux` evidence gate points the new case at its
  fixture-smoke artifact; the GitHub workflow separately gates
  `elf.outer.dynamic-et-exec` after packed-fixture smoke so the packaged
  process-probe artifact exists before inspection.
- CI runs `36118272640` and `36118276208` exposed the original ordering
  defect: the case evidence path pointed at the packed artifact before that
  step had run. The case path
  now targets the fixture-smoke directory and the packed feature artifact is
  checked after `Packed fixture smoke`; both gates pass locally.
- GitHub run `36119338003` passed the managed build, real-sample, and bionic
  jobs. Its retained packed log exposed that GNU `timeout` reports the
  self-SIGTERM probe as 143 on the hosted runner, while local GNU `timeout`
  reports 15. The signal oracle was normalized to accept these two direct
  signal-result encodings while rejecting timeout status 124; the follow-up
  CI after this correction remains pending. The run's real-sample artifact
  supplies the Caddy/Python parser acceptance evidence above.

## Ownership and rollback

- `ElfParser`/`ElfValidator` classify and validate ELF types and executable
  entries; `ElfPackService` owns profile-specific acceptance; the native
  launcher requires both `PT_DYNAMIC` and `PT_INTERP` for recovered ET_EXEC.
- The wrapper keeps the current frame-v3 bytes and memfd/
  `execveat(AT_EMPTY_PATH)` path. HostContext still requires its existing
  ET_DYN shared-object entry contract.
- Roll back the ET_EXEC kind, pack predicate, native recovered-image check,
  fixture, and `elf.outer.dynamic-et-exec` row together. Preserve the existing
  PIE/static-PIE boundaries and native launcher regression probes.
