# Repository facts for the 100x evaluator plan

This is a measured repository inventory, not a product or support claim. The
checkout was inspected at commit `86270e71362572d32544c9fa979553e2f3c4cb7c`
(`chore: archive open-world function protection task`). The active PRD digest is
`4e88cafe02ffd2703c3dae33d151c1624016898ec4e2cc301b5c2f69b500f469`.

## Current product boundaries

* `README.md` describes UrProtect Validator 0.1 / AArch64 ELF Wrapper 0.2 as a
  conservative ELF validator, no-op copier, outer wrapper, and explicitly
  selected function-level protector. It explicitly says the wrapper is not a
  custom ELF loader or an in-process code-protection transformation.
* `src/UrProtect.Core/Protect/FunctionProtectionService.cs` emits rewritten
  AArch64 ELF bytes directly. The current service has two passes,
  `control-flow-flattening` and `register-permutation`, with deterministic
  flatten-then-permute ordering. It requires explicit symbol/address selectors,
  a complete supported CFG, and a spare program-header slot, and publishes no
  output when a selected transformation fails.
* `src/UrProtect.Core/Pack/PayloadFrame.cs` has current frame v3, Deflate, source
  and encoded SHA-256 fields, explicit `outer-execveat` and
  `host-context-entry` profiles, and bounded HostContext metadata. Its payload
  is the compressed source image; it is not a separately named Protected Image
  ABI.
* `src/UrProtect.Core/Pack/ElfPackService.cs` validates the source, encodes the
  frame, appends a trailer to a profile-matched launcher, decodes the generated
  wrapper back to exactly the source bytes, and publishes atomically. It does
  not expose a `Protected Image -> rehydration -> Native Image` product stage.
* `native/urprotect-launcher/launcher_main.c` reads its own wrapper, validates
  the v3 outer frame and recovered ELF, writes the recovered source to an
  anonymous memfd, and calls `execveat(AT_EMPTY_PATH)`. The launcher therefore
  hands the original recovered ELF to the kernel/native interpreter.
* `native/urprotect-runtime/runtime.c` verifies a HostContext frame and both
  payload digests, calls the host's `load_image`, resolves the declared entry,
  dispatches it, and releases the image. `native/urprotect-runtime/host_adapter.c`
  performs bounded image preflight, creates a sealed memfd, calls `dlopen` via
  `/proc/self/fd/<N>`, performs `dlsym`, and owns release/lifetime behavior.
* A repository-wide search of `src`, `native`, `tests`, `scripts`, `benchmarks`,
  `fixtures`, the docs, and CI found no existing `Protected Image`, Scheme A,
  red-team attack-family, dump/reassembly, or evaluator-vector protocol. This
  is a gap, not evidence that the current implementation has such a stage.

## Existing protection E2E

`scripts/run-protection-e2e.sh` builds
`fixtures/samples/protection/main.c` plus `target.S`, records a native baseline,
and runs four recipes:

1. `register-permutation` on `urp_transform_target`;
2. `control-flow-flattening` on `urp_transform_target`;
3. `combined`, whose report must say flattening then permutation; and
4. `branch-control-flow-flattening` on `urp_flatten_target`.

For each recipe it checks the JSON report, protected exit status, stdout and
stderr equality with the baseline, a readelf report, and a SHA-256 record. The
fixture's behavioral oracle is the program's fixed output and zero status; its
source expects `26`, `4`, `7`, and `3` for the four calls. This is a useful
behavior fixture, but it is direct `protected ELF -> native process` execution.
There is no Protected Image artifact, rehydration record, target-loader record,
or attack-cost measurement. The local checkout has no `.artifacts/protection/`
root, so current protection artifacts were not re-run here.

`fixtures/real-samples/protection-policy.json` has no project entries. It keeps
one explicit smoke fixture (`protection-symbolized-fixture`) covering glibc,
musl, and bionic and both current passes. `scripts/validate-protection-policy.py`
passed; this policy is selector metadata, not attack evidence.

## Existing compatibility/sample evidence

* `fixtures/manifest.json` validates to 38 features and 13 cases. The measured
  feature status counts are 25 `validated`, 7 `proven`, and 6 `rejected`.
  The PR tier has seven cases, nightly five, and release one. Cases cover GCC
  and Clang C/C++, Rust, Go, NativeAOT, musl, bionic, Android JNI, ET_EXEC,
  HostContext, and the current launcher paths.
* `fixtures/runtime-matrix.json` has six named cells. PR selects current native
  glibc, the native 16-KiB page probe, and locked bionic; nightly/release add
  older glibc and the two musl cells. The registry explicitly treats a missing
  native 16-KiB kernel as `environment-unavailable`/unknown, not as support.
* `fixtures/real-samples/manifest.json` declares exactly 100 distinct public
  project identities (78 glibc, 21 musl, one bionic; 96 ET_DYN and four
  dynamic ET_EXEC in the registry facts). The checked-in `.artifacts/real-samples`
  aggregates are `evidenceMode=registry-baseline`; they are metadata and do not
  prove a Protected Image chain. Existing docs explicitly distinguish static
  validation, baseline execution, outer-wrapper execution, and HostContext.
* `scripts/run-fixture-matrix.sh` proves source execution and byte-identical
  no-op copy behavior. `scripts/run-packed-fixture-matrix.sh` proves an outer
  wrapper is byte-different while preserving status and standard streams; its
  process probe also compares argv/argv[0], environment, cwd, inherited fd,
  declared file effects, and signal status. These are valuable auxiliary
  oracles, but they must not be counted as strict chain units without the
  additional Protected Image and rehydration stages.
* Existing HostContext evidence is materially stronger than a parser check:
  current frame v3, entry dispatch, release, sealed memfd, lifecycle, TLS,
  dependency, GNU property, and native loader negative cases are represented by
  native fixtures and `test_managed_host_context.sh`. It still is not evidence
  that the function-protection output is a Protected Image consumed by a generic
  rehydrator.

## Existing benchmark, tests, fuzzing, and CI

* `benchmarks/UrProtect.Benchmarks/Program.cs` benchmarks a synthetic 0x204-byte
  ELF for parse, LoadMap, validate with/without analysis, no-op memory copy, and
  no-op disk copy. It emits elapsed time, allocations, heap, and peak working
  set. It does not measure protection, Protected Image encoding, rehydration,
  native-image startup, target-loader handoff, or red-team work.
* Unit/integration tests include parser and malformed corpora, payload-frame
  round trips and mutations, HostContext ABI/layout, pack and launcher tests,
  explicit protection tests, concurrency, large input, golden reports, and
  deterministic fuzz-style parser tests. `tests/ContractInventory.md` gives
  the current managed/native ownership map.
* `tests/UrProtect.Fuzz/Program.cs` has only `elf` and `payload-frame` modes.
  `scripts/run-coverage-fuzz.sh` uses pinned SharpFuzz 2.3.0 and a pinned
  libFuzzer bridge, bounded `max_len`, timeout/RSS/wall budgets, and retains
  crash/timeout corpus. It does not fuzz a Protected Image ABI, rehydration,
  Native Image validation, or attack families.
* `scripts/run-regression-stress.sh` records fixed worker/iteration/large-input
  parameters and bounded timeout. It is correctness/concurrency coverage, not
  protection-strength evidence.
* `.github/workflows/ci.yml` runs build/test/coverage, protection smoke (glibc
  on the main native job; musl in the musl-container job; bionic fixture in the
  bionic job), fixtures, packed fixtures, HostContext, fuzz, stress, runtime
  matrix, real samples, and a scheduled/manual/release benchmark. There is no
  independent compatibility-plus-Scheme-A evaluator job and no immutable 1x
  baseline artifact contract.
* Existing evidence gates are useful precedents: manifests are validated,
  generated evidence is required to be non-empty, raw real-sample inputs are
  kept temporary, artifact trees reject symlinks/raw binaries where policy
  requires, and SHA-256 manifests bind retained files. The new evaluator
  should reuse these controls rather than replace them.

## Commands run during this inventory

Passed static checks:

* `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`
  (`validated fixture matrix: 13 cases; requested tier=pr`)
* `python3 tests/test_fixture_matrix.py` (24 tests)
* `python3 tests/test_regression_matrix.py` (5 tests) and the regression
  metadata validator
* `python3 tests/test_runtime_matrix.py` (13 tests) and runtime registry
  validator
* `python3 scripts/validate-protection-policy.py fixtures/real-samples/protection-policy.json`
* real-sample manifest/fingerprint/security tests (24, 2, and 7 tests)
* `python3 scripts/check-coverage.py` against the newest retained report:
  overall line `0.7166`, branch `0.4102`; UrProtect.Core line `0.6930`, branch
  `0.6227`.

The local environment is native `aarch64`, 4096-byte pages, GCC 15.2.0,
Clang 21.1.8, and binutils readelf 2.46, but `dotnet` was not available in
`PATH`. Native product E2E and benchmarks were therefore not re-run here; old
`.artifacts` are ignored generated state and are not treated as a current
commit baseline. The local kernel identifies as an Android 5.15-derived kernel,
which is not the CI Ubuntu 24.04 runtime-matrix contract.

## Immediate evaluator implications

1. A direct function-protected ELF or compressed complete source frame must not be
   relabeled as a Protected Image. The strict compatibility score must report
   the missing stage rather than count existing wrapper/HostContext rows.
2. The current implementation therefore does not yet supply a positive strict
   Protected Image-chain denominator. The baseline snapshot must record this as
   `baseline-zero`/`protocol-not-ready`, not manufacture a numeric 100x claim.
3. The evaluator needs a pinned attack-tool image/manifest before any Scheme-A
   family can be measured. The repository currently has no dynamic-instrumentation
   or logic-recovery attack runner and CI does not lock such a toolchain.
4. Existing `readelf`, frame, launcher, HostContext, real-sample, fuzz, and
   benchmark evidence remains required auxiliary/non-regression evidence.
