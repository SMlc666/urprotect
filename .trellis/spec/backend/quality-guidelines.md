# Quality Guidelines

## Build and Language Contract

- Production code targets the pinned .NET SDK `8.0.424` from `global.json`.
- Restore uses committed `packages.lock.json` files and CI uses
  `dotnet restore --locked-mode`.
- Nullable reference types and the SDK analyzers remain enabled; warnings are
  treated as errors in the native launcher build and should not be suppressed
  in C# production code.
- `.editorconfig` requires UTF-8, LF endings, a final newline, four-space
  indentation, file-scoped namespaces, and System directives sorted first.
- Keep public binary/report contracts as explicit records, enums, and typed
  address values. Avoid exposing third-party AsmStone model types.

## Required Design Patterns

- Use `BoundedReader` and checked arithmetic for all untrusted binary reads.
- Use program headers as the authoritative ELF runtime layout; section headers
  may be absent or stripped.
- Keep parser classification separate from profile acceptance. The parser may
  model ET_EXEC as well as ET_DYN, but each new executable class needs an
  explicit `ElfPackService` profile rule, a native baseline/wrapper oracle, and
  a paired rejected boundary before a launch claim is recorded.
- Use `FileOffset`, `VirtualAddress`, and `RuntimeAddress` instead of mixing
  address domains as raw integers.
- Keep `DiagnosticCode` stable and machine-readable. Preserve unknown ELF data
  and report unsupported semantics rather than guessing.
- Keep the no-op pipeline byte-preserving. Any output must be compared to the
  source before publication.
- Pin and retain licenses for AsmStone and miniz. Native source, compiler
  inputs, specs hashes, and output hashes belong in provenance.

## Forbidden Patterns

- Do not use a general-purpose ELF library in the production parser.
- Do not cast ELF counts, offsets, or sizes directly to array lengths or `int`
  without a checked bounded conversion.
- Do not duplicate `LoadMap` address arithmetic or frame offsets in consumers.
- Do not rewrite unknown instructions, relocations, dynamic tags, or sections
  as a best effort.
- Do not add a dynamic dependency to the static launcher, require a source
  payload path from the environment, or use a shell for payload execution.
- Do not hide missing toolchains, wrong host architecture, emulator use, or
  host/runtime failures as successful native coverage.

## Testing Requirements

Every parser, pipeline, CLI, frame, launcher, or release change needs focused
tests plus the relevant malformed-input path:

- `ElfParserTests.cs` covers valid models and targeted parser behavior.
- `ElfMalformedCorpusTests.cs` and `ElfParserFuzzTests.cs` cover truncation,
  mutation, overflow, and no-throw safety.
- `BinaryPropertyTests.cs` covers bounded reads, range overflow, and load-map
  round trips.
- `GoldenReportTests.cs` protects JSON diagnostic/report projections.
- `NoOpPipelineTests.cs` and `CliApplicationTests.cs` cover atomic output,
  stable exit codes, JSON stream behavior, and byte identity.
- `PayloadFrameTests.cs` and `ElfPackServiceTests.cs` cover deterministic
  frames, limits, digests, launcher variants, and publication failures.
- `ConcurrencyRegressionTests.cs` and `LargeInputRegressionTests.cs` cover
  immutable shared-input use, deterministic outputs, exact/plus-one limits,
  multi-megabyte inputs, and no-partial-publication behavior under bounded PR
  and amplified nightly profiles.
- `ContractLayoutTests.cs` and `tests/ContractInventory.md` own the
  cross-language ABI/frame-layout drift check and literal ownership record.
- `tests/regression-matrix.json` and `scripts/validate-regression-matrix.py`
  map each E2E regression class to its command, tier, budget, platform, and
  artifact witness.
- `scripts/run-coverage-fuzz.sh` runs the separate SharpFuzz/libFuzzer ELF and
  payload-frame targets. It must retain the pinned bridge hash, seed/corpus,
  limits, and crash/timeout artifacts; it does not replace deterministic fuzz
  tests or Coverlet line/branch coverage.
- Native `self_test.c` and `test_launcher.sh` cover SHA-256, raw deflate,
  malformed frames, handoff behavior, and signal/status preservation.
- HostContext worker-lifetime changes require the real-linker initial-exec TLS
  fixture on native AArch64 glibc, with inherited event/gate pipes, exact
  readelf TLS/relocation facts, explicit and automatic joins, TLS teardown
  before image destructor, serial reruns, concurrent independent dispatches,
  and retained runtime identity/status/hash evidence. Musl/bionic execution is
  not a substitute for the glibc cell.

Use external `readelf`/`llvm-readelf` checks for produced ELF structure when a
change affects a launcher, fixture, or release. Compare runtime behavior using
status, stdout, stderr, signals, cwd, environment, and declared files; exclude
ASLR addresses and timing.

## CI and Release Contract

- Required native Linux jobs run on `aarch64` and retain an environment report.
- `fixtures/manifest.json` is the source of truth for fixture IDs, tiers,
  toolchains, runtimes, and execution facts.
- Required toolchain or runtime failures fail the job. Optional Android native
  bridge capability is reported explicitly and is not relabeled as native
  ARM64 hardware.
- NuGet caching belongs to `actions/setup-dotnet`; Gradle caching belongs to
  `gradle/actions/setup-gradle`. Do not cache build outputs, APKs, or dirty AVDs.
- Release packages contain normalized checksums, source/provenance, third-party
  notices, and SBOM-equivalent inventory. The static launcher must be ELF64
  AArch64 `ET_DYN` with no `PT_INTERP` or `DT_NEEDED`.

## Review Checklist

- Are all offsets, lengths, counts, additions, multiplications, and address
  conversions bounded before use?
- Is the owning parser/codec/report helper reused rather than reimplemented?
- Does every failure return a stable diagnostic and avoid publishing output?
- Are stripped ELF files, unknown records, and unsupported semantics handled
  without guessing?
- Are tests present for both the valid path and the nearest malformed path?
- Are concurrency, large-input, fuzz, and E2E profiles bounded, reproducible,
  and assigned to the correct CI tier?
- Does every promoted fuzz finding have a minimized deterministic regression?
- Does CI retain enough environment and failure evidence to distinguish a
  product failure from a missing capability?

## Examples

- `src/UrProtect.Core/Elf/ElfParser.cs` demonstrates bounded program-header,
  dynamic-table, note, relocation, and symbol-version parsing.
- `src/UrProtect.Core/Pack/ElfPackService.cs` demonstrates source/launcher
  separation, atomic wrapper publication, and final recovery verification.
- `tests/UrProtect.Core.Tests/GoldenReportTests.cs` demonstrates stable report
  snapshots rather than assertions on incidental console formatting.
- `native/urprotect-launcher/Makefile` demonstrates the pinned static-PIE
  compile/link contract and strict AArch64 build checks.

## Public real-sample CI corpus

`fixtures/real-samples/manifest.json` is a separate ecology evidence layer from
`fixtures/manifest.json`. It locks the current approved slice of exactly 20
distinct public AArch64 upstream project identities, records an approved target
of 100, and retains archive/version/file hashes, extracted paths, runtime facts,
and layer policies. A libc/build variant is an attribute of one identity and
never another corpus count. The candidate ledger and selection report retain
why selected, rejected, and deferred public candidates differ.

Local developer commands for this layer are metadata-only:

```sh
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 tests/test_real_sample_manifest.py
```

The real-sample runner rejects non-GitHub-Actions or non-AArch64 invocation
before network access. CI downloads into `RUNNER_TEMP`, checks immutable
archive SHA-256, rejects archive traversal/special links, checks the declared
extracted-file path, and deletes the temporary tree after each run. Raw input
archives, ELF files, and rootfs contents are never uploaded. Every PR runs all
approved projects; no diff-path, label, or affected-sample filter is allowed.
Nightly and release reuse the exact registry and oracle implementation and may
only add repetition/retention/environment strength.

Static evidence is mandatory for all 20. An applicable dynamic oracle must run
in a networkless bounded isolation root with read-only inputs, temporary output,
dropped privileges/no-new-privileges behavior, bounded wall time, memory,
process count, output, and cleanup. A missing isolation capability is
`environment-unavailable` and fails the gate. A layer without its declared
contract is an explicit `not-applicable` result, never a silent skip. The
runner and `check-real-sample-evidence.py` retain normalized fingerprint,
bounded readelf output, UrProtect JSON, hashes, environment facts, result
classification, per-sample logs, and schema-2 aggregate coverage. The shared
first-failure taxonomy is `acquisition`, `fingerprint`, `parse-model`,
`static-validation`, `outer`, `host-context`, or `environment`.

Real observations do not promote support. A parser/validator, packer, launcher,
native-runtime, fixture-contract, or compatibility-document change must list
its affected real-sample project IDs, tier, layer-specific oracle, expected
result, and evidence path in the plan. A new support claim still needs a
controlled positive fixture, nearest-negative fixture, stable diagnostic, and
updated contract/docs. `unexpected-rejection` and `unexpected-acceptance`
keep the compatibility task open until classified and resolved.

### Scenario: schema-2 real-sample evidence and aggregate contract

#### 1. Scope / Trigger

Changes to the public real-sample inspector, CI runner, evidence gate,
aggregate renderer, registry validator, or candidate ledger must preserve one
bounded schema across `pr`, `nightly`, and `release`. The checked-in baseline
is metadata-only; only the native CI artifact root is execution evidence.

#### 2. Signatures

```sh
python3 scripts/inspect-real-sample.py \
  --input ELF --output FINGERPRINT_JSON --readelf-output READELF_TXT \
  --project-id PROJECT_ID --producer PRODUCER --runtime RUNTIME
python3 scripts/render-real-sample-report.py MANIFEST --tier TIER \
  --artifact-root ARTIFACT_ROOT --require-evidence
python3 scripts/check-real-sample-evidence.py MANIFEST --tier TIER \
  --artifact-root ARTIFACT_ROOT
```

#### 3. Contracts

- Fingerprints and per-sample results use schema version `2`; normalized
  feature objects are bounded and retain `unknownFields` instead of guessing.
- Results contain all four layers (`static`, `baseline`, `outerWrapper`, and
  `hostContext`) and use only the shared result vocabulary. `firstFailureLayer`
  is one of `acquisition`, `fingerprint`, `parse-model`,
  `static-validation`, `outer`, `host-context`, or `environment`.
- Schema-2 aggregate output contains `identityCount`, `coverage` with target,
  current count, and shortfall, `featureHistogram`, `firstFailureLayers`, and
  project IDs. Feature frequency is counted by distinct `identityKey`, not by
  variants.
- Features at or above 5% require a matching entry in
  `fixtures/real-samples/feature-dispositions.json`; a disposition never
  changes product support status.
- Raw archives, ELF files, extracted roots, and temporary runner paths are
  removed or sanitized before artifact upload. `raw-inputs-removed.txt` is a
  required postcondition for each schema-2 sample.

#### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| schema-1 sample/result/aggregate evidence | evidence gate rejects it |
| duplicate `identityKey` or candidate provenance drift | registry validator rejects it |
| missing layer or unsupported result vocabulary | evidence gate rejects it |
| missing target/shortfall consistency | evidence gate rejects aggregate |
| threshold feature without reviewed disposition | evidence gate rejects aggregate |
| bounded tool output or unknown field | retain bounded evidence with `unknownFields` |

#### 5. Good/Base/Bad Cases

- Good: native CI writes schema-2 evidence, sanitizes runner paths, renders a
  distinct-identity histogram, and the post-run gate verifies every record.
- Base: the metadata-only baseline reports the current 20/100 coverage and is
  clearly labeled `registry-baseline`.
- Bad: a report infers support from a feature tag, counts a libc variant as a
  new identity, or uploads a raw archive/temp-root path.

#### 6. Tests Required

- Manifest tests assert identity uniqueness, provenance equality, target count,
  candidate hashes, and variant non-inflation.
- Fingerprint tests assert schema-2 fields, canonical ELF names, and output
  bounds against a real local ELF without acquiring a corpus sample.
- Aggregate tests assert deterministic baseline regeneration, feature
  projection, first-failure normalization, and required-evidence failure.
- Evidence/security tests assert all-layer coverage, threshold dispositions,
  cleanup markers, raw-file rejection, and archive traversal rejection.
- Native CI must run the full approved registry, render the aggregate, then run
  the evidence gate; local metadata tests never substitute for that oracle.

#### 7. Wrong vs Correct

```text
Wrong: accept a schema-1 result because its directory and JSON are non-empty.
Correct: require schema-2 fields, all layer results, cleanup marker, and a
         target-consistent aggregate before upload can pass.
```
