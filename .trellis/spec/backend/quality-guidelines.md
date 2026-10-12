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
- Keep generic ELF validation, packing, layout materialization, and rehydration
  structural by default: they must not decode unrelated executable bytes.
  Whole-image instruction inspection is an explicitly named observation-only
  mode; protection code analysis begins at selected-function roots and may make
  only bounded, demand-driven dependency queries.
- Pin and retain licenses for AsmStone and miniz. Native source, compiler
  inputs, specs hashes, and output hashes belong in provenance.
- Keep final AArch64 instruction-word generation behind the project-owned
  `Aarch64InstructionEncoder` in `Aarch64Semantics`. It may call AsmStone's
  generated object encoder, but AsmStone model types and generated field names
  must not escape that adapter. Semantic and ELF layers calculate relocation,
  TLS ownership, target, addend, range, scale, and address-map facts; they pass
  those facts as project-owned requests to the adapter.
- Every adapter-produced word must decode through AsmStone and the project
  decoder before it is returned. A failed encode or round trip returns no word;
  callers do not preserve a partially encoded template or fall back to local
  opcode/bitfield assembly.

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
- `ValidationWorkflowTests.cs` and `CliApplicationTests.cs` cover atomic output,
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
  toolchains, runtimes, and execution facts. `fixtures/runtime-matrix.json`
  owns the named AArch64 runtime environment covering set and immutable OCI
  pins; run `scripts/check-runtime-matrix-evidence.py` after each producer.
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
- Does every new or migrated AArch64 instruction writer use
  `Aarch64InstructionEncoder`, and is every remaining manual writer recorded
  with an owner, replacement slice, and focused test?

## Examples

- `src/UrProtect.Core/StructuralElf/ElfParser.cs` demonstrates bounded program-header,
  dynamic-table, note, relocation, and symbol-version parsing.
- `src/UrProtect.Core/Application/Pack/ElfPackService.cs` demonstrates source/launcher
  separation, atomic wrapper publication, and final recovery verification.
- `tests/UrProtect.Core.Tests/Cli/GoldenReportTests.cs` demonstrates stable
  report snapshots rather than assertions on incidental console formatting.
- `native/urprotect-launcher/Makefile` demonstrates the pinned static-PIE
  compile/link contract and strict AArch64 build checks.

## Scenario: AsmStone-backed AArch64 instruction encoding

### 1. Scope / Trigger

This contract applies whenever managed protection, semantic relocation, TLS
materialization, layout, a fixture builder, or a golden test generates or
re-encodes an AArch64 instruction word. It establishes the one encoding
boundary between UrProtect's ELF/TLS semantics and AsmStone's instruction
codec.

### 2. Signatures

The project-owned API is:

```text
Aarch64InstructionEncoder : IAarch64InstructionEncoder
  TryEncode(Aarch64InstructionEncodeRequest)
    -> Aarch64InstructionEncodeResult
  TryCreate(Aarch64InstructionBuildRequest)
    -> Aarch64InstructionEncodeResult
```

`Aarch64InstructionEncodeRequest` carries the source word/address, output
address, one project-owned `Aarch64InstructionEncodingFamily`, the resolved
target or immediate, optional access width, optional output template, an
explicit source-immediate preservation flag, and optional register width.
`TryCreate` is reserved for adapter-backed fixture or generated-instruction
construction. Current owned families are Branch26, Call26,
ConditionalBranch19, TestBranch14, AdrPrelLo21, AdrPrelPgHi21, Literal19,
AddImmediate, LoadStoreUnsignedImmediate, MoveWideImmediate, MoveRegister,
CompareImmediate, and Return.

`Aarch64InstructionEncodeResult` returns `IsSuccess`, a word, the project-owned
`Aarch64Instruction`, a stable adapter diagnostic code, and a bounded message.
The adapter diagnostic codes include invalid request, source/template decode
failure, unsupported family, operand/width failure, target misalignment or
range failure, backend failure, and round-trip failure.

### 3. Contracts

- Source and output addresses are four-byte aligned and source words must
  decode before re-encoding.
- An output template, when supplied, must decode to the same instruction
  family as the source. The adapter does not infer a different opcode from a
  relocation type.
- AsmStone owns operand legality, register/width/scale encoding, and generic
  PC-relative target encoding. UrProtect owns relocation-family selection,
  TLS symbol/module/GOT/TLSDESC ownership, addends, address-map placement,
  target calculation, range policy, and relaxation decisions.
- The adapter invokes AsmStone encoding and then decodes the result through
  AsmStone and the project decoder. It returns a successful result only when
  the decoded family and requested target/immediate/width still match.
- `Aarch64SemanticFixupEncoder` uses the adapter for Branch26/Call26,
  conditional/test branches, ADR/ADRP, literal loads, ADD low-12, and
  unsigned LDR/STR low-12. Dispatcher MOV/CMP/branch/RET generation,
  layout direct and near-veneer branches, TLSIE literal/pairs, local-exec
  field preservation, dynamic TLS resolver/module/DTPREL output, and TLSDESC
  output use the same boundary. Remaining raw masks are recognition or
  invariant checks only; they are not a second writer.
- GNU assembler/linker output remains an independent ABI/toolchain oracle. It
  can provide a positive fixture, but it does not replace the project adapter
  in managed production paths.
- Raw masks are permitted for bounded recognition or validation only when the
  instruction is also checked through project-owned AsmStone-projected
  operands. They are not a new final-word encoding mechanism.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| source/output address is not four-byte aligned | `InvalidRequest`; no word |
| source or output template cannot be decoded | source/template decode diagnostic; no word |
| requested family does not match decoded instruction | unsupported-family or invalid-operand diagnostic; no word |
| PC-relative target is misaligned or outside its signed range | target alignment/range diagnostic; semantic caller maps it to its stable fixup diagnostic |
| immediate width, access width, or load/store scale is invalid | operand/width diagnostic; no word |
| AsmStone encode fails | backend diagnostic; no fallback encoding |
| AsmStone or project decode round trip changes family or requested value | round-trip diagnostic; no publication |
| instruction is individually encodable but TLS relocation/GOT/PT_TLS facts are inconsistent | TLS semantic/layout diagnostic before materialization; encoding success does not override ELF validation |
| a new production writer bypasses the adapter | review/architecture failure; add or migrate the adapter seam first |

### 5. Good/Base/Bad Cases

- Good: UrProtect validates a TLS relocation and mapped target, sends a typed
  request to `Aarch64InstructionEncoder`, verifies the AsmStone/project decode
  round trip, and materializes only the returned word.
- Base: an existing manual writer remains while its owner, replacement test,
  and bounded migration scope are recorded in the task research; it does not
  receive new instruction families.
- Bad: a semantic or layout consumer imports AsmStone model types, copies an
  opcode mask into a new writer, accepts a backend failure by retaining the
  source word, or treats an encodable instruction as proof of valid TLS
  relocation ownership.

### 6. Tests Required

- `tests/UrProtect.Core.Tests/Semantics/Aarch64InstructionEncoderTests.cs`
  must cover adapter construction, PC-relative remapping, ADD and unsigned
  load/store width/scale requests, target alignment/range rejection, and
  mandatory AsmStone/project round trips.
- `tests/UrProtect.Core.Tests/Semantics/SemanticRelocationTests.cs` and TLS
  workflow tests must prove the production semantic fixup path uses the
  adapter while retaining relocation/addend/address-map decisions in
  UrProtect.
- Positive fixture and golden words must come from the adapter or a named GNU
  assembler/linker oracle and must decode through AsmStone. Nearest-negative
  cases mutate structured operands or relocation metadata from valid fixtures.
- Release build, focused adapter/semantic/TLS tests, full managed tests,
  `git diff --check`, task validation, architecture checks, and the applicable
  native checks must run before promotion. Missing `musl-gcc` is retained as
  an explicit environment gap for the launcher lane.

### 7. Wrong vs Correct

```text
Wrong: calculate a TLS target, OR it into a local opcode mask, and keep the
       source word when AsmStone rejects the result.

Correct: validate TLS ownership and the mapped target in UrProtect, submit a
         project-owned request to Aarch64InstructionEncoder, require both
         AsmStone and project decode round trips, then publish only that word.
```

## Public real-sample CI corpus

`fixtures/real-samples/manifest.json` is a separate ecology evidence layer from
`fixtures/manifest.json`. It locks exactly 100 distinct public AArch64 upstream
project identities, records the approved target of 100, and retains
archive/version/file hashes, extracted paths, runtime facts, and layer
policies. A libc/build variant is an attribute of one identity and never
another corpus count. The candidate ledger and selection report retain why
selected, rejected, and deferred public candidates differ.

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

The bounded extractor and its schema share archive/member/expanded-size limits
through `scripts/real_sample_schema.py`. Alpine v3.22 APKs are gzip-compressed
tar archives with `.SIGN.*`, `.PKGINFO`, and payload paths directly in the
archive; the runner checks locked package name, version, `aarch64` architecture,
origin, and license from `.PKGINFO` before static inspection. Do not treat an
APK as a tar containing a nested `data.tar.gz`; any new APK packaging format
requires a separately named, bounded extraction contract and fixture.

Static evidence is mandatory for all 100. An applicable dynamic oracle must run
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
- Base: the metadata-only baseline reports the current 100/100 coverage and is
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

## Scenario: Managed TLS semantic rewrite and current artifact handoff

### 1. Scope / Trigger

This contract applies when selected-function protection encounters AArch64 TLS
relocations. Structural PT_TLS facts, typed TLS bindings, semantic fixups, the
canonical Protected Image v1 snapshot operation, and shared layout/materializer
validation must remain one flow. The current managed rewrite slice is bounded
and does not by itself promote a native runtime claim.

### 2. Signatures

```text
FunctionProtectionService.Plan(ELF_BYTES, FunctionProtectionOptions)
  -> FunctionProtectionPlanResult

SemanticPlanSnapshotCodec.Create(SemanticRewritePlan)
  -> SemanticPlanSnapshotResult

ProtectedImageSemanticPlanSnapshot(canonicalBytes, planSha256)

TlsSemanticFixupPlanner.Build(SemanticRewritePlan)
  -> TlsSemanticFixupPlanResult
```

The current managed positive forms include:

- local-exec `ADD_TPREL_HI12 + ADD_TPREL_LO12/LO12_NC`;
- local-exec `ADD_TPREL_HI12 + LDST32_TPREL_LO12_NC`;
- local-exec `MOVW_TPREL_G1 + MOVW_TPREL_G0_NC`;
- initial-exec `MOVW_GOTTPREL_G1 + MOVW_GOTTPREL_G0_NC` with one preserved
  `R_AARCH64_TLS_TPREL64` GOT owner;
- initial-exec `ADR_GOTTPREL_PAGE21 + LD64_GOTTPREL_LO12_NC` with the same
  preserved GOT owner and validated page/scale semantics;
- initial-exec standalone `LD_GOTTPREL_PREL19` with one preserved
  `R_AARCH64_TLS_TPREL64` GOT owner and a signed, 4-byte-scaled literal range.
- the exact TLSDESC `ADRP + LD64 + ADD + BLR X1` form with four ordered static
  markers, one preserved 16-byte descriptor owner, paired `DT_TLSDESC_PLT/GOT`
  metadata, and a validated resolver PLT/GOT shape; the marker-owned fallthrough
  block remains adjacent in emitted flattening output.

### 3. Contracts

- `TlsBinding` carries the typed access model, relocation family, image-local
  module/template facts, defined `STT_TLS` symbol, addend, ordered relocation
  sites, instruction sequence, address expression, and profile/runtime needs.
- The producer emits exactly one bounded `ProtectedImageSemanticPlanSnapshot`
  operation whenever transformed TLS fixups are present. It uses
  `SemanticPlanSnapshotCodec` and does not change Protected Image ABI v1 or
  Payload Frame v3.
- Layout and rehydration apply TLS fixups only through the shared
  `ElfLayoutPlanner` and `ElfLayoutMaterializer`. PT_TLS template, zero-fill,
  alignment, relocation identity, and initial-exec GOT ownership are reparsed
  and compared before publication.
- TLSIE ADRP/LD64 requires an adjacent pair, page-congruent ADRP target,
  signed page-range validity, scaled 64-bit LD64 low-12 offset, and a TP-relative
  ADD that does not overwrite the GOT-loaded value before the final access.
- TLSIE LD_GOTTPREL_PREL19 requires one standalone 64-bit literal load, a unique
  writable `R_AARCH64_TLS_TPREL64` GOT owner, and a signed 19-bit displacement
  scaled by four; no ADR/ADRP instruction pair is part of this form.
- Planner and materializer bind all relocation/source/output offsets through
  checked bounded ranges before subtraction or integer conversion.
- A decoder may report zero optional operand-width metadata. The semantic
  projector fills missing widths from a decoded register or memory base and
  uses bounded scalar defaults for non-register operands; nonzero decoder widths
  are preserved. Snapshot validation still rejects zero or out-of-range widths.
- Native adapter/baseline evidence, managed semantic evidence, and transformed
  runtime evidence remain separate. A local environment or one runtime never
  promotes another runtime.

### 4. Validation & Error Matrix

| Condition | Required result |
| --- | --- |
| missing snapshot for transformed TLS operations | reject before materialization/publication |
| model, family, symbol, pair order, addend, or register mismatch | stable TLS semantic diagnostic; no artifact |
| incomplete ADD/MOVW/LDST32/ADRP-LD64/LD_GOTTPREL_PREL19/TLSDESC sequence or non-supported TLS form | fail closed before layout |
| initial-exec GOT or TLSDESC descriptor missing, duplicated, overlapping, non-writable, or unmapped | stable GOT/TLS diagnostic; no output |
| source/output range, opcode, width, scale, or address-map mismatch | layout diagnostic; no Native Image |
| PT_TLS/template/zero-fill/relocation reparse mismatch | output validation failure; no publication |
| zero or unbounded canonical operand width | snapshot malformed diagnostic |
| unavailable native toolchain/runtime | explicit `environment-unavailable`; no promotion |

### 5. Good/Base/Bad Cases

- Good: a selected TLS function produces a canonical typed snapshot, shared
  layout fixups preserve PT_TLS/GOT facts, output reparses equivalently, and
  publication is atomic.
- Base: managed semantic/layout tests pass while transformed glibc, musl, or
  bionic execution evidence is still absent; the runtime claim remains open.
- Bad: a producer carries only raw TLS bytes, rescans unrelated code, accepts a
  missing GOT owner, or treats native adapter acceptance as managed rewrite
  support.

### 6. Tests Required

- Structural tests cover PT_TLS ranges, template/zero-fill, TLS relocation
  identity, GOT ownership, truncation, overlap, and malformed metadata.
- Semantic tests cover each accepted pair, nearest unsupported pair, opcode and
  register ownership, addend/symbol identity, canonical snapshot round-trip,
  digest/tamper rejection, and bounded operand widths.
- Integration tests cover producer snapshot emission, rehydration, shared layout
  output reparse, PT_TLS/GOT equivalence, incomplete pairs, source mismatch,
  mapping conflicts, and no-partial-publication.
- Native matrix tests must separately retain baseline/transformed status,
  streams, per-thread values, lifecycle order, toolchain/runtime identity, and
  rollback evidence for every promoted model/profile/runtime row.

### 7. Wrong vs Correct

```text
Wrong: copy a TLS relocation into an artifact and let rehydration infer its
       model or GOT ownership from unrelated output bytes.
Correct: recognize a bounded typed sequence, carry its canonical snapshot,
        map every source site through the shared layout plan, reparse the
        output, and publish only after identity and TLS facts match.
```

## Scenario: Linked retained TLS relocations

When a linked AArch64 ELF retains section-owned relocation records, the record's
symbol index belongs to the linked section symbol table (`SHT_SYMTAB`), while
loader-owned dynamic/GOT records use the dynamic symbol table (`DT_SYMTAB`).
Raw indices and `r_info` remain preserved for round-trip identity, but semantic
owner matching across those records compares the complete bounded TLS symbol
identity (name, binding, type, visibility, section, value, and size), never a
raw index from the other table. A linked `--emit-relocs` instruction may also
retain an already-resolved page/low-12 field; accept it only when the decoded
page and scaled low-12 value equal the carried GOT owner plus addend. The
relocatable zero-field form remains valid, and any inconsistent nonzero field
fails before snapshot or publication.
