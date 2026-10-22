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
- Native indirect-control promotion must execute every declared bounded
  jump-table target, not infer coverage from table contents or fixture presence.
  Retain measured source/transformed handoff records and exact baseline/target
  stdout/stderr bytes plus hashes; the evidence checker recomputes status and
  stream comparison from those files, binds the selected function and case
  symbols to the source ELF dynamic symbols, binds source entries to the
  source table's mapped file range, and binds rewritten entries to the declared
  output table range. Dispatch-chain recognition must check the exact opcode:
  in particular, ADD-immediate bit 23 must exclude tagged ADDG rather than
  accepting it through the shared high-byte prefix. Keep a refreshed-checksum
  Native Image opcode-substitution regression.
  The current bounded relative-table row uses a distinct
  PF_R-only clone under layout schema 3:
  verify its file-backed placement, ownership ordinal and clone/retarget policy,
  exact per-entry target/base bindings and bytes, the unchanged original table,
  and the selected consumer's decoded reference to the clone. Do not apply the
  retired schema-2 assumption that edit offsets point into the source table.
  Reject refreshed-checksum forgeries of these facts as well as bool/float/string
  ownership ordinals. Its address-map range must cover the selected function and all
  case targets and map to file-backed executable output. Layout evidence also
  retains one planner-derived typed binding per table entry: table/entry/target
  identities, entry index and source row, source target/base VAs, and the mapped
  output target/base VAs. The checker independently recomputes each target from
  the retained address map and each signed-32-bit entry from those VAs, then
  compares it with source table bytes, layout edits, and Native Image bytes;
  missing, duplicate, remapped, or checksum-refreshed forged bindings fail.
  The shared-table copy slice first introduced canonical semantic snapshot v3
  (`URP-SPS3`) to persist bounded owner/reference-site evidence; the current
  single semantic schema is v6 (`URP-SPS6`), with the unchanged provider-facts
  external-table record (discriminator 8) and appended typed selected-consumer
  companion (9) alongside the static function-pointer call owner, while strictly
  rejecting v1-v5. See [external consumer publication](./external-consumer-proof.md)
  for exact source/fixup, logical-map and complete final-emission validation. SPS6 retains the semantic snapshot byte
  ordinals `SelectedFunctionPrivate=0`, `Shared=1`, `External=2`,
  `RuntimeOwned=3`, and `Ambiguous=4`. These are distinct from layout-evidence
  schema v3 JSON ownership ordinals; see
   `runtime-compatibility.md` for that mapping and its exact-integer-token
   validation requirement. The provider-facts reader takes one bounded private
  input snapshot after the raw-size gate, verifies its SHA-256, and uses that
  same snapshot for ELF parsing and all retained provider facts; do not reuse
  caller-owned bytes after the copy. Test the maximum-plus-one refusal before
  copy/access, wrong-hash rejection before parsing, and deterministic mutation
  on a later caller-memory observation. Its strict single-`PT_DYNAMIC` /
  no-`PT_INTERP` rule is provider-profile-only: retain the ordinary parser's
  zero-`PT_DYNAMIC` behavior. Provider facts alone still do not establish
  consumer `GLOB_DAT`/GOT semantics or executable publication. Managed pinned
  admission requires the linked consumer companion, independently rederived
  source analysis/fixups and unchanged GOT mappings, then whole-output
  re-emission plus exact producer-offset, entry, dependency and owner checks.
  Neither managed publication nor the earlier native source-loader self-test
  alone establishes runtime acceptance. A scoped native AArch64/glibc
  source-versus-rehydrated-Native-Image run and separate provider-loaded
  rollback evidence are now retained with exact-root checkers and local CI
  wiring; the feature remains `unknown` / `scoped-observation-not-promoted`
  until the hosted gate passes. See the [runtime evidence contract and current
  inventory](./runtime-compatibility.md#scenario-external-provider-managed-admission-and-scoped-native-evidence).
  Do not promote musl/Bionic or general provider/table support. Layout evidence
  remains schema 3 to retain clone ranges, permissions, ownership, rewrite
  policy, and per-entry target/base bindings. The Protected Image ABI
  remains v1. Its independent native glibc checker proves one selected
  `urp_entry` consumer reads a distinct read-only file-backed clone while an
  unselected `urp_observer` keeps its original table bytes/reference chain;
  this is limited to the controlled signed-32-bit shared-table fixture and does
  not promote other encodings or runtimes. For a proven bounded in-image table
  with an exact selected ADRP/ADD reference but incomplete owner inventory, the
  managed safe-default is `Ambiguous` ownership plus the same distinct PF_R
  clone-and-retarget policy. Global/default-visible symbols and missing or
  stripped metadata prove neither `Shared`, `SelectedFunctionPrivate`,
  `External`, nor `RuntimeOwned`.
  Leave the source table and unselected/unknown references unchanged.
  Rehydration must re-decode the selected source reference chain and rederive
  every carried owner fact/classification before layout/publication; a changed
  selected chain or conflicting selected-site relocation fails before Protected
  Image or Native Image publication. Derive each owner function's section
  identity and executable/file-backed address/file bounds from the retained
  source ELF; every section-linked RELA row must have bounded `sh_info` equal
  to that function's `st_shndx`, contain the complete function and four-byte
  relocation site, and map the site to the section's file bytes. Carry these
  typed section facts through the current URP-SPS6 snapshot, then independently
  cross-check them against source section headers, linked RELA rows, and
  function symbols at rehydration publication; any mismatch or ambiguity
  discards the ownership proof. The static local function-pointer row separately
  carries exact caller/target symbol and section identities, the ordered
  ADRP/ADD/stack spill/reload/BLR chain, exact static RELA sites, and an
  identity-preserved callback range; rehydration re-derives these from source
  ELF and validates the emitted caller and final callback VA/bytes. This is a
  compiler/toolchain-shaped same-image local/hidden `STT_FUNC` mode only;
  arbitrary pointers, imported function pointers, moved callees, veneers, and
  runtime translation remain unpromoted. Python evidence consumers retain the
  nested semantic snapshot as opaque bounded bytes plus its digest. Retain each observer helper's actual process
  exit status and stdout/stderr bytes, bind their hashes/statuses in behavior
  evidence, and require exact source/transformed image hashes, HostContext
  loader identity, release order/status, no failure stage, and expected fixture
  stream behavior. Keep the malformed-table and
  post-CMP/B.HI checked-index-clobber negatives separate,
  require the producer's stable
  diagnostic and actual failed stage, and prove no Protected Image, Native
  Image, or loader handoff was published. Refreshed-manifest tampering tests
  cover forged equality, stream hashes, statuses, negative diagnostics, and
  missing negative artifacts. A true out-of-range relative-entry negative must
  be distinct from an in-image target outside the selected closure: retain the
  exact pre-mutation input and mutated source ELF, independently parse the table
  symbol/range and signed entry/base, recompute the target, and prove it lies
  outside every PT_LOAD memory range and executable file-backed range. Preserve
  the actual producer command, structured failed producer stage and exit status;
  require its stable out-of-executable-PT_LOAD diagnostic and reject refreshed
  checksums that forge the table value, target/range, diagnostic, or publication
  claims. A separate external-table nearest-negative source must use an undefined
  dynamic STT_OBJECT imported by `urp_entry`, one exact non-PLT
  `R_AARCH64_GLOB_DAT` bound by dynsym index, and a guarded ADRP/GOT-LDR to
  indexed signed LDRSW to relative ADD to BR dataflow chain. The evidence
  checker reparses PT_DYNAMIC, dynsym/string facts, RELA ownership, writable
  file-backed GOT mapping, and selected-function bytes from the retained
  source ELF; the GOT slot is a pointer carrier, never external table storage.
  The source-byte proof must bind the taken bounds-branch edge to the exact safe
  default-return path, prove its bounded instructions terminate without
  re-entering or reaching the GOT/indexed-read/relative-dispatch chain, and
  reject an in-function destination that can enter that chain. Keep a
  checksum-refreshed raw-ELF branch-immediate mutation targeting the indexed
  read, and assert rejection for the unsafe bounds destination rather than a
  stale hash. Bind the observed producer command/source digest/exit/stage and stable
  diagnostic, reject downstream publication, and reject refreshed checksums
  that forge owner, relocation, GOT, instruction-link, diagnostic, or stage
  facts. This negative establishes fail-closed behavior only and does not claim
  external-table support or widen indirect-call admission.
- Native CFI promotion must retain genuine typed C++ throw/catch execution
  through the transformed target FDE and register-call assembly frame. Keep the
  C `setjmp`/`longjmp` observation separately named; require the exact BLR
  return-PC symbol/offset and an active assembly FDE covering that PC, plus
  throw-site target-frame/return-PC observations, token-specific catch, no
  normal target return, one RAII cleanup, successful release, and measured
  source/target process results. Bind each runtime target start/end and callback
  PC through measured load bias, mapped VA/extent, and the retained rehydration
  address map using overflow-checked arithmetic; recompute address-derived
  booleans rather than trusting flags, and keep the checks independent of ASLR
  absolute addresses. Retain C/C++ compiler plus libstdc++/libgcc/glibc
  identities. The evidence checker must reject refreshed-checksum tampering;
  these relational checks do not establish cryptographic authenticity of
  self-reported runtime observations. Malformed-CFI rollback remains an
  independent negative gate.
- HostContext worker-lifetime changes require the real-linker initial-exec TLS
  fixture on native AArch64 glibc, with inherited event/gate pipes, exact
  readelf TLS/relocation facts, explicit and automatic joins, TLS teardown
  before image destructor, serial reruns, concurrent independent dispatches,
  and retained runtime identity/status/hash evidence. Musl/bionic execution is
  not a substitute for the glibc cell.
- Native indirect-control evidence must bind a handoff to independently checked
  runtime identity and prove both unique file-backed and page-rounded `p_memsz`
  `PT_LOAD` ownership of each VMA, using checked half-open arithmetic. Reject
  VA-only aliases, BSS intersections, partial intersections, and overflow while
  accepting valid adjacent ranges and RELRO splits. Standalone checkers must
  scan a bounded no-follow evidence tree (512 directories including root) and
  load sibling helpers through explicit file-relative bounded reads rather
  than ambient `PYTHONPATH`. Run Python evidence tests with `PYTHONPATH` unset;
  keep optional historical glibc handling distinct from mandatory fresh glibc
  and musl identity. See the [native runtime identity contract](runtime-compatibility.md#scenario-native-runtime-identity-and-pt_load-ownership-for-ordinary-indirect-control-evidence).

Package-merge cleanup tests must inventory only resources owned by that test,
not a before/after glob of shared `/tmp`. Keep the real merge shell, privilege
drop, timeout, path-security checks, and exit status intact. A test-only
`mktemp` interceptor must validate the exact production invocation and delegate
to the real executable under a private root accessible to the dropped UID.
Test both an unrelated concurrent stage (ignored) and a leaked owned stage
(rejected). Capture return code and both streams on failure. A green rerun or
fixed cleanup assertion does not explain a historical nonzero child exit;
retain that failure separately until its cause is established.

Use external `readelf`/`llvm-readelf` checks for produced ELF structure when a
change affects a launcher, fixture, or release. Compare runtime behavior using
status, stdout, stderr, signals, cwd, environment, and declared files; exclude
ASLR addresses and timing.

## Scenario: Native musl fixture-build boundary and failed-build evidence

### 1. Scope / Trigger

Apply this contract when ordinary indirect-control or HostContext rehydration
runners build the musl fixtures/helper. It records build-stage diagnostics, not
runtime identity; the separate [native runtime identity contract](runtime-compatibility.md#scenario-native-runtime-identity-and-pt_load-ownership-for-ordinary-indirect-control-evidence)
remains authoritative for musl execution evidence.

### 2. Signatures

```sh
make -C native/urprotect-runtime \
  "CC=$runtime_cc" "LD=ld" \
  BUILD_DIR=build/musl-indirect-control \
  jump-table-fixture jump-table-index-clobber-fixture external-jump-table-fixture
```

For a failed ordinary build, retain Make stdout/stderr under
`<upload-root>/ordinary/` and command/status diagnostics under its sibling
`<upload-root>/ordinary.native-build-diagnostics/`.

### 3. Contracts

- Keep `CC` bound to the selected `musl-gcc` driver for C compilation and
  helper linkage; set `LD=ld` for Makefile recipes that directly invoke the
  linker with options such as `--build-id=none`, `--no-undefined`, and
  `--eh-frame-hdr`.
- The ordinary runner records exact Make argv, build cwd, runtime, both output
  streams, and the actual exit status; it propagates the Make status and stops
  before readelf, handoff, or evidence checking on failure.
- Keep the command/status sidecar next to (not inside or outside) the ordinary
  evidence directory. The `if: always()` upload must cover their shared
  run-specific parent, including failed-build diagnostics.
- A fake-tool regression proves this failure path only; musl acceptance still
  requires the pinned producer and exact-root runtime-identity checker.

### 4. Validation & Error Matrix

| Condition | Required result |
|---|---|
| Musl assembly fixture links with linker-only flags | direct `LD=ld`; C compiler remains `CC=musl-gcc` |
| Ordinary Make fails | preserve exact stdout/stderr, argv/cwd/runtime, and status; exit with the same status; publish no success evidence |
| Diagnostic sidecar is outside the uploaded run root or status is lost | executable regression fails |
| Required architecture/toolchain is absent | explicit environment failure; no substitute runtime or success claim |

### 5. Good / Base / Bad Cases

- Good: an isolated fake `make` exits 23; the runner exits 23, retains both
  streams and a `23\n` status, and uploads its sibling command record.
- Base: Make succeeds, after which the normal ELF, HostContext, and exact-root
  checks still run.
- Bad: pass `musl-gcc` as `LD` for direct linker flags, discard child status,
  or treat a fixture-build failure as musl runtime evidence.

### 6. Tests Required

`tests/test_rehydration_evidence.py` must retain both the CC/LD source-contract
check and `test_musl_jump_table_runner_retains_and_propagates_stubbed_make_failure`.
The executable test copies the ordinary runner into a private temporary tree,
stubs `uname -m` and the availability-only `musl-gcc`, and uses a bounded fake
`make` that emits distinct streams and exits 23. Assert runner status, exact
stream bytes, exact sidecar status, `musl`/cwd/argv (`CC=<stub>`, `LD=ld`, the
isolated build directory and targets), upload-parent containment, and that the
compiler stub was not invoked. Also run shell syntax and diff hygiene checks;
the hosted musl producer/checker remains a separate gate.

### 7. Wrong vs Correct

```text
Wrong: CC=musl-gcc LD=musl-gcc -> direct $(LD) receives linker-only flags.
Correct: CC=musl-gcc LD=ld -> preserve and upload failed-build diagnostics;
         require the hosted exact-root runtime check before claiming musl evidence.
```

## CI and Release Contract

- Required native Linux jobs run on `aarch64` and retain an environment report.
- Changes to an auxiliary registry such as `fixtures/manifest.json` must
  synchronize its current `compatibility-corpus.json` retained-registry digest
  and the current `evaluator-protocol.json` corpus digest in the same batch.
  Validate the complete live digest chain; do not rewrite historical immutable
  baselines or weaken digest checks to repair a stale current registration.
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
- For host-pinned provider input, does Infrastructure open nonblocking and
  no-final-symlink, verify regular-file type/size through the descriptor, and
  snapshot that same handle before pre-parse SHA verification? Is a FIFO with
  no writer promptly rejected rather than blocking before validation?
- Do external-consumer tamper tests refresh both snapshot/artifact digests and
  include a mapped dead chain after the live BR is removed? Does publication
  compare the full source-derived emitted output and offsets, not branch counts?
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

## Scenario: Bounded private provider-file input

### 1. Scope / Trigger

Apply this contract to host-supplied external provider bytes before semantic
planning or rehydration. Application code coordinates but performs no direct
file I/O. Do not replace the Infrastructure adapter with `File.ReadAllBytes`,
a blocking `FileStream` followed by type validation, or a path-stat/reopen pair.
See [managed publication](./external-consumer-proof.md) for admission after the
snapshot has been pinned and [provider errors](./error-handling.md#scenario-managed-external-provider-failures)
for sanitized failure propagation.

### 2. Signatures

```csharp
// Application coordinator; returns private bytes or sanitized diagnostics.
public static ExternalJumpTableProviderFileSnapshot Read(
    ExternalJumpTableProviderInput input); // ExternalJumpTableProviderFileReader

// Infrastructure owns all path/descriptor access.
public static FileSnapshot ReadBoundedPrivateSnapshot(
    string path, int maximumBytes); // FileSystemAdapter

// Internal Linux descriptor owner and deterministic race-test seam.
internal static SafeFileHandle OpenReadOnly(string path); // LinuxSafeFileInput
internal static FileSnapshot ReadFromOpenedHandle(
    SafeFileHandle handle, int maximumBytes, string fullPath = "",
    Action? afterInitialSizeValidation = null);
```

### 3. Contracts

- Supported safe-open hosts are **Linux/AArch64 and Linux/x64** with audited
  open flags and `statx` UAPI; other architectures and non-Linux hosts fail
  closed with `InputIoFailure`. This is a managed input-helper policy, **not**
  an x64 ELF/runtime backend. The product ELF remains AArch64-only. Linux/AArch64
  safe-file tests were executed; Linux/x64 and unsupported-host branches were
  statically reviewed, not executed by the accepted review.
- Normalize the host path, open once with
  `O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`, immediately transfer descriptor
  ownership to `SafeFileHandle`, and dispose it on every path. `O_NOFOLLOW` is
  `0x8000` for AArch64 and `0x20000` for x64; never guess on another architecture.
  This forbids a **final-component** symlink; it does not promise a sandbox or
  no-follow traversal of every ancestor directory.
- Query **that descriptor** using `statx(fd, "", AT_EMPTY_PATH, STATX_TYPE |
  STATX_SIZE, ...)` and the fixed 256-byte Linux UAPI shape; require both mask
  bits and `S_IFREG` before allocating or reading file bytes. No fallback to a
  libc-specific `struct stat` layout or reopening a checked path is allowed.
  A directory/device/FIFO is not an empty provider. `O_NONBLOCK` is required
  before type inspection: an unopened FIFO cannot first be rejected by fstat.
- Reject length above the supplied maximum (provider maximum **8 MiB**) before
  allocating; checked-convert only the accepted descriptor length. Read exactly
  that length with offset-based `RandomAccess.Read` on the same handle. Early
  EOF is truncation, never success with a shorter array. Probe one byte at the
  original end for growth, query descriptor type/size again, and require the
  original regular-file size. Reject growth even if the initial length fit.
  Path replacement must not change which inode supplies the snapshot.
- File size checks are not a content-integrity proof. Public provider-reader
  input gets one private copy after the raw-size gate; the managed file path
  passes its already private bytes to `ReadPrivateSnapshot`. Hash that snapshot
  and require fixed-time SHA-256 equality **before** ELF parsing. Every retained
  provider identity, table byte and target fact must use that same byte array.
- Provider paths, the `ExternalJumpTableProviderInput` pin object and raw
  exception text never enter semantic snapshots or provider diagnostics/reports.
  Derived SONAME/build-ID/content hash remain semantic facts. Internal
  `FileSnapshot.FullPath` is host bookkeeping, not a serialization field;
  Application projects only bytes/diagnostics into provider planning.
- No new provider environment key is introduced. The native configured-provider
  aggregate parser-work budget (8 MiB) is a separate work contract, not the
  managed raw-file length limit; neither can substitute for the other.

### 4. Validation & Error Matrix

| Boundary | Required result |
|---|---|
| Blank/invalid path or negative byte limit | sanitized `InvalidArgument`; no successful snapshot |
| Non-Linux, unaudited architecture, unavailable `open`/`statx` or failed descriptor query | sanitized `InputIoFailure`; no portable read fallback |
| Final symlink, directory, FIFO without writer or device | `InputIoFailure`, empty bytes; FIFO rejected promptly without an external writer |
| Initial size is maximum + 1 | `SemanticPlanSnapshotLimitExceeded` before file-byte allocation/read |
| EOF before initial length, end probe sees data or final descriptor size/type differs | `InputIoFailure`, empty bytes; no partial snapshot |
| Path replaced after descriptor size query | original descriptor bytes, never replacement-path bytes |
| Correct bounded snapshot, wrong SHA | `OutputIdentityMismatch` before ELF parser invocation |
| Correct snapshot/hash, invalid ELF/provider profile | bounded semantic/parser failure, no publication |

### 5. Good / Base / Bad Cases

- Good: exact-limit regular file, one nonblocking no-final-symlink descriptor,
  same-handle snapshot, pre-parse SHA match, bounded provider facts.
- Base: a symlink or FIFO is refused with redacted diagnostics; no output is
  published and no missing host capability is labeled native coverage.
- Bad: size-check a pathname then reopen it, block on FIFO open before checking
  type, silently accept a shortened read, or hash caller memory and parse it
  again after a possible mutation.

### 6. Tests Required

- `LinuxSafeFileInputTests.ReadsRegularFileWithinExactLimitAndRejectsMaximumPlusOne`
  asserts exact bytes versus limit diagnostic/empty failure bytes.
- `RejectsDirectoryAndFinalSymlinkWithoutFollowingTheSymlink`,
  `RejectsFifoPromptlyWithoutAnExternalWriter` (two-second bound) and
  `RejectsCharacterDeviceInput` assert `InputIoFailure` and path-redacted messages.
- `DescriptorRemainsBoundToOriginalRegularFileIfPathIsReplaced` replaces the
  path at `afterInitialSizeValidation`; assert original snapshot and distinct
  replacement bytes. Growth and truncation tests mutate deterministically at
  that same seam and assert failure/empty bytes/redaction, not a flaky race.
- `SemanticExternalJumpTableProviderReaderTests` asserts maximum-plus-one refusal
  before observing caller memory, hash rejection before parsing and mutation
  isolation through one private snapshot. CLI/publication tests assert missing
  provider and sanitized errors leave no successful artifacts.
- Preserve the accepted Linux/AArch64 executed-versus-Linux/x64 static-review
  distinction in any report; an unavailable host/test skip cannot promote it.

### 7. Wrong vs Correct

```text
Wrong: FileInfo(path).Length -> FileStream(path) -> reject non-regular file
       (can hang on a FIFO or reopen a replacement); hash then reread path.
Correct: no-follow/nonblocking open -> descriptor regular-file/size check
         -> exact same-handle read + growth/final-size checks -> private bytes
         -> fixed-time SHA comparison -> bounded parse -> publication validation.
```
