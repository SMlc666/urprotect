# Independent evaluator analysis and Protected Image local gates

**Role:** independent analysis only; no product, evaluator, manifest, CI, or baseline changes.

**Active child task:** `.trellis/tasks/10-05-analyze-evaluator-protected-image-gate`

**Analysis artifact:** `.artifacts/evaluator/pr/`

## 1. Measurement binding and reproducibility

The conclusions below are bound to the normative evaluator result and its advisory analysis handoff. The result describes the evaluator's frozen commit, not automatically the current checkout.

| Binding | Identifier / SHA-256 |
|---|---|
| Evaluator `gate.json` | `9cb2e039e2fefcb8be328340034ad06589d58f20103f410b6e2c49112d2009db` |
| Evaluator `analysis-input.json` | `231a984636d7d619c287aded6260d9f4ee5f375ad95da5f4497331b3c91120b2` |
| Root evaluator checksum file (`SHA256SUMS`) | `c5fe543bba725b6e008ff2b83b6c50bbfe3a9579721f5c20c1e87e0c9bc059ea` |
| Evaluator closed-tree inventory digest, recorded in gate | `eb6723fc0219af95f1b09ec7cb6757f81ef5f08ecefad66b8e4e91ca5e08953c` |
| Measured commit (`gate.commit`, `environment.commit`) | `86270e71362572d32544c9fa979553e2f3c4cb7c` |
| Current analysis checkout `HEAD` | `42f48788f7a8ba034e270a7639d58224a218b3b6` |
| Compatibility protocol | `evaluator-v1`, `protocol.json` SHA-256 `b3aa29a728cb4e98d4704ab7fa9cd7bf6e4afefaa6e646fde92a211557e8c6bd` |
| Scheme-A protocol | `scheme-a-v1` |
| Compatibility corpus | `compat-corpus-v1`, SHA-256 `8f48bed4fe66a2fde8ad968972fec2654890956d777a54d6394687d5e503efa4` |
| Scheme-A manifest | SHA-256 `bece932bd38e8c3e1def844023e19306acd37583862f17c6e3943c4ecf57eacc` |
| Oracle registry | SHA-256 `91e8a867157808f839edbabaf6c766c00d86e10f10729130debab0ce640175a4` |
| Runtime matrix digest bound by protocol | SHA-256 `8d778d22926ba5e2791f46821623700e0baccad3fce26201e10ba6cf0ea0dac5` |
| Evaluator baseline reference file | SHA-256 `3290389f3c28778131b6a633143f17432cc3ffc807d3e38907e941495636b44c` |
| Immutable compatibility baseline | ID `compatibility-1x-baseline-zero`, SHA-256 `3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2`, baseline commit `86270e71362572d32544c9fa979553e2f3c4cb7c` |
| Evaluator runner / library | `e573f761962e5a950e5e4dbda4305afe629501f3eb108f157a098a203c46d47d` / `8d83ef81144f509f09a305c001426cd05343b0cab12e5067c72631a2ffe997fb` |
| Parent PRD | `.trellis/tasks/10-05-100x-compatibility-protection-benchmark/prd.md`, SHA-256 `064bb8aef50a6b94a9029e2f525014722c6fce5261056013b4c4a41985f16ba3` |
| Child PRD | `.trellis/tasks/10-05-analyze-evaluator-protected-image-gate/prd.md`, SHA-256 `a40b3c665a67e6fade11b1f41810cfae5e7b1c0d372c8cace439f8f5e28e0d92` |

The checked-out protocol/corpus/Scheme-A/oracle/reference files hash to the same values as the copied evaluator artifacts. The artifact root checksum verification passed for every listed evaluator file, including every compatibility and Scheme-A raw evidence manifest. Recomputing the evaluator closed-tree inventory digest, excluding the self-describing `gate.json` and `analysis-input.json` as the checker does, yielded `eb6723fc...e08953c`, equal to both inventory digests in `gate.json`. `python3 scripts/validate-evaluator-manifests.py` passed and reported one compatibility row, six families, compatibility `baseline-zero`, and strength `baseline-not-calibrated`.

**Commit distinction:** the evaluator measured commit `86270e7...` while the current checkout is `42f4878...`. The report therefore states the result for the former immutable artifact. No evaluator run on the current checkout is inferred. The current worktree status observed during analysis showed only the parent Trellis task metadata and this untracked child task; no product-code edit was made in this analysis.

## 2. Measured facts (not proposed decisions)

### 2.1 Compatibility: exact current result

The measured compatibility status is **`baseline-zero`**. The frozen baseline has `completeUnits=0` across one fixed row; the candidate has `candidateFixedCompleteUnits=0` and `candidateGrowthCompleteUnits=0`. The factor is `null`, not a numeric factor. `growthTarget=0` is the protocol's zero-denominator diagnostic; it does not create a positive denominator or a 100x target. `fixedViewPass=true` is a zero-baseline non-regression result, not positive compatibility; `growthViewPass=false`. The evaluator gate is `claimable=false`.

The one frozen row is:

- Unit: `compat.protection-symbolized-fixture.glibc.outer-execveat`
- Source digest: `4f26b59a88c9ccfac1edee65dddb5f3bef2db4d7e7cfad99ec1d032fd8864088`
- Profile/runtime: `outer-execveat` / `glibc.current.native-arm64`
- Declared target: `kernel.execveat-at-empty-path`
- Oracle: `fixture.process-oracle.v1`
- Unit record: `.artifacts/evaluator/pr/compatibility/compat.protection-symbolized-fixture.glibc.outer-execveat/unit.json`
- Raw status record: `.artifacts/evaluator/pr/compatibility/compat.protection-symbolized-fixture.glibc.outer-execveat/raw/strict-chain-status.json`

The exact first failure layer is **`protector`** (`firstFailureCounts: {"protector": 1}`). The unit is incomplete. The product does not declare the strict Protected Image chain; all six recorded chain stages are `not-applicable` with the reason “strict Protected Image chain is not declared by the current product.” This is an absence-of-declared-stage result, not a measured failed execution of a valid Protector/rehydrator implementation. The raw status explicitly says `strictChainMeasured=false` and `nativeResultsCaptured=false`; current direct-ELF, wrapper, and protection evidence is auxiliary.

The measured product gap is: **no product-declared Protected Image ABI/emission stage and no rehydration consumer producing a distinct Native Image handoff record.** Consequently this unit has no strict target-loader or behavioral-oracle result. Existing direct protected ELF output and the current complete-source `PayloadFrame` are not retroactively assigned these roles.

### 2.2 Scheme-A: exact current result

The measured Scheme-A result is **`baseline-not-calibrated`**, with `allRequiredPass=false`. There are exactly six required families; all six remain in the manifest and gate:

| Required family | Frozen tool ID | Measured family result |
|---|---|---|
| `runtime_dump_reassembly` | `scheme-a-dump-reassembly-toolset` | `baseline-not-calibrated`; baseline/candidate replicas `0/0`; costs/factor `null`; environment unavailable; uncensored |
| `patch_repack` | `scheme-a-patch-repack-toolset` | `baseline-not-calibrated`; baseline/candidate replicas `0/0`; costs/factor `null`; environment unavailable; uncensored |
| `function_logic_recovery` | `scheme-a-logic-recovery-toolset` | `baseline-not-calibrated`; baseline/candidate replicas `0/0`; costs/factor `null`; environment unavailable; uncensored |
| `static_decomposition` | `scheme-a-static-toolset` | `baseline-not-calibrated`; baseline/candidate replicas `0/0`; costs/factor `null`; environment unavailable; uncensored |
| `dynamic_instrumentation` | `scheme-a-dynamic-instrumentation-toolset` | `baseline-not-calibrated`; baseline/candidate replicas `0/0`; costs/factor `null`; environment unavailable; uncensored |
| `integrity_handoff` | `scheme-a-integrity-toolset` | `baseline-not-calibrated`; baseline/candidate replicas `0/0`; costs/factor `null`; environment unavailable; uncensored |

Each required tool has `availability=not-calibrated`, `version=null`, and `binarySha256=null`. The evaluator persisted all 36 role/replica attempt records (6 families × 2 roles × 3 replicas), but each says `environment-unavailable`; their command logs say the attack was not started because the pinned toolset is unavailable. There are no attack successes/failures, finite baseline costs, candidate cost lower bounds, or factors to interpret. No family is omitted or marked not-applicable.

The environment record is `environment-unavailable`. Capability fields are exactly: `nativeAarch64=true`; `dotnetSdk=false`; `networkDisabled=false`; `pinnedRuntimeCell=false`; `protectedImageProducer=false`; `rehydrator=false`; `schemeAttackToolset=false`. The unavailable-reason string names `dotnetSdk`, `networkDisabled`, `pinnedRuntimeCell`, `protectedImageProducer`, `rehydrator`, and `schemeAttackToolset`. Although the record names runtime cell `glibc.current.native-arm64`, `loaderIdentity=not-captured`; the environment does not establish the required pinned, isolated cell. This is environment/tool absence, not evidence of attack resistance or attack failure.

### 2.3 Integrity and anti-gaming result

All nine evaluator anti-gaming booleans are true: corpus unchanged, oracle unchanged, attack manifest unchanged, budgets equal, baseline digest matches, required rows present, no unowned status markers, no duplicate identity count, and bounded raw evidence. These establish the artifact/protocol consistency checks only. They do not override zero compatibility, unavailable product stages, absent attack tools, or the `claimable=false` result.

## 3. Repository facts behind the implementation boundary

The repository evidence supports a narrow first implementation slice and warns against confusing current output with the requested chain:

- `src/UrProtect.Core/Protect/FunctionProtectionService.cs:82-235` parses the ELF, resolves explicit selectors, analyzes and transforms selected functions, then writes a final ELF byte array. It needs a free `PT_NULL` slot at lines 194-200. It is a direct ELF transformation, not a declared Protected Image producer.
- `FunctionProtectionService.cs:762-845` appends transformed code as a new executable `PT_LOAD`, using a fixed `0x1000` segment alignment and the unused program-header entry. It patches a branch in each selected function; `TryEncodeBranch` at lines 848 onward uses the bounded AArch64 direct branch encoding. Absence of a header slot, output-size limits, virtual-address placement and branch reach can block otherwise-analyzable functions.
- `FunctionProtectionService.cs:630-667` requires unchanged source bytes outside selected functions and the reserved program-header slot. `tests/UrProtect.Core.Tests/FunctionProtectionTests.cs:105-120` explicitly asserts that lack of program-header capacity returns `ProtectionLayoutUnavailable` and publishes no output. This is a tested current boundary, not speculation.
- `src/UrProtect.Core/Pack/PayloadFrame.cs` v3 compresses and integrity-checks the entire source byte array, with source and encoded digests and an explicit dispatch profile. `src/UrProtect.Core/Pack/ElfPackService.cs` round-trips that frame to the same source bytes before publication. The existing frame is not a separate Protected Image representation or Protected Image ABI.
- `native/urprotect-launcher/launcher_main.c` hands recovered bytes to the OS via an anonymous memfd and `execveat(AT_EMPTY_PATH)`. `native/urprotect-runtime/host_adapter.c` validates a bounded HostContext image and delegates mapping, symbol resolution, relocation, lifecycle and final loader behavior to the native system loader. These are useful precedents for a non-loader rehydration boundary: create/validate Native Image bytes, then use the already-declared native loader rather than implementing dynamic-loader semantics in the shell.
- Existing protection E2E (`scripts/run-protection-e2e.sh`) covers explicit register permutation, control-flow flattening, combined passes, and a branch fixture in native runtime lanes; `scripts/check-protection-evidence.py` validates its records. It has no Protected Image, rehydration, or Scheme-A result role.
- The parent PRD explicitly requires generic Protected Image understanding and leaves dynamic-loader responsibilities with the native loader (R4), complete end-to-end coverage rather than parser/pack/handoff credit (R5), six independent red-team families (R6), and append-only retention (R7-R9).

## 4. Proposed local-gate decisions

The gates below are **proposals for future product child tasks**, not capabilities measured in the present evaluator artifacts. All gate records must carry the measurement-binding tuple from §1 (at minimum the fixed unit/source ID, `evaluator-v1`, corpus/oracle hashes, baseline ID/digest, and the product/evaluator build digests applicable to that run). A local gate passing one stage must never rewrite the current baseline, change the evaluator protocol, or imply a 100x result.

Common stage statuses should reuse `passed`, `failed`, `environment-unavailable`, `not-applicable`, `unknown`, and `protocol-failure`. Required fixed rows may not become `not-applicable` to hide an implementation problem. Every produced artifact and raw evidence file is retained or deterministically regenerated, SHA-256-bound, and covered by the artifact `SHA256SUMS`. Emit failure records as well as pass records.

### 4.1 `protected-image-emission-v1`

**Parent requirements served:** R4 (observable Protector → Protected Image ABI boundary); R5 (distinguish Protector/encoding failures and do not claim a complete unit); R7 (retain existing fixtures/negative evidence and only append); R8 (machine-gated tests/evidence); R9 (stage gate cannot substitute for the independent compatibility dimension). It also advances R3 by defining an independently verifiable next child task.

**Inputs**

1. The exact frozen corpus row and `sourceSha256` listed in §2.1, with its registered profile, runtime cell, target loader and oracle unchanged.
2. The existing explicit transformation recipe/selector for the committed protection fixture; a build from the tested commit; versioned Protected Image ABI identity and producer build digest.
3. Bounded source/artifact limits from the product ABI design and a fresh artifact root. Do not add rows to or alter `.artifacts/evaluator/pr`.

**Outputs and required records**

- Exact emitted bytes under a stage-owned raw artifact path and SHA-256 manifest.
- A product-owned `protected-image.json` role record containing at least schema version, `artifactRole=protected-image`, `abiId`, `abiVersion`, fixed `unitId`, profile, source digest, artifact digest and byte length, producer build digest, declared rehydrator consumer ID, transformation/request digest, retained-raw-artifact path, and `rawArtifactRetained=true`.
- A bounded machine-readable producer/stage record containing status, command/environment digest, source input hash, exact Protected Image output hash, selected transformation identity/result, diagnostics, producer build hash and raw-evidence-manifest path.
- An ABI-aware product inspection/round-trip test result that demonstrates a structured Protected Image representation rather than a final executable ELF merely renamed or a complete source/final ELF carried as the current compressed-payload frame. The public evaluator record stays at role/hash granularity; format-specific inspection belongs to the product ABI checker and its tests.

**Pass rule**

`passed` requires: correct frozen unit/source/profile binding; known ABI/version; producer and output hashes/size match the retained raw bytes; transformation is the explicit registered request; ABI inspection validates the structured role; no publication on any error; output is not byte-identical to the source; and the record binds a declared future rehydrator consumer. The strict evaluator may then bind `protector.outputSha256` and `protected-image.artifactSha256` for the same unit. All later chain stages remain unproven until their own gates pass.

**Fail/negative cases**

Missing/unknown ABI or consumer; wrong source/unit/profile; truncated or over-limit artifact; malformed/duplicate records; incorrect size/hash/build/command binding; no selected transformation; cross-unit replay; byte-identical source; final ELF relabeled as the Protected Image; or an ABI “payload” that is only a complete source/final ELF encoded in the current generic compression frame. A failure leaves no published output and records a stable diagnostic. Missing required tool/runtime capability is `environment-unavailable`, not product `failed` or pass.

**Tests and commands**

Add deterministic valid and nearest-negative ABI codec/record tests and preserve the existing atomicity/layout, selector, byte-invariant and post-write tests. Run in the implementation child/CI:

```sh
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~FunctionProtectionTests|FullyQualifiedName~ProtectedImage"
dotnet test UrProtect.sln --configuration Release --no-restore
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
python3 scripts/check-protection-evidence.py .artifacts/protection/pr/glibc --tier pr --runtime glibc
python3 scripts/validate-evaluator-manifests.py
```

The filtered/new ABI test name is proposed; retain and run the existing test names as they stand. CI should retain the new product evidence (for example `.artifacts/protected-image/pr/glibc/<unit>/`) plus `SHA256SUMS`, logs, record JSON, producer identity and environment report; upload on failure as well as success. Existing protection smoke artifacts remain unchanged and separately labeled auxiliary.

**Rollback point**

Keep the new ABI-emission path opt-in/isolated until its gate and existing protection tests pass. On any schema/hash/atomicity/compatibility regression, disable or revert only the new producer path; retain the legacy direct-ELF smoke as auxiliary historical evidence. Do not silently fall back to direct ELF and count it as a Protected Image. Do not change protocol, corpus, baseline, oracle, or existing evidence tier.

### 4.2 `rehydration-native-handoff-v1`

**Parent requirements served:** R4 (generic rehydration to Native Image while leaving native-loader semantics with the OS); R5 (actual loader execution and behavior oracle); R7-R8 (retain and gate old/new test and evidence sets); R9 (full-chain compatibility is independent and conjunctive).

**Inputs**

1. A `protected-image-emission-v1` pass artifact and its exact output bytes/hash/ABI identity from the same fixed unit.
2. A versioned rehydrator consumer/build, fixed profile and source digest, frozen `fixture.process-oracle.v1` definition/hash, and actual native AArch64 glibc runner identity.
3. Existing target loader `kernel.execveat-at-empty-path`; existing launcher/memfd transport; declared bounded time/size/resource controls.

**Outputs and required records**

- Exact reconstructed Native Image bytes with SHA-256, size, mode and bounded structural validation report.
- `rehydration.json` binding input Protected Image digest to the output Native Image digest, unit/profile/ABI, consumer ID and build digest, command/environment digest, status, resource evidence and raw manifest.
- `native-image` record binding its hash to the exact bytes passed into handoff.
- `target-loader` record binding the same Native Image hash to `kernel.execveat-at-empty-path`, actual native runtime/loader identity, process status/signal, and retained invocation evidence.
- `behavioral-oracle` record binding the frozen oracle digest and all registered comparison fields (`status`, `stdout`, `stderr`, `argv`, `cwd`, `declaredFiles`, `signal`) to baseline and candidate observations and a deterministic comparison hash.

**Pass rule**

`passed` requires exact hash continuity `Protected Image → rehydration input → Native Image output → target-loader input`; distinct Protected Image and Native Image digests; status from a real target process in the declared native runtime; complete required oracle equality; all evidence is retained/hash-verified; and no partial publication or loader attempt on pre-handoff rejection. For a complete compatibility unit, all six evaluator stages must pass together for the same source/unit/profile/runtime/oracle/run. A local positive on one fixed unit remains only one local-gate result; the compatibility factor stays `null` while its frozen baseline is zero.

**Fail/negative cases**

Corrupt or truncated Protected Image; unknown ABI/profile; wrong source/consumer/build; hash/size mismatch; oversize fields/overflow; malformed materialized ELF; changed bytes between verification and handoff; target loader receives a different hash; wrong runtime/loader identity; loader failure; oracle mismatch; executable temporary-path fallback; missing resource/raw record; or successful local self-test without process execution. Nearest-negative tests require rejected malformed Protected Image before `execveat`/entry markers and zero published/partial Native Image; retain the corpus negative `compat.legacy-direct-protected-elf-not-strict-chain` as auxiliary and never count direct ELF as a strict unit.

**Non-loader boundary**

The rehydrator is a bounded ABI consumer and Native Image writer/validator. It reconstructs ordinary ELF bytes and may verify their static structure with the existing project parser/validators. It does not map the image into a process, perform runtime symbol/dependency lookup, apply runtime relocation/lifecycle semantics, choose loader behavior, or replace the target native loader. The existing memfd plus `execveat` path remains responsible for handoff; the OS/native interpreter owns ELF runtime semantics. Any feature requiring new product loader semantics is separately gated and out of this slice.

**Tests and commands**

Add positive end-to-end and nearest-negative tests for ABI decoding, materialization, exact byte/hash handoff, process marker absence, oracle fields and resource/rollback behavior. Run:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
./scripts/run-packed-fixture-matrix.sh --tier pr
native/urprotect-launcher/test_launcher.sh
native/urprotect-runtime/test_managed_host_context.sh
python3 scripts/check-protection-evidence.py .artifacts/protection/pr/glibc --tier pr --runtime glibc
```

Native handoff results require the declared native AArch64 glibc CI lane; metadata-only local checks do not replace it. Store per-unit emission, rehydration, Native Image, process/oracle, loader identity, environment and raw hash manifests under a new `.artifacts/protected-image/pr/glibc/<unit>/` subtree. The evaluator artifact remains a separate, closed tree.

**Rollback point**

Reject before native handoff on any bad record/hash/layout/runtime/oracle result. Revert or disable the new rehydration/handoff integration without changing the existing launcher, HostContext, frame or loader contracts. Keep every failed run and its raw evidence; do not relabel the old direct-protection path as a successful fallback.

### 4.3 `scheme-a-baseline-calibration-v1`

**Parent requirements served:** R1 (content-addressed immutable baseline), R2 (independent six-family machine records), R6 (attack-vector family evidence and objective criteria), R8 (required CI result/artifact), and R9 (per-family independent gates; no averaging). It does not certify a candidate's 100x factor.

**Inputs**

1. The existing unchanged `scheme-a-v1` manifest and its six required families/recipe hashes; profile `scheme-a-glibc-v1`; fixed source and, once produced, immutable published Protected Image artifact hash.
2. Three reproducible baseline replicas per family; pinned tool binary/version hashes; exact evaluator/blue-oracle hashes; native runtime and loader identity; sandbox capability probes; frozen identical budgets for all baseline/candidate attempts (wall 60s, CPU 45s, RSS 1 GiB, 32 processes, output 16 MiB, raw artifact 256 MiB, zero manual steps, network disabled).
3. Raw command, stdout/stderr, resources, attack outputs and independent blue-oracle evidence for every attempt, including failures, timeouts and unavailable capability checks.

**Outputs and required records**

- One schema-validated attempt record and raw `SHA256SUMS` per family × role × replica, preserving the full six-family vector and all 36 baseline/candidate attempts when candidate attempts are in scope.
- A capability/tool qualification record per required tool (availability, version and binary digest, exact missing capability and runner evidence); unavailable is explicit.
- A family calibration result with baseline success count, finite CPU cost, objective/blue-oracle result, recipe/tool/budget binding, replica/raw evidence hashes and status.
- An immutable content-addressed Scheme-A baseline artifact only after every required family satisfies the frozen three-success baseline rule. Keep the current `baseline-not-calibrated` result if any family/tool/capability is missing; never write a zero/infinite cost or substitute another tool/profile.

**Pass/fail statuses**

For this calibration-only gate, `baseline-calibrated` means every one of the six required families has three finite, reproducible, raw-evidence-backed successful baseline replicas using the exact pinned tool and blue oracle, identical frozen recipe/profile/budget, and passed environment/capability checks. Otherwise emit `baseline-not-calibrated`, `environment-unavailable`, or `protocol-failure` as warranted. This gate has no `100x pass` status: candidate attack results are compared later under the unchanged `scheme-a-v1` protocol; all six independent candidate factors must then meet the parent evaluator threshold. Mixed replicas, absent raw artifacts, absent tool/capability, failed blue oracle, changed recipe/budget, manual steps, or missing family block calibration.

**Tests and commands**

Preserve and extend the evaluator schema, manifest, anti-gaming and artifact-tree integrity tests; add cases for each missing tool, missing runner capability, each missing family/replica, hash/recipe/budget/oracle drift, mixed replica outcomes and partial-baseline rejection. Run in the future calibration child/CI:

```sh
python3 scripts/validate-evaluator-manifests.py
python3 tests/test_evaluator_schema.py
python3 tests/test_evaluator_antigaming.py
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
```

The last command applies to a newly generated evaluator artifact matching the checked-out commit; the present frozen artifact is tied to older commit `86270e7...`, so it must not be judged against current `HEAD` by that commit-sensitive checker. Retain all tool/capability probes, family attempt records, blue-oracle evidence, resource counters, raw manifests, scheme gate, normative gate, analysis input and top-level checksum manifest with `if: always()` CI artifact upload.

**Rollback point**

Do not freeze or overwrite an incomplete Scheme-A baseline. Leave status `baseline-not-calibrated`/`environment-unavailable`, repair the runner/tool pin before calibration, then create a new content-addressed immutable baseline. Once frozen, any changed tool, recipe, budget, oracle or threat-model requires an append-only new version/baseline; never edit the current baseline in place.

## 5. Recommended next implementation child task

**Recommendation:** create the next child around **`protected-image-emission-v1`**, since the measured first failure is `protector` and the product has neither a producer ABI nor a rehydrator consumer. A suitable title is “Emit a versioned layout-neutral Protected Image ABI for the frozen protection fixture.” This recommendation is a proposal, not a measured result or permission to change evaluator inputs.

### Suggested child PRD scope

**Goal:** add an explicit producer boundary that emits and records a distinct, versioned Protected Image from the already-registered AArch64 protection fixture and explicit transform request. Make the transform output independent of final ELF program-header/file/virtual placement so the lack of an input `PT_NULL` entry does not determine whether a Protected Image can be emitted. Establish the producer/consumer record and a local evidence gate; keep full Native Image materialization and actual loader handoff in a follow-on `rehydration-native-handoff-v1` child.

**Design boundary:** split function analysis/transform emission from final ELF image writing. Represent selected transformed code as address/layout-neutral product data plus bounded, explicit fixup/identity metadata for the later rehydrator. Let a later materializer choose a legal ELF layout, construct and validate a conventional Native Image, and hand it to the existing native launcher/system loader. The rehydrator is not a runtime mapper/relocator or general-purpose ELF loader. Preserve the existing AArch64 ELF parser, `LoadMap` ownership, stable diagnostics, explicit selectors/pass order, atomic output rules, byte invariants where applicable, and system-loader ownership of dependencies/relocations/TLS/lifecycle.

**Specific layout bottlenecks to address:** remove the emitter's hard dependency on `TryFindRewriteSlot` and `TryAppendExecutableSegment` for the Protected Image output; represent branch/fixup intent rather than assuming final executable `PT_LOAD`/virtual address during transform emission; leave output-size bounds, AArch64 branch reach, segment alignment/congruence and program-header construction to the separately tested materializer. Do not claim these issues resolved until a subsequent rehydration gate demonstrates legal materialization and native execution for the no-spare-header fixture and its nearest negatives.

**Scope limits:** start with the existing pre-registered `compat.protection-symbolized-fixture.glibc.outer-execveat`, exact source digest and explicit protection recipe; do not broaden selector semantics or instruction support merely to pass the gate. Do not change the fixed/growth corpus, row identities, sample denominator, `evaluator-v1`, Scheme-A version/families/recipes/budgets, oracle, immutable baseline or CI gate semantics. Do not claim positive compatibility, attack resistance, or 100x from emission alone. Keep the existing direct protected ELF/E2E results as auxiliary evidence, not as a silent fallback or strict unit.

**Acceptance / validation:** `protected-image-emission-v1` passes with a schema-valid role record and exact artifact/build/source/request hashes; output is distinct and ABI-inspectable rather than a renamed ELF/current whole-source compressed frame; a valid explicit transformation emits deterministically; unsupported/invalid requests fail closed without publishing partial output; the no-`PT_NULL` fixture proves emission no longer relies on the final-ELF placement slot; existing protection tests/E2E and repository regression suite pass. Preserve current evaluator manifest inputs and status. Run focused protection/ABI tests, `dotnet test UrProtect.sln --configuration Release --no-restore`, the existing glibc protection smoke/evidence checker, and `python3 scripts/validate-evaluator-manifests.py` in CI. Upload the new artifact plus all raw records and hashes even on failure.

**Next sequence:** after emission passes, create the separate rehydration/native handoff child against the same fixed unit; only when a product Protected Image and blue-oracle-valid Native Image are available should Scheme-A baseline calibration proceed. Scheme-A tool/capability qualification can be prepared in parallel, but unavailable status stays explicit and all six required families remain.

## 6. Preserve existing evidence; stage-gated benchmark/fuzz expansion

No existing evidence is displaced or reclassified. Keep all current benchmark measurements, parser/ELF and malformed-input tests, frame/launcher/HostContext/protection tests, regression and stress tests, existing `elf` and `payload-frame` fuzz targets/corpora/crash/timeout handling, real-sample corpus and policies, fixture manifest positives/nearest negatives, native glibc/musl/bionic protection runs, packed/runtime matrices, and their independent CI evidence gates. In particular retain:

- `benchmarks/UrProtect.Benchmarks/Program.cs` parse, LoadMap, validate with/without analysis, no-op memory copy and no-op disk copy characterization;
- `tests/UrProtect.Core.Tests/FunctionProtectionTests.cs`, parser and malformed corpus, `PayloadFrameTests`, launcher/native self-tests, HostContext/dependency/TLS/lifecycle tests, concurrency/large-input/golden report coverage;
- `tests/UrProtect.Fuzz/Program.cs` `elf` and `payload-frame` modes and `scripts/run-coverage-fuzz.sh`'s pinned SharpFuzz/libFuzzer bridge, bounds, corpora and crash/timeout artifacts;
- the existing 100-identity real-sample policy and `fixtures/runtime-matrix.json` plus all producing/checker jobs; these remain separate ecology/runtime evidence and are never replaced by a smaller strict fixture set;
- the existing protection E2E recipes and its glibc, musl and bionic evidence. Continue to label it auxiliary until it binds the full Protected Image chain.

| Product boundary achieved | New performance/diagnostic targets that become valid | New fuzz targets that become valid | What still cannot be claimed |
|---|---|---|---|
| Before any Protected Image stage | Keep existing parser/validation/no-op benchmark unchanged. | Keep `elf` and `payload-frame` unchanged. | No Protected Image/rehydration/strength claim. |
| Emission/ABI v1 passes | Protector analysis and emission CPU, allocations, peak RSS; Protected Image byte size and ABI encoding time; per-stage failure counts. These characterize throughput/size, not protection strength. | Protected Image envelope/record/codec parser: truncation, bounds, unknown ABI/version, digest mutation, duplicate records, malformed fixups, source/build/unit mismatch and atomic failure. Keep all old fuzz targets. | No Native Image, loader, behavioral compatibility unit or Scheme-A factor. |
| Rehydration produces validated Native Image | Rehydration CPU/RSS, Native Image size, validation cost and layout/materialization diagnostics. | Rehydration codec/consumer, fixup arithmetic and overflow, layout planner/materializer, exact Native Image structural validation. Seed from valid Protected Image outputs; retain minimized regressions. | No target-loader execution or complete compatibility unit. |
| Native handoff and oracle pass | Target-loader startup and behavioral-oracle cost as diagnostic performance fields; end-to-end stage-time/resource/failure breakdown. Never convert time, compression ratio or size into a Scheme-A factor. | Handoff record/path/hash binding, mutated native-image metadata, changed-byte/hash/TOCTOU boundaries and malformed handoff metadata, with no-entry/no-loader marker checks for pre-handoff rejection. | No 100x compatibility until fixed-view and append-only growth rules pass against a positive frozen denominator; no strength claim. |
| All Scheme-A tools/capabilities and finite three-replica baselines calibrated | Existing evaluator's per-family CPU/resource/time cost measurements and diagnostics, under unchanged `scheme-a-v1`. | Add attack-runner/family harness fuzzing only as evaluator/tooling tests; preserve all product fuzz targets. | Calibration alone is not a candidate 100x result; all six family gates still pass independently. |

Any added fuzz target needs a bounded seed corpus, input size, run/timeout/RSS budgets, retained crash/timeout artifacts, and a no-crash/no-timeout evidence gate in the established SharpFuzz/libFuzzer style. Any benchmark records are appended as separate names/schema fields and do not replace the old baseline. Real-sample promotion still requires real observation, a controlled positive and nearest-negative fixture, stable diagnostics, and the required CI runtime oracle; one fixture cannot stand in for corpus growth.

## 7. Residual risks and conclusion

1. **Not current-HEAD measurement:** the normative result is for commit `86270e7...`; current `HEAD` is `42f4878...`. The artifacts are hash-verified and internally consistent, but no fresh strict run on current `HEAD` is represented.
2. **Zero denominator:** compatibility remains `baseline-zero` with a null factor; current evidence cannot support a positive compatibility claim or a 100x comparison.
3. **Unmeasured Native Image path:** native output, target-loader execution and oracle are not captured for the strict unit. Existing native product evidence is auxiliary, not a substitute.
4. **Scheme-A capability gap:** all six family tools/capabilities are unavailable or uncalibrated; all factors are null. No attack outcome or resistance inference is supported.
5. **Environment gap:** the evaluator reports native AArch64 but lacks required .NET SDK, network-disabled isolation, pinned runtime, producer, rehydrator and Scheme-A toolset; loader identity is not captured. Current product-stage implementation and evaluator environment are separate blockers.
6. **Layout/ABI design risk:** a layout-neutral artifact and later rehydrator must prove exact hash continuity, valid ELF placement, branch range and alignment, rollback/atomicity, and real native loader behavior. Avoid expanding ELF parsing into custom dynamic loader semantics.
7. **Evidence-preservation risk:** new tests/benchmarks/fuzz targets must be additive; do not delete, downgrade, rename, reduce, or reweight fixed rows, existing real samples, negative cases, attack families, budgets, or protocol fields.

**Conclusion:** The evaluator result is **not-ready**: compatibility `baseline-zero`; first failure `protector` because the product has no declared Protected Image stage and rehydration/native-handoff chain; Scheme-A `baseline-not-calibrated` for all six required families with explicit missing tool/capability evidence. The next implementation slice should establish `protected-image-emission-v1` without altering evaluator inputs, then gate native handoff separately, while retaining the full fixed/growth corpus and existing evidence. No 100x, positive compatibility, or attack-resistance result is claimed.

## 8. Analysis commands and validation performed

The analysis resolved the assigned task with `python3 ./.trellis/scripts/task.py current --source`, read the child PRD and both curated manifests, inspected the complete `.artifacts/evaluator/pr/` tree and the relevant repository source/spec/research evidence, and ran these read-only checks:

```text
(cd .artifacts/evaluator/pr && sha256sum -c SHA256SUMS) — passed for every listed file
Recomputed evaluator inventory digest excluding gate.json and analysis-input.json — matched both recorded gate digests
python3 scripts/validate-evaluator-manifests.py — passed; corpus=compat-corpus-v1, rows=1, families=6, baselineStatus=baseline-zero, strengthStatus=baseline-not-calibrated
git rev-parse HEAD — 42f48788f7a8ba034e270a7639d58224a218b3b6
command -v dotnet — no executable found in the analysis environment
```

No product tests, evaluator run, baseline generation, evaluator protocol/manifests/CI modification, or commit was performed by this analysis agent.
