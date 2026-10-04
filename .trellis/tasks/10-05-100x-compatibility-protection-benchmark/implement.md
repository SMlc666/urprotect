# 100x Compatibility and Protection Strength Implementation Plan

## Execution Rules

- Do not run `task.py start` until the final planning summary is reviewed and explicitly approved by the user.
- Start one independently verifiable child task at a time. The parent task owns the cross-child gate; child artifacts own detailed dependencies and local gates.
- Preserve all existing fixture, benchmark, test, fuzz, real-sample, runtime, and CI paths. New gates are additive until a replacement has passed the parent integration gate.
- The evaluator is read-only against product/source/task state. The analysis agent receives only the persisted evaluator result and raw-evidence references.
- Every implementation step publishes machine-readable evidence before being called complete.

## Phase 0 — Establish child-task and evidence scaffolding

1. Create the first child task under the parent:

   ```sh
   python3 ./.trellis/scripts/task.py create \
     "冻结 1x 基线并建立独立 evaluator gate" \
     --slug freeze-1x-independent-evaluator \
     --parent .trellis/tasks/10-05-100x-compatibility-protection-benchmark \
     --priority P0 --no-start
   ```

2. Give the child its own `prd.md`, `design.md`, `implement.md`, `implement.jsonl`, and `check.jsonl`. Its local gate is `evaluator-protocol-v1`.
3. Record the parent PRD/design/implementation hashes and the exact current commit in the child artifacts.
4. Do not create the evaluator-to-analysis implementation child until the evaluator has emitted `gate.json` and `analysis-input.json`; its scope must be derived from the first failure layers and Scheme-A calibration status.

**Review gate:** parent and child task artifacts are valid; no product code is changed; existing git status is understood.

## Phase 1 — Freeze the current 1x snapshot and evaluator protocol

1. Add append-only manifest schemas for:
   - compatibility corpus rows and identity rules;
   - frozen behavioral oracles;
   - Scheme-A family/profile applicability, recipes, tool hashes, replicas, budgets, and success predicates;
   - baseline references and protocol versions.
2. Add evaluator result schemas and validators:
   - per-stage `compatibility/<unit-id>/unit.json`;
   - per-attempt `strength/<family>/replica-N/attempt.json`;
   - `environment.json`, `protocol.json`, `baseline-reference.json`;
   - closed `SHA256SUMS` manifests;
   - final `gate.json` and `analysis-input.json`.
3. Implement evaluator control scripts under `scripts/` as read-only processes. They must:
   - validate manifest/protocol/baseline hashes;
   - reject traversal, symlink, duplicate identity, missing raw evidence, and mutable external paths;
   - retain failed, unknown, and environment-unavailable rows;
   - emit `baseline-zero` for the current strict chain because Protected Image and rehydration are absent;
   - emit `baseline-not-calibrated` for any Scheme-A family without three finite reproducible baseline successes;
   - calculate no fabricated factor from a zero denominator.
4. Run the current checkout's existing auxiliary evidence jobs and attach their hashes without counting them as strict units.
5. Freeze the baseline object content-addressably. Store the immutable digest in a reviewed lock/reference file; later runs may read it but never overwrite it.

**Validation:**

```sh
python3 scripts/validate-evaluator-manifests.py fixtures/evaluator/...
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
python3 tests/test_evaluator_schema.py
python3 tests/test_evaluator_antigaming.py
python3 tests/test_compatibility_unit_rules.py
python3 tests/test_scheme_a_gate.py
```

If native prerequisites are absent, the evidence records `environment-unavailable` with runner facts. It does not substitute a local non-contract environment.

**Rollback:** remove only the new evaluator job and scripts from the active CI path; retain manifests, baseline artifacts, reports, and existing jobs.

## Phase 2 — Run evaluator and hand off to the analysis agent

1. Execute the independent evaluator against the frozen current commit.
2. Confirm the result is machine-readable and contains:
   - strict compatibility `baseline-zero`/`not-ready`;
   - Scheme-A `baseline-not-calibrated` or measured family baselines;
   - first failure counts;
   - anti-gaming status;
   - exact raw evidence paths/hashes;
   - benchmark/fuzz diagnostics.
3. Persist the evaluator result under the parent task research/evidence area and pass only `gate.json`, `analysis-input.json`, and referenced reports to the analysis agent.
4. The analysis agent must produce:
   - a gap analysis by compatibility layer and attack family;
   - an ordered implementation proposal;
   - risks and rollback points;
   - one machine-checkable local gate for its first proposed slice;
   - a new Trellis child task with PRD/design/implement artifacts.
5. Review the analysis child plan before starting it. Do not let the analysis agent silently redefine the parent 100x metrics or remove required families.

**Validation:** `gate.json` schema, raw manifest, baseline digest, and analysis handoff all pass; the child task's local gate points to concrete unit/family IDs.

## Phase 3 — Introduce a real Protected Image ABI

1. Add typed managed artifact roles and immutable descriptors for `SourceImage`, `ProtectedImage`, `NativeImage`, `PayloadFrame`, and `Wrapper`.
2. Define a versioned Protected Image v1 envelope with:
   - magic/schema/ABI identity;
   - architecture and profile;
   - source digest and producer build digest;
   - exact Protected Image size/digest;
   - declared rehydrator consumer/version;
   - bounded operation stream or region descriptors;
   - integrity metadata.
3. Refactor `FunctionProtectionService` to expose a protection plan/operation model in addition to the legacy direct output. The plan must describe transformed regions, address mappings, fixups, and pass metadata without requiring a spare `PT_NULL` slot as the Protected Image contract.
4. Add managed codec round trips and malformed-input tests for truncation, integer overflow, duplicate/overlapping regions, unknown operations, version mismatch, source digest mismatch, and Native Image aliasing.
5. Keep legacy direct protected-ELF output explicitly named as auxiliary until the new ABI has a positive end-to-end baseline.

**Local gate:** every selected protection fixture emits a valid, hash-bound Protected Image artifact whose bytes differ in role from the Native Image and whose manifest identifies the rehydrator consumer.

**Validation:** focused xUnit tests, malformed corpus tests, property tests, golden report updates, and managed codec fuzz smoke.

**Rollback:** keep the legacy `protect` output path and current JSON report; disable only the new Protected Image profile if ABI validation fails.

## Phase 4 — Implement generic rehydration and Native Image materialization

1. Add the managed materializer/oracle that maps a Protected Image to a Native Image descriptor and exact bytes.
2. Add native Protected Image parsing/validation and rehydration in the shell/runtime. All untrusted offsets, lengths, counts, and address conversions use bounded checked arithmetic and stable diagnostics.
3. Make the native path converge after rehydration:

   ```text
   Protected Image
     -> authenticated rehydration
     -> exact Native Image
     -> final structural validation
     -> sealed memfd / execveat or HostContext loader
   ```

4. Keep native loader responsibilities outside the rehydrator. The rehydrator restores the input image/context; it does not resolve arbitrary dependencies or simulate TLS/lifecycle semantics.
5. Emit and verify a rehydration record binding Protected Image hash to Native Image hash, consumer build hash, resource evidence, and target-loader invocation.
6. Add nearest-negative fixtures for wrong ABI, wrong consumer, tampered operation, overlapping output, invalid permission transition, incomplete final image, and failed loader handoff.

**Local gate:** one native AArch64 glibc fixture completes all six compatibility stages, with distinct Protected Image and Native Image hashes, preserved behavioral oracle, sealed/memfd or execveat evidence, and no output publication after a failed stage.

**Validation:** native self-test, managed HostContext/outer handoff tests, readelf checks, status/stream/cwd/env/fd/signal comparisons, and contract-layout tests.

**Rollback:** disable the new Protected Image dispatch profile while retaining the old launcher/profile paths and all evidence.

## Phase 5 — Remove protector-specific layout bottlenecks

This phase is driven by the analysis child and its local gate. The expected high-value changes are:

1. Replace direct in-place-only layout assumptions with a Native Image materializer that can allocate new code/data regions and rebuild the required program-header representation.
2. Remove the mandatory spare `PT_NULL` dependency for the new path.
3. Expand AArch64 lowering in measured increments, beginning with direct calls/branches, conditional branches, PC-relative address formation, and branch veneers/islands where required.
4. Preserve and validate relocations, load-map domains, entry mappings, unwind/metadata requirements, and external dynamic metadata through the materializer.
5. For every newly supported lowering class, add a positive fixture and nearest negative fixture, then append a compatibility challenge row with real native behavior.
6. Ensure a failed selected transform or materialization aborts publication and leaves no partially emitted image.

**Local gate:** the analysis-defined class of current protector rejections shows a positive end-to-end growth in distinct compatibility units while all frozen rows remain green.

**Validation:** function/protection tests, generated assembly fixtures, output parser/validator, native behavior oracle, external `readelf`/`llvm-readelf`, and regression-matrix evidence.

## Phase 6 — Build and calibrate the Scheme-A red/blue harness

1. Add the pinned attack-tool manifest and evaluator image/toolchain lock.
2. Implement the six family recipes with three deterministic replicas, bounded process-tree resource accounting, zero manual steps, and raw evidence retention.
3. Implement independent objective scorers:
   - reassembled artifact loader/behavior equivalence;
   - behavior mutation after patch/repack;
   - machine-readable semantic/CFG/constant logic recovery;
   - static segment/code/data/function/CFG inventory;
   - internal trace/state or unauthorized replacement;
   - integrity/handoff bypass markers and zero-handle fail-closed oracle.
4. Establish finite baseline successes for each required family before using the family factor. Families lacking finite calibration remain explicitly `baseline-not-calibrated`.
5. Freeze `scheme-a-baseline-v1` only after tool hashes, budgets, recipes, fixtures, oracles, replica count, and threat model are reviewed.
6. Enforce Scheme A as a conjunction: every required family independently reaches `>=100x`; mixed replicas, missing capabilities, changed tools/oracles, or missing raw evidence fail the gate.

**Local gate:** `scheme-a-integrity-v1` and/or the analysis-selected first family gate passes with complete raw evidence and no evaluator-owned file modifications.

**Validation:** unit tests for cost/censoring/status classification, attack recipe replay, raw manifest checks, sandbox capability checks, and intentional tamper/repack negative tests.

## Phase 7 — Expand corpus, benchmarks, tests, and fuzzing

1. Convert current protection fixtures and selected real samples into append-only compatibility challenge rows without inflating identity counts through duplicates or variants.
2. Add challenge dimensions for producer/build chain, ELF layout, protection operation combinations, profile, and native runtime cell.
3. Retain all existing real-sample, fixture, HostContext, parser, no-op, packed, and negative cases; add first-failure layer projections for the new chain.
4. Extend benchmarks with:
   - protection analysis/emission cost;
   - Protected Image size/encoding;
   - rehydration CPU/RSS and Native Image size;
   - loader startup/behavior oracle costs;
   - per-stage failure counts.
5. Extend fuzzing with Protected Image codec, operation stream, rehydration, Native Image validation, and handoff inputs once each product stage exists. Preserve existing ELF/payload-frame fuzz targets and promote every discovered crash/timeout into a deterministic regression.
6. Keep PR workloads bounded and fixed; use nightly/release for append-only growth, additional repetitions, and larger attack/corpus budgets without replacing the fixed gate.

**Local gate:** fixed-view compatibility non-regression, distinct growth identities, benchmark schema validation, no-crash/no-timeout fuzz smoke, and retained provenance/hash manifests.

## Phase 8 — Integrate CI and reports

1. Add an evaluator CI job after build and required native runtime provisioning. Its required steps are manifest validation, environment/tool checks, compatibility execution, Scheme-A execution, anti-gaming checks, evidence hashing, and `gate.json` emission.
2. Upload `.artifacts/evaluator/<tier>/` on every result, including failure and environment-unavailable outcomes.
3. Keep all existing CI jobs and gates. The new evaluator must not replace narrower evidence contracts.
4. Add summary/report projections to distinguish:
   - parser/model evidence;
   - auxiliary wrapper/HostContext evidence;
   - strict end-to-end compatibility units;
   - red-team attack results;
   - blue-team rejection evidence;
   - benchmark/fuzz diagnostics;
   - claimable versus not-ready status.
5. Update `COMPATIBILITY.md`, `fixtures/manifest.json`, README, and contract inventory only after the new artifacts and gates exist. Do not promote an observation to support by documentation alone.

**Validation:** workflow syntax, manifest/evidence validators, full PR tier, native ARM64 fixture/packed/runtime matrix, protection E2E, coverage/fuzz/stress, evaluator gate, and artifact cleanup/security checks.

## Phase 9 — Re-evaluate and iterate

1. Run the independent evaluator exactly as specified, with the same frozen baseline and protocol.
2. If either compatibility or any required Scheme-A family fails, preserve the complete artifact tree and send `analysis-input.json` to the next analysis agent.
3. Create the next Trellis child from the measured first failure/local gate. Do not infer the next implementation slice from prose alone.
4. Repeat phases 5–9 until compatibility reaches its independent `100x` growth condition and every required attack family reaches its independent `100x` factor with no regression.
5. The parent integration review must confirm all existing gates, evidence, corpus rows, benchmark records, fuzz corpora, and negative boundaries remain present and passing.

## Validation Command Set

Existing checks remain mandatory:

```sh
dotnet restore UrProtect.sln --locked-mode
dotnet build UrProtect.sln --configuration Release --no-restore
dotnet test UrProtect.sln --configuration Release --no-build
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
python3 tests/test_runtime_matrix.py
python3 scripts/validate-runtime-matrix.py fixtures/runtime-matrix.json
python3 scripts/validate-protection-policy.py fixtures/real-samples/protection-policy.json
./scripts/run-regression-stress.sh --tier pr
./scripts/run-coverage-fuzz.sh --tier pr
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
```

New gates must add, not replace, commands of this shape:

```sh
python3 scripts/validate-evaluator-manifests.py ...
./scripts/run-independent-evaluator.sh --tier pr
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
python3 tests/test_compatibility_evaluator.py
python3 tests/test_scheme_a_evaluator.py
```

Native commands must run on the declared AArch64 CI cells. Local environments lacking the required SDK, loader, kernel, isolation, or attack backend produce retained environment evidence and do not silently claim success.

## Final Parent Gate

The parent remains open until all of the following are true:

- immutable 1x baseline and protocol hashes match;
- compatibility fixed view has no regression;
- compatibility growth view has at least `100 * frozenBaselineCompleteUnits` distinct complete end-to-end units;
- every required Scheme-A family has a finite immutable baseline and candidate factor `>=100` under identical recipes/budgets/tools;
- all anti-gaming checks pass;
- Protected Image ABI, rehydration, Native Image handoff, benchmark, test, fuzz, real-sample, runtime, and existing CI evidence are retained;
- the final evaluator emits `claimable=true`.
