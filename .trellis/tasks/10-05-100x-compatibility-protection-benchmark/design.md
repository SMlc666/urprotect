# 100x Compatibility and Protection Strength Design

## 1. Design Intent

This task establishes a measurement-and-implementation architecture whose success is observable in two independent dimensions:

1. **Compatibility** counts only complete protected execution units:

   ```text
   Source Image
     -> Protector
     -> Protected Image ABI artifact
     -> Generic Rehydration
     -> Native Image
     -> target native loader
     -> frozen behavioral oracle
   ```

2. **Protection strength** is Scheme A, a versioned red-team/blue-team vector. Every required attack family receives its own immutable baseline and must independently reach `>=100x`; no family can compensate for another.

The evaluator owns measurement and gate calculation. It does not define loader semantics, implement protection, alter product code, or reinterpret missing evidence. The analysis agent receives the evaluator's machine-readable result and creates the next independently verifiable implementation child with a local gate.

## 2. Repository Boundaries

### Managed core

`src/UrProtect.Core/` owns typed artifact contracts, Protected Image planning/encoding, bounded codec validation, diagnostics, and report models. It must not expose AsmStone types or duplicate ELF address arithmetic.

- `Artifact/` (new): source, protected-image, and native-image role records and immutable descriptors.
- `Protect/` (existing/new): protection plans and pass lowering; the service stops treating final ELF bytes as the only product result.
- `Rehydrate/` (new): managed codec/validation and test oracle for Protected Image to Native Image materialization.
- `Pack/` (existing): PayloadFrame remains transport/dispatch framing; it binds an artifact role and ABI identity rather than defining protection semantics.
- `Diagnostics/` (existing): stable machine-readable stages and failure codes.

### Native shell and handoff

`native/urprotect-launcher/` and `native/urprotect-runtime/` own the native Protected Image consumer, bounded rehydration, final Native Image validation, memfd/sealing, and native loader handoff. The rehydrator does not implement dependency resolution, symbol lookup, TLS, constructors, destructors, or a general ELF loader. It materializes the final bytes/context consumed by the selected native loader.

The current direct-source and HostContext paths remain named auxiliary/history paths during migration. They are not relabeled as the strict Protected Image chain.

### Measurement control plane

`scripts/` owns corpus validation, evaluator orchestration, attack recipes, resource limits, evidence normalization, anti-gaming checks, and gate calculation. `fixtures/` owns append-only challenge manifests, positive/negative fixtures, oracle definitions, and provenance. `.artifacts/evaluator/<tier>/` owns closed evidence trees.

The evaluator is read-only with respect to source, manifests, product configuration, Trellis state, and baseline objects. It writes only its own evidence tree.

## 3. Artifact Model

The implementation must distinguish these roles:

```text
SourceImage       original input bytes
ProtectedImage    protector-owned ABI artifact; may be complex/encoded/partitioned
NativeImage       exact bytes/context handed to the target native loader
PayloadFrame      transport, compression, digest, profile, and dispatch envelope
Wrapper           launcher plus PayloadFrame and trailer
```

A strict Protected Image artifact requires a product-owned ABI/version, exact artifact hash/size, producer build identity, source hash, declared rehydrator consumer, and a separate rehydration record binding Protected Image hash to Native Image hash. A compressed complete ELF or a final ELF merely renamed as Protected Image is not a strict artifact.

The first ABI should be minimal but real. It may encode the current protection plan in a deterministic format, but it must not alias the final Native Image. Later protection passes can lower to the same operation vocabulary without adding sample-specific runtime branches.

The conceptual operation vocabulary is:

```text
DECLARE_IMAGE_LAYOUT
EMIT_REGION
DECODE_REGION
APPLY_IMAGE_FIXUP
PATCH_ENTRY
SET_FINAL_PERMISSIONS
FINALIZE_NATIVE_IMAGE
```

Operations describe materialization, not loader behavior. External `DT_NEEDED`, relocations, TLS, constructors, destructors, and platform-specific loading remain in the resulting Native Image and are handled by the native loader.

## 4. Data Flow

```text
registered source/corpus row
        |
        v
ProtectionPlan / pass lowering
        |
        v
ProtectedImageCodec.Emit --------------------+
        |                                     |
        v                                     v
protected-image.json + bytes             evaluator evidence
        |                                     |
        v                                     |
PayloadFrame / wrapper -----------------------+
        |
        v
native shell: parse -> authenticate -> rehydrate
        |
        v
exact Native Image bytes/hash
        |
        v
sealed memfd / execveat or HostContext native adapter
        |
        v
target loader + behavior oracle
```

The evaluator records every stage separately. It never infers a later stage from an earlier one.

## 5. Compatibility Measurement

### Corpus identity

Create an append-only, pre-registered compatibility corpus. Each row binds a unique `unitId` and `identityKey` to source provenance/hash, producer/build chain, ELF facts, protection profile, runtime cell, target loader, and frozen oracle. Compression settings, launcher changes, random seeds, package variants, and reruns do not create new identity units. A reviewed new producer/feature/runtime interaction creates an explicit corpus version and row.

Maintain two views:

- **fixed view:** rows frozen in the 1x baseline; candidates must not regress them;
- **growth view:** fixed rows plus reviewed append-only additions.

### Complete unit rule

A unit counts only when all six stages are `passed` for the same source digest, profile, runtime, oracle, and run. Any required non-passed stage remains in the denominator with its first failure layer. `environment-unavailable`, `unknown`, and protocol failures never become silent skips.

```text
C(version, view) = count(distinct complete unitId)
compatibilityFactor = C(candidate, growthView) / C(frozenBaseline, fixedView)
```

The gate uses the exact unrounded integer condition:

```text
C(candidate, fixedView) >= C(baseline, fixedView)
C(candidate, growthView) >= 100 * C(baseline, fixedView)
```

The current checkout has no product-declared Protected Image/rehydration stage. The first strict run therefore records `baseline-zero`/`not-ready` and does not fabricate a positive denominator. The strict 100x claim becomes measurable only after a positive Protected Image-chain baseline is frozen. Existing parser, wrapper, HostContext, real-sample, benchmark, test, and fuzz evidence remains auxiliary and non-regression evidence.

## 6. Scheme-A Protection Measurement

Required families are:

```text
runtime_dump_reassembly
patch_repack
function_logic_recovery
static_decomposition
dynamic_instrumentation
integrity_handoff
```

Each required family uses the same three replicas, source/artifact hashes, target runtime, pinned attack toolchain, recipe digest, random seed, resource budget, and frozen success predicate for baseline and candidate. Proposed initial budgets are 60 seconds wall, 45 seconds CPU, 1 GiB RSS, 32 processes/threads, 16 MiB captured output, 256 MiB recovered artifact, zero manual steps, and disabled network; the pilot freezes exact values before baseline capture.

The primary cost is total process-tree CPU nanoseconds to the first independently verified success. A fully attempted candidate with no success is a censored lower bound at the frozen CPU budget. Mixed replica outcomes, missing raw evidence, tool crashes, changed oracles, and unavailable required capabilities are non-passing statuses.

```text
baselineCost_f  = max(successCpuNs across 3 successful baseline replicas)
candidateCost_f = min(successCpuNs across 3 successful candidate replicas)
factor_f        = candidateCost_f / max(baselineCost_f, 1 ms)
```

A family passes only when its finite immutable baseline exists and `factor_f >= 100`, with the blue behavior/integrity oracle still valid. If no baseline attack recipe has a finite reproducible success, the family is `baseline-not-calibrated`; it is not assigned infinity or zero.

```text
schemeA_pass = every required family has status=pass and factor>=100
```

Family-specific objective success predicates are frozen in `scheme-a-manifest.json`:

- dump/reassembly: loader-accepted reassembled artifact plus behavioral equivalence;
- patch/repack: authorized-by-attacker behavior mutation reaches the target oracle without a product rebuild;
- logic recovery: machine-readable recovered logic meets frozen semantic/structural thresholds with zero manual steps;
- static decomposition: pinned tools recover the registered structural inventory thresholds;
- dynamic instrumentation: required internal trace/state or unauthorized replacement reaches its frozen threshold;
- integrity/handoff: tampered/replayed/repacked input reaches forbidden behavior/marker or bypasses required rejection.

## 7. Evidence and Gate Contract

The evaluator output is one `gate.json` plus closed raw evidence. Its top-level result keeps compatibility and Scheme A independent:

```json
{
  "schemaVersion": 1,
  "kind": "urprotect-independent-evaluator",
  "commit": "...",
  "baselineArtifactId": "...",
  "corpusVersion": "...",
  "protocolVersion": "...",
  "compatibility": {
    "status": "baseline-zero|measured|environment-unavailable|not-ready",
    "fixedRows": 0,
    "growthRows": 0,
    "baselineCompleteUnits": 0,
    "candidateFixedCompleteUnits": 0,
    "candidateGrowthCompleteUnits": 0,
    "factor": null,
    "firstFailureCounts": {}
  },
  "schemeA": {
    "status": "baseline-not-calibrated|measured|environment-unavailable|not-ready|pass",
    "requiredFamilies": [],
    "familyFactors": {},
    "allRequiredPass": false
  },
  "antiGaming": {
    "corpusUnchanged": true,
    "oracleUnchanged": true,
    "attackManifestUnchanged": true,
    "budgetsEqual": true,
    "baselineDigestMatches": true,
    "requiredRowsPresent": true
  },
  "claimable": false
}
```

`claimable=true` requires compatibility and every required Scheme-A family to pass independently, all anti-gaming checks to pass, and all existing correctness/evidence gates to remain green. `analysis-input.json` is the only normative handoff to the analysis agent besides `gate.json` and its raw manifest; it contains first-failure layers, family factors, missing evidence, benchmark/fuzz regressions, and residual risks.

## 8. CI and Retention

Retain all existing build/test/fixture/packed/HostContext/fuzz/stress/runtime/real-sample/benchmark jobs. Add an independent evaluator job after product build and native runtime provisioning:

1. validate manifests, protocol hashes, and baseline digest;
2. verify tool/runtime identities and isolation capabilities;
3. execute fixed and growth compatibility rows through all six stages;
4. execute all required Scheme-A families with identical baseline/candidate budgets/tools;
5. validate raw evidence, anti-gaming invariants, and artifact tree;
6. emit and hash `gate.json`; fail the required status when either dimension is not claimable.

PR runs must execute the fixed corpus and required family fixtures rather than changed-path subsets. Nightly/release add append-only challenges and repetition without replacing the fixed gate. Upload the evaluator tree on success and failure so the analysis agent can consume missing or failed evidence.

Existing ELF/payload-frame fuzz targets, malformed corpora, stress tests, real-sample security checks, and benchmarks remain required. Add Protected Image codec, rehydration, Native Image validation, and handoff fuzz targets only after the corresponding product stages exist. New benchmark fields measure stage costs and failure counts; they do not become Scheme-A factors.

## 9. Agent and Child-Task Flow

The parent task owns the end-to-end contract and final integration gate. The first child freezes the baseline and implements the read-only evaluator protocol. After its `gate.json` exists, an analysis agent consumes `analysis-input.json` and writes a new Trellis child task with a local gate chosen from the measured first failures. That child owns the next implementation slice. Subsequent children are created from later evaluator feedback, not guessed in advance.

Every child task must contain its own PRD, design, implement plan, evidence manifest, local gate, and rollback point. Child ordering is written in child artifacts:

```text
baseline/evaluator
  -> evaluator feedback analysis + local-gate child
  -> Protected Image ABI / rehydration slice
  -> Native Image materialization and handoff
  -> Scheme-A attack harness and calibration
  -> compatibility corpus expansion
  -> benchmark/fuzz/CI integration
  -> repeated evaluator gates
```

## 10. Rollback and Migration

- Keep current direct protected-ELF and frame paths as explicitly named auxiliary/history behavior until the new chain has a positive baseline and vertical slice.
- Make Protected Image and rehydration selection explicit in frame/profile metadata; stale or mismatched ABI/consumer versions fail before handoff.
- Store baselines content-addressed and immutable. A changed corpus, oracle, threat model, budget, toolchain, or protocol creates a new version and baseline rather than mutating history.
- If a materializer or rehydrator fails, publish no output and retain the failed stage evidence; do not fall back silently to direct protected-ELF execution for a strict-chain row.
- Roll back each child by disabling only its new profile/job while retaining manifests, negative cases, raw evidence, and the prior passing CI graph.

## 11. Risks and Trade-offs

- The current strict compatibility denominator is zero until the product emits a real Protected Image and rehydration record. This is an honest `not-ready` state, not a reason to count existing wrappers.
- Scheme A requires attack recipes with finite baseline successes. Logic recovery and dynamic instrumentation need pinned evaluator tools and native capabilities; missing capability is visible and gate-blocking for required rows.
- Requiring every required family to reach 100x is intentionally strict and may make one family the bottleneck. That is the selected product policy, not an aggregation bug.
- Native ARM64 execution and raw attack evidence are expensive. PR should use small fixed fixtures with the full protocol; nightly/release expand the append-only challenge set and retention without weakening the fixed gate.
- The new architecture improves compatibility only when materialization removes current protector-specific layout restrictions and improves strength only when the published artifact is not a complete final ELF hidden under compression. A metadata-only rename fails the evaluator's role/hash checks.
