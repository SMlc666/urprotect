# Strict-chain evaluator analysis and positive immutable baseline-v2 gate

- **Active task:** `.trellis/tasks/10-05-analyze-strict-chain-evaluator`
- **Analysis scope:** read-only inspection of the current PR evaluator tree, its retained strict-chain/product evidence, the immutable baseline reference, and the parent/spec context. No product code, fixture/evaluator manifest, baseline, Scheme-A file, threshold, or CI file was changed.
- **Evaluator evidence tier:** `.artifacts/evaluator/pr`
- **Candidate evidence commit recorded by the evaluator:** `042a7d6d4e2d5f1c5ffe91d026d624ca995ad0bd`
- **Checked-out commit during this analysis:** `9574bca7fd5d11f8c998033603e7a0659b611b9d`

## 1. Result

The retained candidate evidence proves **one complete six-stage strict-chain unit** for `compat.protection-symbolized-fixture.glibc.outer-execveat`. The proof is based on the independent evaluator's `unit.json`, the closed raw manifest, and the retained product-chain manifest; it is not inferred from direct protected-ELF, parser, wrapper, or auxiliary fixture evidence.

The current evaluator result remains deliberately non-claimable:

- the immutable baseline object is `baseline-zero` with zero complete units;
- the candidate has one complete unit, but a zero denominator yields `factor: null`, not a numeric factor;
- `claimable` is `false` because the strict positive denominator is not frozen and Scheme-A is independently `baseline-not-calibrated`;
- Scheme-A has six required families, zero baseline replicas in every family, and null factors; this is not a strength score and is not a pass.

The next implementation/evidence child should freeze a **new content-addressed compatibility baseline-v2** containing this one strict unit only after a fresh evaluator run closes the current package-level consistency gaps. Baseline-v2 is a compatibility denominator snapshot, not a 100x claim and not Scheme-A calibration.

## 2. Hash ledger and evidence closure

The following hashes are the bytes observed during this analysis. The distinction between a file's current SHA-256 and a digest declared inside another artifact is intentional and is part of the result.

| Evidence | Path | Observed SHA-256 |
| --- | --- | --- |
| Gate | `.artifacts/evaluator/pr/gate.json` | `f2bc44c9bc81d62828790c42c664fe153526aa0a446faed98f8e79235dfc462c` |
| Analysis input | `.artifacts/evaluator/pr/analysis-input.json` | `28605c2888427690a8cdc27b1d284737379956add04c3b44255710ecbbdffdea` |
| Baseline reference | `.artifacts/evaluator/pr/baseline-reference.json` | `3290389f3c28778131b6a633143f17432cc3ffc807d3e38907e941495636b44c` |
| Evaluator root manifest, current bytes | `.artifacts/evaluator/pr/SHA256SUMS` | `111d39a69da8f4447a2553e618e00139995a1df8380d734c9f80909c81d4b588` |
| Evaluator root manifest, gate-declared value | `gate.json:artifactManifestSha256` and `rawEvidenceManifestSha256` | `27806fe7669d88dad9d510457e8d9623a9b51326a39aa7592aed698c63df2a63` |
| Unit record | `compatibility/.../unit.json` | `9fe0d3881021d32a1885d7c6e1ecfc47e6161014d345478d07ded8ef719c62b4` |
| Unit raw manifest | `compatibility/.../raw/SHA256SUMS` | `f98745a844a78040c4b0c47bc9adfae353bfe05c185a6f33cc213142d9a75a49` |
| Product-chain manifest | `compatibility/.../raw/product-chain/SHA256SUMS` | `77726071141a04f945444d8045f7fac86b415fbd9ade05113228cdfa96bbfee5` |
| Retained product-evidence manifest | `.artifacts/protected-image/pr/glibc/.../SHA256SUMS` | `77726071141a04f945444d8045f7fac86b415fbd9ade05113228cdfa96bbfee5` |
| Immutable baseline object | `fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json` | `3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2` |
| Scheme-A gate | `.artifacts/evaluator/pr/scheme-a-gate.json` | `1d08c5a066b72855d472f3a01f512b59dfa336f52c1cb9b53a589e19c64d1d14` |
| Scheme-A manifest | `.artifacts/evaluator/pr/scheme-a-manifest.json` | `bece932bd38e8c3e1def844023e19306acd37583862f17c6e3943c4ecf57eacc` |
| Protocol | `.artifacts/evaluator/pr/protocol.json` | `b3aa29a728cb4e98d4704ab7fa9cd7bf6e4afefaa6e646fde92a211557e8c6bd` |
| Corpus manifest | `.artifacts/evaluator/pr/corpus-manifest.json` | `8f48bed4fe66a2fde8ad968972fec2654890956d777a54d6394687d5e503efa4` |
| Oracle registry | `.artifacts/evaluator/pr/oracles.json` | `91e8a867157808f839edbabaf6c766c00d86e10f10729130debab0ce640175a4` |

### Closure result

All file entries in the four checked manifests were verified against their listed hashes:

- evaluator root: **258 entries, 0 bad**;
- unit raw tree: **31 entries, 0 bad**;
- retained product-chain tree: **29 entries, 0 bad**;
- retained product-evidence tree: **29 entries, 0 bad**.

The evaluator root manifest and the product/strict-chain nested manifests are therefore internally closed at the file-entry level. There is one package-level inconsistency that blocks immediate baseline-v2 publication: the current root manifest hashes to `111d39...`, while both `gate.json` manifest fields declare `27806f...`. This is not silently normalized. A fresh run must close and re-emit the root manifest so that the observed root SHA equals both gate fields.

A second package-level freshness issue is that `gate.json` and `environment.json` record commit `042a7d6...`, while the checked-out repository is at `9574bca...`. The existing validator was run and failed with:

```text
FAIL independent evaluator evidence: environment commit does not match checked-out commit
```

Consequently, the strict-unit conclusion below is scoped to the retained evidence commit and hashes. A positive baseline-v2 freeze must use a fresh evaluator package whose recorded commit equals the checkout used for the freeze.

## 3. Proof of the complete six-stage candidate unit

**Unit:** `compat.protection-symbolized-fixture.glibc.outer-execveat`  
**Unit record:** `compatibility/compat.protection-symbolized-fixture.glibc.outer-execveat/unit.json` (`9fe0d388...`)  
**Raw manifest:** `compatibility/compat.protection-symbolized-fixture.glibc.outer-execveat/raw/SHA256SUMS` (`f98745...`)  
**Strict status:** `raw/strict-chain-status.json` (`12da7d83a2361b8f57500a1971e83bdea0ca0d1f9ab7a40d168d21821d587032` as listed by the evaluator root manifest)

The unit has `complete: true`, `strictChainMeasured: true`, `firstFailureLayer: null`, and the strict status has `nativeResultsCaptured: true`, `strictChainMeasured: true`, and `status: measured`. The stage key set is exactly the six required names; key order in JSON is immaterial.

| Stage | Retained evidence and status | Exact linkage |
| --- | --- | --- |
| `protector` | `raw/product-chain/stage.json` (`abb0cc8e...`) and product `stage.json`; `status: passed` | source image `d676d718...`, request `4c759b0d...`, producer `gcc-c-protection-fixture`, producer build `b1dd5735...`, output/protected artifact `2e59a447...` |
| `protected-image` | `raw/product-chain/protected-image.json` (`f569f224...`); `status: passed` | role `protected-image`, ABI `urprotect.protected-image.v1`, version `1`, exact artifact `protected-image.bin` SHA `2e59a447...`, size `393`, declared consumer `urprotect.rehydrator.v1`, raw bytes retained |
| `rehydration` | `raw/product-chain/rehydration.json` (`d4ef8000...`); `status: passed` | input Protected Image `2e59a447...`; consumer `urprotect.rehydrator.v1`, consumer build `57589fa1...`; output Native Image `ede64f3f...`; handoff record SHA `cb8475c4...`; materialization and handoff both passed |
| `native-image` | `raw/product-chain/native-image.json` (`0a1a28d2...`); `status: passed` | role `native-image`, ABI `urprotect.native-image.v1`, exact bytes `native-image.bin` SHA `ede64f3f...`, size `73764`, rehydration record `d4ef8000...` |
| `target-loader` | `raw/product-chain/target-loader.json` (`45d27dfd...`); `status: passed` | loader `kernel.execveat-at-empty-path`, handoff/evidence SHA `cb8475c4...`, exact Native Image SHA `ede64f3f...`, target status `0`, signal `null` |
| `behavioral-oracle` | `raw/product-chain/behavioral-oracle.json` (`196c6cc0...`) and comparison `behavior-comparison.json` (`179a03ec...`); `status: passed` | oracle `fixture.process-oracle.v1`, source image `d676d718...`, Native Image `ede64f3f...`, status/stdout/stderr comparisons all equal, target status `0` |

Additional byte-level facts:

- `source-image.bin` hashes to `d676d7180958ea55fe3344c02ebb213d3b40c75f5fccdbeebd4b16aa82e26ac9`, matching every stage's `sourceImageSha256` and the strict status record. The corpus source provenance hash is separately `4f26b59a...`; these are the source file and built source-image roles, respectively.
- `protected-image.bin` hashes to `2e59a4472f11626a0a9465d049c8be0363c95189525b22cf66229114b276ba62` and is 393 bytes.
- `native-image.bin` hashes to `ede64f3fcc2c9651c8c92e3686bcd206f04ad783b72afdb415ef836de4505fff` and is 73,764 bytes.
- The Protected Image and Native Image hashes are distinct, and the rehydration record binds both exact values. This rules out a final ELF being merely renamed as the Protected Image for this row.
- The product-chain manifest SHA `777260...` equals the unit's `productEvidence.manifestSha256`, the strict status `productEvidenceManifestSha256`, and the retained product-evidence manifest SHA. The evaluator raw manifest binds the product-chain manifest itself.
- `baseline.status` and `behavior-check.status` both contain `0`; baseline and target stdout hashes are both `ac1988da...`, and stderr hashes are both the empty-stream digest `e3b0c442...`.

### Why this is not auxiliary direct-ELF evidence

The unit's strict records are under `raw/product-chain/` and include a product-owned Protected Image role, a separate rehydration record, a Native Image role, actual `execveat` handoff, and the frozen behavior oracle. The corpus explicitly retains the direct-ELF shortcut as the negative row `compat.legacy-direct-protected-elf-not-strict-chain` with reason that it has no Protected Image ABI or rehydration record. The unit also lists the existing protection-policy/E2E scripts only under `auxiliaryEvidence`; none is used to synthesize a stage status. This is an independently measured strict chain, not a relabeling of auxiliary wrapper or direct-ELF evidence.

## 4. Why the current result is baseline-zero, factor-null, and non-claimable

The immutable reference is:

- ID: `compatibility-1x-baseline-zero`;
- path: `fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json`;
- object SHA: `3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2`;
- reference SHA: `baseline-reference.json` (`3290389f...`), whose `baselineArtifactSha256` matches the object;
- fixed corpus rows: `1`;
- complete units: `0`;
- `completeUnitIds: []`;
- `baselineStatus: baseline-zero`;
- immutable/content-addressed/never-overwrite flags: all true.

The normative gate repeats `baselineArtifactId` and the same baseline object SHA, and reports:

```text
baselineCompleteUnits       = 0
candidateFixedCompleteUnits = 1
candidateGrowthCompleteUnits = 1
factor                       = null
growthTarget                 = 0
growthViewPass               = false
claimable                    = false
compatibility.status         = baseline-zero
```

The candidate's one complete unit is valid progress evidence, but it does not mutate the historical denominator. The evaluator protocol explicitly represents a zero denominator as `null`; it does not assign 1x, infinity, or a fabricated numeric factor. `growthTarget: 0` is a diagnostic consequence of the zero baseline and is not a passing 100x result. The fixed-view observation is useful (`fixedViewPass: true`), but it does not turn the old zero baseline into a positive baseline.

The baseline object also records the strict blockers `protected-image-stage-not-declared`, `rehydration-stage-not-declared`, and `native-target-loader-oracle-not-captured` for its historical commit. The newly retained candidate evidence closes those stages for one candidate unit; it does not rewrite that historical object.

## 5. Why Scheme-A remains baseline-not-calibrated

Scheme-A is an independent dimension and is unchanged by the strict compatibility unit:

- the normative gate's `schemeA.status` is `baseline-not-calibrated` and `allRequiredPass` is `false`;
- all six required families remain present: `runtime_dump_reassembly`, `patch_repack`, `function_logic_recovery`, `static_decomposition`, `dynamic_instrumentation`, and `integrity_handoff`;
- each family has `baselineReplicas: 0`, `baselineCostCpuNs: null`, `factorLowerBound: null`, `environmentUnavailable: true`, and `status: baseline-not-calibrated`;
- `scheme-a-gate.json` repeats the same status and null factors;
- `scheme-a-manifest.json` has `publishedArtifactSha256: null`, `publishedArtifactStatus: not-produced`, tool versions/binary hashes null, and tool availability `not-calibrated` for every required family;
- the evaluator analysis lists all baseline/candidate attempts as `environment-unavailable`; no finite three-replica baseline success exists.

No zero, infinity, or proxy strength value is inferred from the compatibility run. A positive compatibility baseline-v2 artifact must record `schemeAStatus: baseline-not-calibrated`, retain the `scheme-a-v1` policy/manifest digest, and set any compatibility-baseline claim flag for Scheme-A to false. Scheme-A can only advance through its own future calibration gate with the same six-family policy and three finite reproducible baseline successes per required family.

## 6. Machine-checkable positive immutable compatibility baseline-v2 local gate

### Gate name and purpose

`compatibility-positive-immutable-baseline-v2` freezes the first positive strict-chain denominator. It is a local compatibility-baseline gate, not a replacement for the parent 100x gate and not a Scheme-A gate.

The gate produces a new immutable payload and reference, for example:

```text
fixtures/evaluator/baselines/compatibility-1x-v2.json
fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
.artifacts/evaluator/pr/positive-baseline-v2-gate.json
```

The old `compatibility-1x-baseline-zero` payload and reference remain byte-identical. The new reference carries the SHA-256 of the new payload; the payload's content address is the `(baselineArtifactId, baselineArtifactSha256)` pair, avoiding a self-hash cycle.

### Preconditions and exact checks

A machine-checkable implementation should return `pass` only when every check below is true. Otherwise it returns `blocked` and publishes no new baseline/reference.

1. **Freshness and package closure**
   - `git rev-parse HEAD == gate.commit == environment.commit` for the run being frozen. The current retained package fails this check (`HEAD=9574bca...`, artifact commit `042a7d6...`).
   - Verify every entry in evaluator root, unit raw, product-chain, and retained product manifests.
   - Require `sha256(.artifacts/evaluator/pr/SHA256SUMS) == gate.artifactManifestSha256 == gate.rawEvidenceManifestSha256`. The current retained package fails this check (`actual=111d39...`, declared=`27806f...`).
   - Require the unit's raw manifest and product evidence manifest hashes to equal their parent records. These nested checks pass for the retained evidence (`f98745...` and `777260...`).
   - Require the existing independent evaluator validator to pass on the fresh package; its current invocation is retained as a failed validation witness, not converted to pass.

2. **Compatibility-scope environment**
   - The fresh run must report true for the strict-chain capabilities: native AArch64, pinned `glibc.current.native-arm64` runtime cell, Protected Image producer, rehydrator, locked SDK/toolchain, network-disabled evaluator input, and the declared isolation capabilities.
   - Scheme-A attack tooling is not a prerequisite for this compatibility-only freeze. Its absence remains visible and leaves Scheme-A `baseline-not-calibrated`; this separation preserves the two independent dimensions.
   - Native results must be captured from the declared loader lane, not inferred from an emulated or unpinned environment.

3. **Frozen identity and corpus invariants**
   - `corpusVersion == compat-corpus-v1`, protocol version remains `evaluator-v1`, and the corpus/protocol/oracle/runtime/fixture digests remain the already frozen values (`8f48bed4...`, `b3aa29a7...`, `91e8a867...`, `8d778d22...`, and `c354380e...`).
   - The fixed view contains exactly the existing row `compat.protection-symbolized-fixture.glibc.outer-execveat`; its `unitId`, `identityKey`, source/provenance, profile, runtime cell, loader, and oracle are unchanged.
   - Duplicate identity or variant inflation fails the gate. No row is removed, renamed, downgraded, or reclassified as auxiliary.

4. **Strict six-stage unit**
   - Exactly one fixed row has `complete == true` and `strictChainMeasured == true`.
   - The six required stages are exactly `protector`, `protected-image`, `rehydration`, `native-image`, `target-loader`, and `behavioral-oracle`; every stage is `passed` for the same unit, source image, profile, runtime cell, oracle, and run.
   - Require the exact current retained hash relationships: producer output/Protected Image `2e59a447...`; rehydration input `2e59a447...`; Native Image `ede64f3f...`; target-loader input `ede64f3f...`; loader handoff `cb8475c4...`; behavior comparison `179a03ec...`; oracle `fixture.process-oracle.v1`; target status `0`; signal `null`.
   - Recompute the Protected Image and Native Image hashes from retained bytes and require them to differ. Require the Protected Image role/ABI and the rehydration record; a direct ELF, complete compressed ELF, parser result, or wrapper-only record fails.
   - Require `firstFailureLayer == null`, `nativeResultsCaptured == true`, and the declared behavior oracle's status/stdout/stderr comparisons to pass.

5. **New baseline payload/reference**
   - Payload `kind` remains `compatibility-1x-baseline`; `baselineVersion` is a new immutable version such as `compatibility-1x-v2`; `fixedCorpusRows: 1`; `completeUnits: 1`; `completeUnitIds` contains exactly the unit ID above; `baselineStatus: measured` (or the repository's reviewed positive-baseline vocabulary).
   - Include exact producer ID/build hash, Protected Image ABI/version/size/hash, rehydrator consumer/build hash, rehydration-record hash, Native Image ABI/version/size/hash, loader ID/handoff evidence hash, oracle ID/comparison hash, source-image hash, unit JSON hash, unit raw-manifest hash, product-chain-manifest hash, evaluator gate hash, and closed artifact-manifest hash.
   - Include the unchanged corpus/protocol/oracle/runtime/fixture bindings. Store the payload once; the reference records its exact payload SHA and `immutable: true`, `contentAddressed: true`, `neverOverwrite: true`.
   - The new baseline is a denominator snapshot only. It does not set a compatibility factor or `claimable` state.

6. **Scheme-A non-claim invariant**
   - Preserve `scheme-a-v1`, the six required families, and the current Scheme-A manifest digest.
   - Record `schemeAStatus: baseline-not-calibrated`, null family factors, and `schemeAClaimable: false` in the baseline-v2 projection.
   - The local gate must fail if it sees a reduced family list, changed budget/tool/oracle, fabricated finite baseline cost, or a Scheme-A pass derived from this compatibility unit.

### Suggested machine-readable local-gate output

```json
{
  "schemaVersion": 1,
  "kind": "compatibility-positive-baseline-local-gate",
  "gateId": "compatibility-positive-immutable-baseline-v2",
  "status": "pass",
  "baselineArtifactId": "compatibility-1x-v2",
  "baselineArtifactSha256": "BASELINE_V2_PAYLOAD_SHA256",
  "source": {
    "evaluatorGateSha256": "FRESH_GATE_JSON_SHA256",
    "analysisInputSha256": "28605c2888427690a8cdc27b1d284737379956add04c3b44255710ecbbdffdea",
    "artifactManifestSha256": "FRESH_CLOSED_ROOT_MANIFEST_SHA256",
    "unitJsonSha256": "9fe0d3881021d32a1885d7c6e1ecfc47e6161014d345478d07ded8ef719c62b4",
    "unitRawManifestSha256": "f98745a844a78040c4b0c47bc9adfae353bfe05c185a6f33cc213142d9a75a49",
    "productEvidenceManifestSha256": "77726071141a04f945444d8045f7fac86b415fbd9ade05113228cdfa96bbfee5"
  },
  "identity": {
    "corpusVersion": "compat-corpus-v1",
    "protocolVersion": "evaluator-v1",
    "unitId": "compat.protection-symbolized-fixture.glibc.outer-execveat",
    "fixedRows": 1,
    "completeUnits": 1
  },
  "strictChain": {
    "allSixStagesPassed": true,
    "sourceImageSha256": "d676d7180958ea55fe3344c02ebb213d3b40c75f5fccdbeebd4b16aa82e26ac9",
    "protectedImageSha256": "2e59a4472f11626a0a9465d049c8be0363c95189525b22cf66229114b276ba62",
    "nativeImageSha256": "ede64f3fcc2c9651c8c92e3686bcd206f04ad783b72afdb415ef836de4505fff",
    "loaderId": "kernel.execveat-at-empty-path",
    "oracleId": "fixture.process-oracle.v1",
    "behaviorComparisonSha256": "179a03ec7a6e41f513ce74f7602434c238b52604c5d8f1d30371ef982672bcbf"
  },
  "schemeA": {
    "protocolVersion": "scheme-a-v1",
    "status": "baseline-not-calibrated",
    "claimable": false
  },
  "rollback": {
    "previousBaselineArtifactId": "compatibility-1x-baseline-zero",
    "previousBaselineArtifactSha256": "3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2",
    "fallbackProfile": "strict-chain-not-ready",
    "publishOnFailure": false
  }
}
```

The `nativeImageSha256` value in the illustrative JSON above is the verified unit-record value (`ede64f3fcc2c9651c8c92e3686bcd206f04ad783b72afdb415ef836de4505fff`); the child gate should still reject any value that is not the recomputed byte hash.

### Exact command/artifact handoff for the parent

The full proposed child bundle is persisted at:

`.trellis/tasks/10-05-analyze-strict-chain-evaluator/research/follow-on-positive-baseline-v2-child.md`

The parent can create the follow-on child with:

```sh
python3 ./.trellis/scripts/task.py create \
  "Freeze positive immutable compatibility baseline v2" \
  --slug freeze-positive-immutable-baseline-v2 \
  --parent .trellis/tasks/10-05-100x-compatibility-protection-benchmark \
  --priority P0 --no-start
```

That bundle contains complete draft `prd.md`, `design.md`, `implement.md`, `implement.jsonl`, and `check.jsonl` contents. It intentionally leaves the new child in planning until the parent reviews the two package-level blockers above.

## 7. Rollback and policy boundary

- **Before publication:** any freshness, manifest, environment, identity, stage, hash, oracle, or Scheme-A invariant failure returns `blocked`; no baseline-v2 payload/reference is written. The immutable zero baseline remains the active denominator and the existing auxiliary/direct paths remain named as auxiliary.
- **After publication:** baseline-v2 is never overwritten. If a later compatibility child regresses or a handoff/materializer fails, disable only the new strict-chain baseline/profile selection, retain the v2 object and all raw evidence, and return to the prior passing graph/reference. A corrected contract, corpus, oracle, budget, toolchain, or environment receives a new content-addressed baseline version rather than mutating v2.
- **No silent fallback:** a failed Protected Image or rehydration stage does not fall back to direct protected-ELF execution for a strict row; the row remains failed/blocked with its evidence.
- **100x policy unchanged:** after a positive baseline with `completeUnits=1` is frozen, the parent compatibility growth rule remains the exact integer condition `candidateGrowthCompleteUnits >= 100 * frozenBaselineCompleteUnits` (target `100`). Fixed-view non-regression remains required. Baseline-v2 itself is not a 100x result.
- **Scheme-A policy unchanged:** every required family remains independently required with its existing three-replica/frozen-budget/factor rules. Baseline-v2 makes no Scheme-A claim and does not assign a factor.

## 8. Residual risks and next child

1. **Evaluator package freshness/closure (blocking):** current root manifest digest and gate-declared digest differ, and the evaluator commit is behind the checkout. Rerun/close the evaluator package at the exact freeze commit before baseline-v2 publication.
2. **Environment capability scope (blocking for a fresh freeze):** the current environment record says `environment-unavailable` for network-disabled execution, pinned runtime cell, Protected Image producer, rehydrator, and Scheme-A tooling. The strict product evidence is retained and hash-valid, but a fresh compatibility lane must establish the required compatibility capabilities and native loader identity. Scheme-A tooling remains independent and may stay unavailable.
3. **Single-unit coverage:** one complete unit establishes the first denominator only. It provides no broad compatibility claim and sets a future 100-unit growth target after v2 is frozen.
4. **Runtime/profile scope:** the proof is limited to `outer-execveat` on `glibc.current.native-arm64`; it says nothing about musl, bionic, HostContext, or other loader/profile rows.
5. **Negative publication boundary:** the positive retained tree does not itself demonstrate every malformed/tampered Protected Image rollback case. The child should retain at least one nearest-negative handoff/materialization witness proving no Native Image publication or loader marker after a failed stage, while preserving the positive baseline unit.
6. **Scheme-A calibration:** all six attack families remain uncalibrated and block any overall claim. The compatibility baseline child must leave their manifests, thresholds, and status untouched.

**Next child:** `freeze-positive-immutable-baseline-v2`, using the exact draft artifacts in the companion research file. Its first action is a fresh package/evidence rerun and closure check; its success action is content-addressed baseline-v2 publication with `completeUnits=1` and `schemeAClaimable=false`.

## 9. Validation commands executed

```sh
python3 ./.trellis/scripts/task.py current --source
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
```

The task resolver passed. The existing evaluator checker failed as recorded above because the environment commit (`042a7d6...`) does not match checkout `9574bca...`.

Read-only manifest/hash checks executed in this analysis verified all four manifests and all six stage/hash assertions. The compact result was:

```text
evaluator: 258 entries, bad=0
strict-chain-raw: 31 entries, bad=0
product-chain: 29 entries, bad=0
product-evidence: 29 entries, bad=0
six-stage/hash-link assertions: PASS
unit= compat.protection-symbolized-fixture.glibc.outer-execveat
baseline-complete-units= 0
candidate-complete-units= 1
scheme-a-status= baseline-not-calibrated
claimable= False
declared-root-manifest-sha256= 27806fe7...
actual-root-manifest-sha256= 111d39a6...
```

No commit was created.
