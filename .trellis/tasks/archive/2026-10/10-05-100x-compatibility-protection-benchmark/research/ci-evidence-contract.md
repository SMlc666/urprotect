# Proposed CI, artifact, and evaluator handoff contract

## 1. Independent evaluator boundary

The evaluator is a read-only job/process. It receives the checked-out commit,
immutable baseline artifact, reviewed corpus/attack manifests, built product
artifacts, and runtime-cell inputs. It may execute those artifacts and write
only its own evidence directory. It does not edit source, manifests, product
configuration, task files, or baseline objects; it does not choose new samples,
change an oracle, or interpret a product architecture.

A separate analysis agent may consume the evaluator result, but its suggestions
are not product facts. Any implementation change requires a Trellis child task
with its own PRD/design/local gate. The evaluator's persisted handoff is the
machine-readable `gate.json` plus raw-evidence manifest, not a prose verdict.

## 2. Artifact tree

Use a new root that follows the existing `.artifacts` conventions:

```text
.artifacts/evaluator/<tier>/
  environment.json
  protocol.json
  corpus-manifest.json
  baseline-reference.json
  compatibility/
    <unit-id>/unit.json
    <unit-id>/raw/SHA256SUMS
    <unit-id>/raw/...
  strength/
    <family-id>/replica-1/attempt.json
    <family-id>/replica-1/raw/SHA256SUMS
    <family-id>/replica-1/raw/...
    ...
  benchmark/
    stage-times.json
    resource-summary.json
  gate.json
  SHA256SUMS
```

`unit-id` and `family-id` directory names are normalized manifest IDs; path
traversal, symlinks, duplicate names, missing files, and mutable external paths
are rejected. All retained text evidence is bounded. Raw binary inputs/recovery
outputs are generated in a private runner workspace and hashed before cleanup;
if the CI policy permits internal raw artifact retention, the exact raw bytes
are uploaded under `raw/`. If public artifacts must be sanitized, the result
must retain `rawPresentDuringEvaluation=true`, exact size/hash, producer command,
fixture/provenance hash, and a reproducible regeneration path. A hash with no
raw file or deterministic regeneration proof does not support a strict pass.

`SHA256SUMS` covers every retained file except itself. The final manifest hash
is recorded in `gate.json`; the gate is computed only after the tree is closed.
Reuse existing evidence controls (`check-evidence.py`, real-sample sanitization,
runtime-matrix checksum manifests, no-symlink checks, and raw-input cleanup)
where applicable. Do not upload an executable product or public real-sample
archive merely because the new evaluator needs a hash.

## 3. Required machine-readable files

### `environment.json`

Must include commit, OS/architecture, native-vs-emulated flag, kernel/page size,
runtime-cell identity, loader identity, isolation capabilities, toolchain
versions and hashes, evaluator script/build hash, and exact command/budget
parameters. Required capabilities that are absent produce
`environment-unavailable`; they do not silently downgrade a required row.

### `protocol.json`

Contains protocol/schema versions and SHA-256 digests of the compatibility
corpus, runtime matrix, attack manifest, oracle definitions, toolchain lock,
and baseline reference. This prevents a result from being read against a
changed threat model.

### `baseline-reference.json`

Contains the immutable 1x baseline object ID and digest, baseline commit,
corpus/attack/protocol hashes, tool hashes, and all frozen counts/costs. A
candidate gate fails closed if the downloaded baseline digest differs from this
record. A baseline artifact is written once and stored under a content-addressed
release/CI artifact; a later run is not permitted to overwrite it.

### `gate.json`

Minimum fields:

```json
{
  "schemaVersion": 1,
  "kind": "urprotect-independent-evaluator",
  "commit": "CANDIDATE_COMMIT",
  "baselineArtifactId": "...",
  "baselineArtifactSha256": "...",
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
    "requiredRowsPresent": true,
    "noUnownedStatusMarkers": true
  },
  "rawEvidenceManifestSha256": "...",
  "artifactManifestSha256": "...",
  "claimable": false
}
```

`claimable=true` requires compatibility and Scheme A to pass independently;
there is no combined weighted score. The current implementation should produce
`claimable=false` because its strict compatibility Protected Image stage and
Scheme-A finite baselines do not exist yet.

## 4. Status semantics

Use the repository's existing explicit result vocabulary and extend it only for
stage/attack diagnostics:

* `passed`/`measured`: the declared operation and oracle completed;
* `failed`: product/target did not meet the declared expected result;
* `environment-unavailable`: required runner, native loader, isolation, or
  pinned attack capability was absent;
* `not-applicable`: pre-registered profile boundary only; never assigned after
  an inconvenient result;
* `unknown`: protocol/measurement ambiguity, mixed replicas, or incomplete
  evidence;
* `protocol-failure`: malformed/missing/manipulated evaluator evidence;
* `baseline-zero` / `baseline-not-calibrated` / `not-ready`: the required
  frozen denominator or attack baseline does not support a numeric factor.

For a required row, `environment-unavailable`, `unknown`, and protocol failure
are CI gate failures. Optional profile observations remain visible but does not
promote a claim. An environment failure must retain environment facts, command,
expected profile, missing capability, and no fabricated target status.

## 5. CI job graph

Retain every existing build/test/fixture/packed/HostContext/fuzz/stress/runtime/
real-sample/benchmark job. Add one independent evaluator job after the product
build and required runtime-cell provisioning:

1. validate the frozen corpus, attack manifest, protocol, and baseline digest;
2. verify tool/runtime identities and sandbox capabilities;
3. run fixed compatibility units through all six stages; retain each row even
   on failure/environment-unavailable;
4. run all six Scheme-A families with the same frozen baseline, toolset, replicas,
   seed, and budget; retain all raw attempts;
5. run schema/anti-gaming/artifact-integrity checks;
6. emit `gate.json`, close/hash the tree, and fail the required status check if
   either independent dimension is not claimable.

The PR evaluator should run the frozen fixed corpus and all required bounded
Scheme-A families, not a changed-path subset. Nightly/release can add the
append-only corpus and repeated diagnostic strength runs, but must use the same
fixed rows/family gates and must never replace them with a sample. The existing
real-sample full 100-identity policy and runtime matrix provide the right
precedent for exact-ID merge checks.

If budget makes a full attack run too slow for PR, a PR may run a protocol/smoke
job only, but that job must not report Scheme-A satisfaction; the required
pre-merge status then remains `not-ready` until the full gate executes. The
simpler and more auditable option is a small committed attack fixture with the
same six families and frozen budgets on every PR, with larger append-only
challenges nightly.

Upload the evaluator tree with `if: always()` so failed and unavailable runs
remain available to an analysis agent. A missing evaluator artifact, missing
family, skipped required job, changed baseline hash, or failed anti-gaming check
blocks any 100x statement.

## 6. Benchmark and fuzz integration

Current benchmark output is a characterization of parser/validation/no-op work;
it remains and must not be relabeled as protection strength. Add separate
records only after the product exposes the chain:

* Protector analysis/emission CPU, allocation, peak RSS;
* Protected Image size and encoding cost;
* rehydration CPU/RSS and Native Image size;
* target-loader startup and behavioral-oracle wall/CPU observations; and
* per-stage failure counts.

Do not convert compression ratio, output size, hash verification, or startup
cost into a Scheme-A factor. Those are performance/diagnostic fields.

Retain existing `elf` and `payload-frame` fuzz targets, malformed corpora,
crash/timeout artifacts, and stress tests. Add Protected Image codec,
rehydration, Native Image validation, and handoff fuzz targets only when those
product stages exist. Each new fuzz target gets a bounded seed/corpus/timeout/
RSS/run manifest and a no-crash/no-timeout retained-corpus gate, using the
current SharpFuzz/libFuzzer evidence style.

## 7. Evaluator-to-analysis handoff

`gate.json` is the evaluator's only normative result. For analysis, also
persist a compact `analysis-input.json` containing:

* baseline and candidate commit/tool/corpus/protocol hashes;
* per-unit first failure layer and raw-evidence paths;
* per-family factor/lower-bound, success predicate, resource usage, and
  environment status;
* anti-gaming checks and missing evidence;
* benchmark/fuzz regressions as diagnostics; and
* the exact residual risks and `not-ready` blockers.

The analysis agent may propose priorities, rollback points, and local gates,
but must not reinterpret `environment-unavailable` as a pass or delete a
required family. A local implementation gate should point back to one or more
specific unit/family IDs and expected evidence hashes.

## 8. Local gate examples for future child tasks

These are protocol examples, not current product capabilities:

* `protected-image-emission-v1`: every selected source emits a declared
  Protected Image role/ABI artifact; no output is counted when the role is
  missing or the bytes alias Native Image.
* `rehydration-native-handoff-v1`: every Protected Image row records a distinct
  Native Image hash, invokes the declared target loader, and passes the frozen
  oracle on at least one native glibc fixture and nearest negative.
* `scheme-a-integrity-v1`: all registered mutations reject before forbidden
  handoff/entry markers; all raw mutation evidence and zero-handle/lifecycle
  evidence are retained.
* `scheme-a-vector-v1`: all six family rows have finite baseline records,
  identical candidate/baseline budgets/tools, and independent factors >=100.
* `compatibility-growth-v1`: fixed rows do not regress and append-only rows
  have distinct provenance and complete six-stage evidence; no weighted score.

Each gate remains independently machine-checkable and is persisted in the
child task that implements it.
