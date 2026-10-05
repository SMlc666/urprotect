# Proposed strict compatibility evaluator protocol

This is the proposed evaluator contract. It deliberately does not define a
new loader, relocation model, or Protected Image implementation. The product
must emit the Protected Image ABI and the rehydrator; the evaluator only binds
roles, hashes, stage outcomes, the already-declared target runtime, and the
existing behavioral oracle.

## 1. Frozen corpus and unit identity

Create an append-only `compatibility-corpus.json` before the first baseline
run. Start from the checked-in fixture/real-sample/runtime manifests, retaining
all existing IDs and negative cases. Each applicable row has:

```json
{
  "unitId": "compat.c-gcc-glibc-pie.host-context-v1.glibc.current",
  "identityKey": "c-gcc-glibc-pie",
  "sourceProvenance": "fixtures/samples/... + builder recipe hash",
  "sourceSha256": "SOURCE_SHA256",
  "producerId": "gcc-c",
  "featureTags": ["ET_DYN", "PT_DYNAMIC", "glibc"],
  "profile": "PROFILE_ID",
  "runtimeCell": "glibc.current.native-arm64",
  "targetLoader": "DECLARED_LOADER_ID",
  "oracleId": "fixture.process-oracle.v1",
  "applicable": true,
  "required": true
}
```

`unitId` and `identityKey` are registered before execution. A generated
variant must not create a new unit merely by changing a compression level,
launcher, package version, or random seed. A new producer/ELF feature/runtime
interaction requires a reviewed append-only row and provenance. The real-sample
registry's rule that runtime/package variants do not multiply identity count is
retained. Each unit is counted at most once per exact corpus version, regardless
of rerun count.

Use two views without changing the denominator:

* **fixed view:** the exact frozen rows in the 1x snapshot; candidates must not
  regress any previously applicable row;
* **growth view:** the frozen rows plus append-only reviewed increments. New
  complete units demonstrate coverage growth; duplicate identities are rejected
  by manifest validation.

Do not remove, rename, downgrade, or silently change a row after baseline.
Changing a source, producer, runtime, oracle, profile, or threat model creates
an explicit corpus version and a new baseline, never a revised old denominator.

## 2. Required stage chain

A row contributes one compatibility unit only if all of these stages are
`passed` for the same `unitId`, same source digest, same profile/runtime, and
same run:

```text
source image
  -> Protector
  -> Protected Image (product-declared ABI artifact)
  -> rehydration (product-declared consumer)
  -> Native Image (bytes actually given to the target loader)
  -> target native loader
  -> behavioral oracle
```

The evaluator uses these stage names and does not infer one from another:

| Stage | Machine-checkable evidence | Excluded shortcut |
| --- | --- | --- |
| `protector` | command/build identity, input hash, output Protected Image hash, status, bounded logs | parser acceptance or direct protected ELF without a Protected Image artifact |
| `protected-image` | product-emitted role/ABI manifest, ABI/version, exact bytes/hash, producer and declared rehydrator consumer | a v3 Deflate frame carrying the complete source ELF; a final ELF relabeled as Protected Image |
| `rehydration` | product rehydrator invocation, Protected Image hash in, Native Image hash out, status, resource/time record | decompression/copy evidence unless the product explicitly declares it as the ABI consumer |
| `native-image` | exact bytes/hash written to the target-loader invocation, structural report, mode/permissions | parser-only output or an unobserved temporary/intermediate file |
| `target-loader` | actual target loader/process invocation, runtime cell identity, exit/signal status and loader evidence | `readelf`, `dlopen`/`dlsym` test unrelated to this unit, or a handoff claim without process execution |
| `behavioral-oracle` | fixed oracle ID, baseline digest, candidate observations, exact comparison result | stdout-only or a weakened oracle chosen after seeing the candidate |

The Protected Image metadata is an envelope for evaluator binding, not a
loader model. Require only fields needed to bind evidence:

```json
{
  "schemaVersion": 1,
  "artifactRole": "protected-image",
  "abiId": "PRODUCT_DECLARED_ABI_ID",
  "abiVersion": "PRODUCT_DECLARED_VERSION",
  "unitId": "...",
  "sourceSha256": "SOURCE_SHA256",
  "artifactSha256": "PROTECTED_IMAGE_SHA256",
  "artifactSize": 1234,
  "producerBuildSha256": "PRODUCT_BUILD_SHA256",
  "rehydratorConsumerId": "PRODUCT_DECLARED_CONSUMER",
  "rawArtifactPath": "raw/protected-image.bin",
  "rawArtifactRetained": true
}
```

The evaluator must not require fields that prescribe how the image is encoded,
relocated, decoded, or loaded. It must, however, reject a missing ABI identity,
missing exact bytes/hash, a role mismatch, or an artifact that is byte-identical
to the Native Image. The latter prevents the claimed chain from being only a
renamed final ELF. If the product intentionally supports an identity transform,
that is a separately named non-protection profile and is not a strict
Protected Image-chain unit.

The rehydration record binds the consumer without defining its internals:

```json
{
  "schemaVersion": 1,
  "unitId": "...",
  "protectedImageSha256": "PROTECTED_IMAGE_SHA256",
  "nativeImageSha256": "NATIVE_IMAGE_SHA256",
  "consumerId": "PRODUCT_DECLARED_CONSUMER",
  "consumerBuildSha256": "PRODUCT_BUILD_SHA256",
  "status": "passed",
  "commandDigest": "COMMAND_AND_ENV_DIGEST",
  "resourceEvidence": "raw/rehydration.resources.json"
}
```

The Native Image hash must be calculated from the exact bytes handed to the
already-reviewed native loader. A target loader invocation must be present;
static ELF reports never substitute for it. A wrapper may be used as the
transport, but the row still needs an explicit Protected Image artifact and a
separate rehydration record. Existing outer-wrapper and HostContext rows remain
auxiliary until they satisfy these roles.

## 3. Behavioral oracle

The oracle is registered with each corpus row and frozen before the baseline.
Reuse the repository's strongest existing observations instead of inventing a
new loader semantic:

* fixture/packed process rows compare status, stdout, stderr, and, where the
  process probe is declared, argv/argv[0], arguments, environment, cwd,
  inherited descriptor, declared-file effects, and signal termination;
* HostContext rows compare declared entry status, exactly-once dispatch,
  release/destructor/lifecycle markers, sealed-image evidence, and clean
  streams;
* runtime-matrix rows use native runtime and loader identity plus the existing
  marker/output oracle;
* real-sample rows use only the per-project command/closure policy already
  declared by the registry. Static `validated` is never an execution success.

An oracle record has a frozen `oracleId`, command digest, expected status,
stream/file/signal comparison rules, bounded output limits, and a baseline
observation hash. ASLR addresses, timing, and unrelated host paths are excluded
from behavioral equality unless a row explicitly declares them. A candidate
that changes an oracle rule, drops an observation, or changes the target loader
is a protocol failure, not an improvement.

## 4. Per-unit result and score

Each unit writes a bounded JSON record with all stage outcomes:

```json
{
  "schemaVersion": 1,
  "unitId": "...",
  "corpusVersion": "compat-corpus-v1",
  "sourceSha256": "SOURCE_SHA256",
  "profile": "PROFILE_ID",
  "runtimeCell": "RUNTIME_CELL",
  "oracleId": "fixture.process-oracle.v1",
  "stages": {
    "protector": {"status": "passed", "outputSha256": "..."},
    "protected-image": {"status": "passed", "artifactSha256": "...", "abiVersion": "..."},
    "rehydration": {"status": "passed", "nativeImageSha256": "..."},
    "native-image": {"status": "passed", "sha256": "..."},
    "target-loader": {"status": "passed", "loaderId": "...", "statusCode": 0},
    "behavioral-oracle": {"status": "passed", "comparisonSha256": "..."}
  },
  "complete": true,
  "firstFailureLayer": null,
  "rawEvidenceManifest": "raw/SHA256SUMS"
}
```

Allowed statuses are `passed`, `failed`, `environment-unavailable`,
`not-applicable`, `unknown`, and `protocol-failure`. A required, applicable row
with any non-`passed` stage is not a unit. Its row remains in the denominator
and its `firstFailureLayer` is retained. `environment-unavailable` is never
converted to `not-applicable` by a runner default.

Define the strict count as:

```text
C(version, view) = count(distinct unitId with complete == true)
compatibility_factor = C(candidate, growth-view) / C(frozen-baseline, fixed-view)
```

A fixed-view candidate must have `C(candidate, fixed-view) >= C(baseline,
fixed-view)` (non-regression). The growth gate requires the exact unrounded
integer condition `C(candidate, growth-view) >= 100 * C(baseline, fixed-view)`;
there is no weighted average, feature histogram substitution, parser credit,
or wrapper-only credit.

The first measured repository state has no product-declared Protected Image
stage, so the evaluator should emit `baselineStatus=baseline-zero` and
`completeUnits=0` if run against the current implementation. It must not call
that zero a positive 1x compatibility result and must not divide by zero. The
strict 100x gate is `not-ready` until a positive frozen baseline unit exists.
A progress-only report may show `targetCompleteUnits=100 * max(1, baselineUnits)`
for planning, but this floor is not a compatibility factor and does not satisfy
R9. This rule prevents a zero-denominator claim while preserving a concrete
path to the first baseline.

## 5. Baseline snapshot

Freeze exactly one immutable baseline artifact before implementation changes
that claim the new chain. The snapshot contains:

```json
{
  "schemaVersion": 1,
  "kind": "compatibility-1x-baseline",
  "commit": "86270e71362572d32544c9fa979553e2f3c4cb7c",
  "prdSha256": "4e88cafe02ffd2703c3dae33d151c1624016898ec4e2cc301b5c2f69b500f469",
  "corpusManifestSha256": "CORPUS_MANIFEST_SHA256",
  "fixtureManifestSha256": "c354380e84234e6dd94a9d848956010a2d92ad4014dcec24bf5e466eb9a3ddab",
  "runtimeRegistrySha256": "8d778d22926ba5e2791f46821623700e0baccad3fce26201e10ba6cf0ea0dac5",
  "toolchainManifestSha256": "TOOLCHAIN_MANIFEST_SHA256",
  "environmentSha256": "ENVIRONMENT_SHA256",
  "protocolSha256": "PROTOCOL_SHA256",
  "fixedCorpusRows": 0,
  "completeUnits": 0,
  "baselineStatus": "baseline-zero",
  "rawEvidenceSha256": "RAW_EVIDENCE_MANIFEST_SHA256",
  "immutableArtifactId": "compatibility-1x-BASELINE_DIGEST"
}
```

The current commit, manifest hashes, exact compiler/SDK/launcher/runtime
identity, runner architecture/kernel/page size, and all raw artifact hashes are
captured in the actual snapshot. The placeholder values above are schema
examples, not measurements. The snapshot is content-addressed and must not be
overwritten when a later candidate performs poorly.

## 6. Environment and bounded execution

Required strict compatibility lanes run on native AArch64 with the selected
`fixtures/runtime-matrix.json` runtime cell. The existing runtime matrix is the
authority for runtime/loader identity, native-vs-emulated status, page-size
classification, pinned OCI image/toolchain facts, and bionic package evidence.
A local Android-derived kernel, a container page-size assumption, QEMU, or an
x86 native bridge does not substitute for a required native cell.

For each unit use an evaluator-owned sandbox with the existing repository
precedent: network disabled, read-only root/input, bounded writable temporary
output, dropped capabilities/no-new-privileges where available, bounded
processes, memory, output, and wall time. Record the exact limits and whether
each isolation capability was actually active. A missing required capability is
`environment-unavailable` and fails the required gate; it is not a skipped row.

The compatibility protocol does not use timing as behavioral equality. Timing
and resource records are retained for diagnosis and for the separate benchmark,
not to move the unit count.
