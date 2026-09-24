# Public real-sample CI corpus design

## Design objective

Add a third, ecology-facing evidence layer beside the existing synthetic
contract fixtures and controlled producer fixture matrix. The new layer owns a
locked set of exactly 20 distinct public AArch64 projects, obtains their
artifacts only inside CI, runs applicable observations in an isolated native
ARM64 environment, and retains normalized evidence without treating sample
success as an automatic support claim.

The design keeps product behavior and the existing `fixtures/manifest.json`
contract stable during the first corpus slice. Real-sample observations can
identify a missing or surprising ELF feature; a later compatibility task must
still define the feature semantics, add controlled positive/negative fixtures,
and update the supported boundary before the claim changes.

## Boundaries and ownership

### Existing controlled matrix

`fixtures/manifest.json`, `scripts/validate-fixtures.py`, and
`scripts/run-fixture-matrix.sh` remain the source of truth for named feature
obligations, controlled producers, and runtime evidence. They continue to
prove exact contract cases and must not be overloaded with download
provenance or public-corpus policy.

### New real-sample layer

The new layer owns:

- a public candidate ledger and a frozen 20-project registry;
- source/archive/file hash verification;
- feature fingerprint collection from downloaded ELF files;
- per-sample execution policy and expected result classification;
- isolated baseline/pack/HostContext observations;
- per-sample evidence and aggregate coverage reports;
- CI workflow integration and future CI-first contributor rules.

The registry is metadata only. Sample binaries are downloaded into
`${RUNNER_TEMP}` and are never committed, copied into the repository, or
uploaded as raw evidence artifacts.

## Repository layout

```text
fixtures/real-samples/
├── candidates.json       # public candidate ledger and selection metadata
├── manifest.json         # exactly 20 selected project records
├── selection.md          # selection rationale and coverage report contract
└── README.md             # local/CI boundary and contributor workflow

scripts/
├── validate-real-samples.py       # metadata-only schema and policy validator
├── run-real-sample-matrix.sh     # CI-only acquisition/orchestration entrypoint
├── inspect-real-sample.py        # normalized ELF fingerprint helper
└── check-real-sample-evidence.py # post-run evidence gate

tests/
└── test_real_sample_manifest.py  # schema, uniqueness, policy, and tier tests

.artifacts/real-samples/<tier>/<sample-id>/
├── source.txt
├── hashes.txt
├── environment.txt
├── elf-fingerprint.json
├── readelf.txt
├── urprotect-report.json
├── baseline.*
├── packed.*
├── result.json
└── logs/
```

The candidate ledger may contain more than 20 public candidates. Only the
selected registry is used by required CI. The selected registry's `projectId`
values must be unique; runtime/build variants are nested under one project and
do not increase the corpus count.

## Registry contract

The selected manifest has a versioned schema with these logical sections:

```text
schemaVersion
corpus: {
  requiredProjectCount: 20,
  selectionPolicy,
  projects: [ ... ]
}
```

Each project record contains:

- `projectId` and display name;
- public provenance: source kind, URL, version/tag/commit, archive path,
  archive SHA-256, extracted ELF SHA-256, license and redistribution note;
- target facts: AArch64, OS, runtime/libc, interpreter, page size, and artifact
  kind;
- `variants`, when a single project has an explicitly useful glibc/musl/bionic
  or release-build comparison;
- observed/expected feature identifiers, with observed facts kept separate from
  claimed support identifiers;
- execution policy for static, baseline, outer-wrapper, and HostContext layers;
- bounded timeout, memory, process, output, and filesystem limits;
- expected result classification and evidence ownership.

The validator owns field names, URL/path restrictions, lowercase hash syntax,
unique project counting, supported status vocabulary, and the rule that every
execution policy has an explicit applicable/not-applicable result. It performs
no network access and accepts no sample path for execution.

## Candidate discovery and selection

Candidate discovery is a CI job, not a local binary workflow. It reads a
public candidate ledger, downloads candidate archives to a temporary directory,
verifies hashes, extracts only declared paths, and emits a normalized static
fingerprint. It does not execute candidate binaries during selection.

The fingerprint records at least:

- ELF class, data encoding, machine, type, and interpreter;
- program-header count and bounded `PT_LOAD` layout/alignment;
- dynamic tags and dependency names;
- RELA, RELR, PLT relocation, and symbol-version presence;
- PT_TLS, GNU property, GNU RELRO, GNU STACK, and section-header state;
- stripped/dynamic-symbol facts, file size, and build-id when present.

Selection is a covering problem over project identity and feature diversity,
not a popularity list or a libc multiplication scheme. `selection.md` records
why each selected project adds producer/runtime/feature coverage, which
candidate was rejected as a duplicate, and which boundary samples are
deliberately expected to reject. The final manifest must contain exactly 20
unique projects.

## CI data flow

```text
checked-in registry
  -> metadata/schema validation (no network)
  -> public download into RUNNER_TEMP
  -> archive + extracted-file hash verification
  -> pinned runtime/rootfs preparation
  -> static ELF fingerprint and UrProtect JSON report
  -> policy-selected isolated observations
  -> normalized result classification
  -> per-sample evidence gate
  -> aggregate report and artifact upload
```

The orchestrator must use `set -euo pipefail`, bounded download/extraction
limits, explicit cleanup traps, and a unique temporary root. It must reject
archive path traversal, unexpected extracted files where the policy requires
an exact path, hash mismatches, unsupported host architecture, and missing
runtime images. A required sample never degrades to a skip.

## Isolation model

The workflow runs on the existing `ubuntu-24.04-arm` native AArch64 runner
class with read-only repository checkout and `contents: read` permissions.
Network access is needed only for the acquisition phase. The target execution
phase uses a pinned ARM64 OCI/runtime image or equivalent fixed rootfs and:

- `network=none`;
- read-only rootfs plus a bounded temporary filesystem;
- dropped capabilities and `no-new-privileges`;
- bounded PID count, CPU, memory, output, and wall-clock time;
- no host workspace mount writable by the sample;
- explicit sample and dependency mounts with read-only permissions;
- cleanup after each sample and no raw sample upload.

Runtime images/rootfs inputs are identified by immutable digest and recorded in
the sample evidence. The policy may mark a layer `not-applicable` when the
artifact does not have the required contract, for example a normal program
without `urp_entry` for HostContext. Missing infrastructure for a required
applicable layer is `environment-unavailable` and fails the required job.

The implementation should reuse existing bionic/musl container conventions
where they fit, but must not silently execute a real sample on the host or
inherit an ambient host dependency search path.

## Layered oracle

Every sample first gets static evidence. Applicable dynamic layers then run in
this order:

1. original baseline;
2. no-op copy, where the product contract applies;
3. outer packed image, where the sample is an accepted outer-wrapper input;
4. HostContext load/lookup/entry/release, only where the image declares the
   required entry contract.

The baseline/packed comparison excludes ASLR addresses and timing, but checks
exit status, signal, stdout, stderr, current directory, declared environment
observations, and declared file observations. A positive loader result without
the required observation remains `runtime-failure`, `unknown`, or
`not-applicable` according to policy; it never becomes a support claim by
itself.

The result classifier uses a fixed vocabulary:

```text
accepted-and-runs
expected-rejected
unexpected-rejection
unexpected-acceptance
runtime-failure
environment-unavailable
not-applicable
```

The expected value is stored in the registry. The actual value is produced by
the runner. A mismatch fails the CI gate and remains visible in the aggregate
report.

## Evidence and report contract

Evidence is generated under `.artifacts/real-samples/<tier>/<sample-id>/` and
is checked after the producer step. It includes source/hash facts, runner and
runtime facts, normalized fingerprint, raw tool output, UrProtect JSON output,
oracle outputs, result classification, and a machine-readable `result.json`.
Raw downloaded binaries and full runtime rootfs contents are excluded from
upload. The evidence gate verifies that declared files are non-empty, remain
under the artifact root, have the expected schema, and match the registry
sample/tier.

The aggregate report includes:

- the 20 project list and selected variants;
- per-layer status counts;
- feature/producer/runtime coverage;
- first-seen and currently unsupported feature fingerprints;
- environment-unavailable records;
- unexpected outcomes with links to per-sample artifacts.

Real-sample results are evidence inputs to `COMPATIBILITY.md` and
`fixtures/manifest.json`; the report does not mutate either support claim
automatically.

## CI tier and merge policy

The same registry, orchestrator, policy, and oracle implementation is used by
all tiers:

- **PR:** required full run for all 20 projects, including static analysis and
  every policy-applicable isolated oracle. Any mismatch or missing evidence
  blocks the job.
- **Nightly:** reruns all 20 and may add stability repeats or approved runtime
  variants. It cannot replace PR coverage.
- **Release:** reruns the locked corpus and retains release-grade provenance,
  environment, per-sample, and aggregate evidence.

The workflow should add a dedicated real-sample job rather than fold sample
downloads into the existing controlled fixture job. This keeps sample
provenance, isolation, timeout, and artifact cleanup independently auditable.

## Future compatibility workflow

The durable backend runtime spec and the real-sample README must state that a
compatibility task includes a real-sample impact table. A support change needs
real observation, controlled positive and nearest-negative fixtures, stable
diagnostics, a layer-specific oracle, and updated evidence/docs. A rejection
change needs pre-handoff fail-closed evidence. Unexpected real-sample results
keep the task open until classified and resolved.

This process turns the real corpus into a discovery and regression layer while
preserving the existing rule that semantic support is contract-owned.

## Rollback and failure handling

- If a public URL, archive, package index, or runtime image changes, hash
  verification fails before execution; update the registry in a separate
  reviewed change rather than falling back to a moving latest URL.
- If isolation prerequisites are absent, fail the required job with an
  `environment-unavailable` artifact and a nonzero status.
- If a sample's project release disappears, retain its metadata and report the
  acquisition failure; do not replace it silently with a different version.
- If the corpus runner causes regressions in the existing fixture matrix, revert
  only the new workflow job/registry path; existing compatibility claims and
  controlled fixture jobs remain authoritative.
