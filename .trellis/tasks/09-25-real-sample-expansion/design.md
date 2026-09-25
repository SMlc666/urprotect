# Design: real-sample expansion and failure taxonomy

## Objective

Grow the public AArch64 sample ecology toward 100 distinct identities and turn
CI observations into a bounded, reviewable compatibility-prioritization data
set without moving raw executables into the repository.

## Data flow

```text
registry/candidate ledger
  -> CI acquisition and archive hash verification
  -> safe extraction and extracted-file hash verification
  -> bounded readelf/UrProtect inspection
  -> normalized fingerprint
  -> policy-selected baseline/outer/HostContext oracle
  -> normalized per-sample result
  -> evidence postcondition
  -> feature histogram + first-failure aggregate
```

Local commands remain metadata-only. CI-only scripts own network acquisition,
isolation, cleanup, raw-input handling, and execution. Shared schemas should be
factored only after the architecture foundation identifies repeated ownership;
the existing registry and result vocabulary remain the compatibility boundary.

## Registry model

Preserve the distinction among:

- `projectId` / upstream identity;
- artifact/build/runtime variant;
- target ELF and loader facts;
- feature fingerprint observations;
- layer policy and expected result;
- actual result and evidence.

One project may have glibc, musl, bionic, or distribution variants, but those
variants are grouped under the project identity for the 100-project target and
feature frequency. Each selected artifact remains independently hash-locked.

## Fingerprint schema

The normalized fingerprint extends current fields with bounded, tool-derived
observations:

- ELF identity, interpreter, PT_LOAD layout/congruence, sectionless/stripped,
  page-size facts, and producer/toolchain;
- dynamic tags and `DT_NEEDED` graph, including path-search tags;
- relocation family/count/type/symbol-index summaries for RELA/RELR/PLT and
  Android packed forms;
- dynamic symbol binding/visibility/version summaries;
- PT_TLS/model/relocation facts;
- GNU property, RELRO, GNU_STACK, and other selected hardening facts;
- source/runtime/loader metadata and a schema version.

The inspector never infers support from a fingerprint. Missing or unsupported
tool output is represented as bounded `unknown` with a reason. Reports exclude
raw input bytes and sensitive temporary paths.

## Failure taxonomy

Normalize the first blocking result into a layer:

```text
acquisition
fingerprint
parse-model
static-validation
outer
host-context
environment
```

Retain the existing public outcome vocabulary and add structured fields rather
than parsing free-form log text. A sample can be `not-applicable` at one layer
and `accepted-and-runs` at another. An environment-unavailable result never
becomes product rejection or success.

## Frequency report

Aggregate by distinct `projectId`, not variants. For each observed feature:

- identity count and percentage;
- project IDs and variants;
- producer/runtime distribution;
- first failing layer and diagnostic distribution;
- current matrix status;
- positive/negative fixture and oracle availability;
- roadmap disposition (`support-candidate`, `rejected`, `deferred`).

The 5% trigger opens explicit prioritization review. Product-critical features
below the trigger can be selected with a recorded rationale. The report is a
planning/evidence aid, not a support claim.

## Growth stages

1. Extend fingerprint and aggregate current 20 to establish baseline.
2. Add high-diversity increments with provenance review, aiming for 60.
3. Add the remaining reviewed increments toward 100 while preserving runtime,
   producer, dependency, hardening, TLS, and negative-boundary diversity.
4. Re-run the histogram after every increment; feature children consume a
   versioned aggregate rather than a manually copied list.

## Compatibility and rollback

Keep the previous locked corpus usable while an increment is reviewed. If a
new source becomes unavailable, hash-different, unsafe to extract, or unstable,
remove or quarantine only that candidate with a reason; do not weaken the
registry gate. If aggregate schema changes, version it and retain a migration
or a clearly bounded previous report.
