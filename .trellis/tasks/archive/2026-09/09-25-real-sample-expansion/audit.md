# Real-sample expansion audit

## Scope

This child establishes the schema, registry validation, bounded fingerprint
inspection, aggregate report, first-failure taxonomy, and CI evidence gate for
the approved public AArch64 real-sample slice. The registry remains at 20
approved identities while its reviewed expansion target is 100; variants are
never counted as additional identities.

## Evidence

- Local registry, fingerprint, evidence, security, aggregate, syntax, and
  deterministic-baseline checks pass.
- GitHub Actions PR run `36097042633` passed the native ARM64 real-sample
  matrix and its post-run evidence gate for commit
  `f707a1247643b6fb84c31100224dde5225b8c817`.
- Artifact `real-samples-pr-36097042633` retains 20 schema-2 project records,
  the aggregate, runner environment, and cleanup markers. Its aggregate has
  `identityCount=20`, target `100`, shortfall `80`, zero unexpected outcomes,
  and all 36 observed features carry reviewed dispositions.
- Downloaded PR evidence was checked for raw archive/ELF/shared-object files
  and temporary-runner path leakage; none was found.

## Contracts verified

- `identityKey` uniqueness and selected-candidate provenance equality are
  enforced by the metadata validator.
- Fingerprint and result artifacts use bounded schema 2 fields, canonical ELF
  identity names, explicit unknown fields, and the shared result vocabulary.
- Aggregate feature frequency is computed over distinct identities and records
  project IDs, identity keys, variants, producer/runtime coverage, page sizes,
  diagnostics, result classifications, first-failure layers, and dispositions.
- The post-run gate checks schema, all four layers, coverage target/shortfall,
  threshold dispositions, cleanup markers, text-only evidence, and project
  identity coverage.

## Residual roadmap

The approved corpus is intentionally not promoted from 20 to 100 in this
child. The candidate ledger retains 26 reviewed rejected/deferred public
identities with provenance, hashes, license/reuse facts, extracted paths, and
selection reasons. Future increments must repeat native fingerprint/evidence
review and preserve runtime/producer diversity before selection.
