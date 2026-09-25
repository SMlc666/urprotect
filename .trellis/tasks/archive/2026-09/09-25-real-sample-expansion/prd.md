# Expand real AArch64 sample corpus and failure taxonomy

## Goal

Grow the public CI-only AArch64 corpus from 20 toward 100 distinct upstream
project identities and turn its observations into a reliable feature-frequency
and first-failure taxonomy that drives compatibility priorities.

## Dependencies and constraints

- Depends on the architecture foundation’s evidence owners and characterization
  results, but may design registry work in parallel.
- The registry counts distinct upstream identities; libc, distribution, and
  build variants are attributes, not additional projects.
- Raw archives, ELF files, and runtime roots remain runner-temporary and are
  never committed or uploaded.
- The approved 5% trigger is computed over distinct identities. It requires an
  explicit roadmap disposition, not automatic feature acceptance.

## Requirements

- Extend normalized fingerprints for relocations/PLT/GOT, dependencies,
  symbol versions, TLS, GNU properties, hardening, stripping, page size,
  producer, loader, runtime, and first failing layer.
- Add bounded aggregate reports by feature, project, producer, runtime, layer,
  diagnostic, and result classification.
- Add public candidates and approved corpus increments with provenance, exact
  hashes, license/reuse facts, selection rationale, and expected layer results.
- Reuse one result vocabulary and one evidence validator across PR/nightly/
  release tiers.
- Preserve CI-only acquisition, network restrictions, isolation, cleanup,
  hash verification, and explicit environment-unavailable behavior.

## Acceptance Criteria

- [ ] Registry validation proves unique project identity and corpus metadata
      correctness for each approved increment.
- [ ] Corpus has a documented path toward 100 identities with reviewed
      diversity and no duplicate-variant inflation.
- [ ] Fingerprint output exposes the feature fields needed for prioritization,
      with bounded unknown handling and stable schema.
- [ ] Aggregate report computes distinct-identity frequencies and first-failure
      layers, and every feature at or above 5% has a recorded disposition.
- [ ] Metadata tests pass locally; CI execution remains isolated, hash-locked,
      evidence-gated, and raw-input-free.
