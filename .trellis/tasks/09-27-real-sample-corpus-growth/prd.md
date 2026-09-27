# Grow the public AArch64 sample corpus to 100 identities

## Goal

Complete parent requirement R2 by expanding the locked public CI-only corpus
from 20 to 100 distinct upstream project identities. Add exactly 80 approved
identities through a reviewed, hash-locked increment while preserving the
sample-layer/result taxonomy and isolation guarantees.

## Background and constraints

- The current manifest has 20 approved identities and an approved target of
  100; `selection.md` records a shortfall of 80.
- `candidates.json` contains 23 deferred candidates and 3 rejected candidates
  in addition to the 20 selected identities. Deferred candidates require
  review and may be promoted only when archive, artifact, license, identity,
  architecture, and runtime facts remain correct.
- A package, archive, build, libc, or distribution variant is never another
  project identity. `identityKey` represents the upstream project.
- Real samples are acquired only by native ARM64 GitHub Actions. Archives,
  ELF files, extracted package roots, and raw command output containing raw
  bytes remain runner-temporary and are not uploaded.
- A real-sample observation does not promote product support. The task updates
  static ecology evidence, aggregate frequency, and feature dispositions only.
- Each CI tier executes the full selected 100-project registry using the same
  orchestrator and result semantics.

## Requirements

- Approve 80 additional upstream identities, resulting in exactly 100 selected
  identities and retaining the approved target of 100.
- Preserve cross-ecosystem and runtime diversity. The increment must add at
  least 20 independently sourced musl/AArch64 projects using pinned Alpine
  package artifacts, while retaining the existing glibc, bionic, Go, Rust,
  C/C++, BusyBox/musl, server, tool, and language-runtime observations.
- Lock an immutable public archive URL, version, relative archive path,
  SHA-256, executable artifact path, architecture/runtime/loader, license and
  license-source facts, expected static result, selection rationale, and
  explicit layer policies for every promoted identity.
- Do not promote a package unless local package inspection confirms that its
  declared executable exists, resolves only within the extracted archive,
  is an AArch64 ELF fitting the bounded archive limit, and passes the managed
  static validator or has an explicit nearest-boundary expectation.
- Recompute the metadata-only aggregate, CI aggregate expectations, and
  feature dispositions over distinct identities. Every CI-observed feature at
  or above 5% receives an explicit roadmap disposition.
- Keep every applicable baseline, outer, and HostContext layer explicit. A
  layer without a reviewed runtime closure/ABI oracle remains
  `not-applicable`; it must not be silently skipped or inferred from loader
  acceptance.
- Preserve cleanup markers, bounded extraction, networkless execution, raw
  input non-publication, complete evidence gates, and deterministic aggregate
  reporting for PR, nightly, and release.

## Acceptance criteria

- [x] `manifest.json` contains exactly 100 unique selected `identityKey`
      values, and `candidates.json` marks each as selected with matching
      locked provenance; no variant inflates identity count.
- [x] The 80 new identities include at least 20 reviewed Alpine/musl
      artifacts and maintain a documented producer/runtime/ecosystem mix.
- [ ] All 100 package artifacts have locked SHA-256, license/source metadata,
      bounded extraction facts, and an existing executable AArch64 artifact
      path verified locally and by CI.
- [x] Metadata validators, fingerprint/aggregate/security tests, and registry
      consistency tests pass at the 100-identity count.
- [x] Native AArch64 PR CI acquires and validates all 100 artifacts, produces
      all-layer results plus fingerprints/readelf/provenance, deletes raw
      inputs, and retains complete evidence; nightly/release use the same
      registry and complete-set semantics.
- [x] CI aggregate identity count is 100, first-failure classification is
      complete, and every feature above the 5% distinct-identity threshold has
      a disposition.
- [x] Existing parser, outer, HostContext, bionic, TLS, and runtime-matrix
      claims are unchanged except where their dedicated controlled evidence
      independently supports a change.

## Out of scope

- Adding ELF feature acceptance based only on real-sample frequency.
- Counting build, version, package, libc, or runtime variants as additional
  project identities.
- Uploading raw sample archives, executable files, or extracted runtime
  roots.
- Increasing the product architecture scope or claiming universal support for
  all sample runtime variants.
