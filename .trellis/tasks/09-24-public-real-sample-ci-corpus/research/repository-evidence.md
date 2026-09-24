# Repository evidence for public real-sample CI corpus

## Existing implementation surfaces

- `fixtures/manifest.json` is the existing feature/case matrix. Its schema
  couples feature status, witness/oracle/evidence paths, controlled producer
  cases, tier, runtime, and execution facts.
- `scripts/validate-fixtures.py` validates the existing manifest and emits
  selected cases. It has no public-download or real-sample provenance model.
- `scripts/run-fixture-matrix.sh` builds controlled samples from repository
  sources on native AArch64 and compares baseline/no-op-copy structure and
  streams. It is the pattern to reuse for observation shape, not the owner of
  the new public corpus.
- `scripts/check-evidence.py` validates declared source/generated evidence
  paths under the repository and `.artifacts`. The real-sample layer needs a
  registry-aware sibling or an explicit extension because its generated
  evidence has per-sample/tier result schemas.
- `.github/workflows/ci.yml` already has a required ARM64 build-and-test job,
  native bionic and musl container jobs, scheduled/release fixture tiers,
  environment recording, artifact uploads, and read-only contents permission.
- `.trellis/spec/backend/quality-guidelines.md` requires AArch64 native jobs,
  bounded/reproducible CI, retained environment facts, stable diagnostics, and
  separation of missing capabilities from successful coverage.
- `.trellis/spec/backend/runtime-compatibility.md` requires layered claims:
  parser/model, outer wrapper, HostContext, and runtime-specific evidence. It
  also states that loader acceptance alone does not prove HostContext support.

## Confirmed product decisions

- The corpus contains exactly 20 different upstream project identities.
- libc, distribution, and build variants are attributes or comparisons of one
  project, not extra sample count.
- Only public, hash-pinned, auditable sources are eligible.
- Real binaries stay in CI temporary storage; the repository stores metadata,
  selection rationale, and reports/contracts, not raw sample inputs.
- Real sample execution is isolated CI-only. Local commands are metadata-only
  for this layer.
- Every PR runs the full 20-project suite. Nightly and release reuse the same
  locked corpus and may add repeats or runtime coverage.
- Real observations discover gaps and lock regressions; explicit contracts and
  controlled fixtures still own support claims.

## Important design constraints

- A public download is external input. It needs archive path traversal checks,
  bounded extraction, archive and extracted-file hashes, and cleanup before a
  target is launched.
- A real program without `urp_entry` is not a HostContext test. Its result must
  be `not-applicable` for that layer, while parser/outer-wrapper observations
  remain independently classified.
- Missing runtime/rootfs or runner isolation is an environment result and must
  remain distinct from a product rejection or pass.
- Raw samples must not be uploaded as CI artifacts; evidence should retain
  enough normalized and raw textual/tool output to reproduce the classification
  without handing the binary to the local developer by default.
- The existing controlled fixture matrix and the new real-sample matrix need
  separate manifests and validators to keep feature ownership and provenance
  ownership clear.
