# Design: 100-identity public AArch64 ecology

## Boundary and owners

- `fixtures/real-samples/manifest.json` owns exactly the approved selected set,
  tier selection, archive/artifact provenance, expected facts, and layer policy.
- `fixtures/real-samples/candidates.json` owns the disposition ledger for
  selected, deferred, and rejected public projects, including identity and
  selection rationale.
- `scripts/validate-real-samples.py` is the metadata-only schema and
  cross-ledger owner. It proves uniqueness, tier consistency, provenance
  equality, target count, and candidate disposition before acquisition.
- `scripts/run-real-sample-matrix.sh` owns CI-only download/hash/extract,
  artifact resolution, static inspection, and per-layer results.
- `scripts/extract-real-sample.py` owns bounded archive extraction and
  traversal/special-file/symlink defenses for the selected archive formats.
- `scripts/inspect-real-sample.py`,
  `scripts/compare-real-sample-fingerprint.py`, and
  `scripts/render-real-sample-report.py` own normalized observations,
  locked invariant comparison, and distinct-identity aggregates.
- `scripts/check-real-sample-evidence.py` owns complete evidence coverage,
  result classification, cleanup markers, and raw-file exclusion.
- `fixtures/real-samples/feature-dispositions.json` owns explicit dispositions
  for observed features at/above the 5% distinct-identity trigger.

## Source plan and selection

Promote the 23 previously deferred candidates only after checking their exact
package metadata, then add 57 distinct upstream identities to reach the exact
80-project increment. The planned source mix is a fixed-size increment:

- The 23 existing `deferred` candidates, individually re-reviewed and
  promoted only when their current source and archive facts remain valid.
- 37 additional Debian Bookworm AArch64 project artifacts for glibc-native
  utilities/applications. Lock package filename/version and package SHA-256
  from the public Debian ARM64 package index, then verify artifact bytes
  locally and in CI.
- 20 additional Alpine 3.22.2 AArch64 APK projects for musl runtime coverage.
  Exclude every existing selected/deferred/rejected upstream identity. Resolve
  package version, origin/homepage/license fields and archive metadata from
  the versioned aarch64 repository index, compute and lock each APK SHA-256,
  then select a concrete executable path from a local extraction.

The count is `23 + 37 + 20 = 80` additions. If an item fails an eligibility
gate, replace it with another distinct project from the same source/runtime
class so the final selected count and minimum 20 APK/musl additions are met.
- Retain existing bionic/Termux and BusyBox/musl projects as runtime witnesses;
  do not add unreliable mirror variants solely to increase the count.

Every package contributes one upstream identity, regardless of package path
or variants. Reject/defer candidates when they duplicate an existing upstream
identity, have unreviewable provenance/license, exceed archive/extraction
bounds, lack an AArch64 ELF executable, or do not satisfy the declared static
result policy. An unavailable repository or failed checksum remains a failed
required CI result; it is not relabeled as an unsupported product image.

## Data flow

```text
review public catalog + package metadata
  -> candidate ledger disposition and exact archive lock
  -> manifest selected entry + local executable/path verification
  -> metadata validation and registry-only aggregate tests
  -> native ARM64 CI download + SHA-256 verification
  -> bounded extraction in RUNNER_TEMP + declared-artifact resolution
  -> readelf fingerprint + managed CLI validate + per-layer results
  -> cleanup marker + raw artifact removal
  -> 100-project aggregate + complete evidence gate + sanitized upload
```

The source manifests must remain metadata-only. The on-runner artifact and
fingerprint evidence contains no archive bytes, ELF bytes, package rootfs, or
raw-input paths after sanitization. The current system has a 90-minute
real-sample job budget; use the locked, extracted single-ELF artifacts and
avoid launching baseline commands except for already reviewed rootfs policies.

## Schema and aggregate changes

Keep schema version 2 for fingerprints/results/aggregate. Change the manifest's
`requiredProjectCount` to 100 and keep `targetProjectCount`/`approvedTarget`
100. Compute registry size and shortfall from the distinct identity set; do
not preserve hardcoded 20 in validators/tests/report output. Update tests to
assert the selected count from the approved target and to reject duplicate
identity keys/project IDs at scale.

Update `baseline-aggregate.json` and Markdown as explicitly labelled
registry-metadata output. It is not CI observation evidence. The CI aggregate
must show `identityCount=100`, correct feature denominators/percentages, all
four layer results for each identity, first-failure summaries, and disposition
coverage for each feature at or above 5%.

Alpine v3.22 APK archives are gzip-compressed tar files containing `.SIGN.*`,
`.PKGINFO`, and payload paths directly at the archive root; inspection of all
20 locked APKs confirms they do not contain a nested `data.tar.gz`. The public
extractor already routes this direct representation through the same bounded
tar safety checks used for gzip tar archives. Extend it to require and check
`.PKGINFO` against the locked package name, version, architecture, origin, and
license; all extracted metadata/payload stays in the runner temporary root.

## Compatibility and rollout

- Preserve all existing 20 records byte-for-byte except a reviewed
  documentation/count update; retain every existing candidate disposition
  unless a specific candidate is promoted.
- `expectedFeatureTags` are prioritization annotations, not measured ELF
  facts. The actual tags/facts continue to come from CI `readelf` and managed
  validation outputs.
- Do not change parser/packer/runtime acceptance as part of corpus ingestion.
- Every CI tier runs the entire selected set. No dynamic matrix slicing or
  “changed-only” project selection is allowed.
- If the final artifact set cannot finish inside the 90-minute bound, reduce
  per-artifact size selection before changing any claimed identity count;
  acceptance remains 100 selected and fully evidenced.

## Rollback

Revert the entire 80-identity increment as one registry change if local
provenance, static validation, CI isolation, or complete evidence gates fail.
Retain the 20-identity baseline and the candidate ledger reasons for deferred
entries; never keep an unverified selected row as a metadata-only success.
