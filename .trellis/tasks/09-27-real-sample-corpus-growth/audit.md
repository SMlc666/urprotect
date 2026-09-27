# Public real-sample corpus growth audit

## Result

The approved public AArch64 registry now contains exactly 100 distinct
upstream identities: 78 glibc package identities, 21 musl identities (20
Alpine APKs plus the retained BusyBox rootfs), and one bionic/Termux identity.
The registry target is 100 with a zero shortfall. The selected set keeps
package, distribution, version, libc, and build variants as attributes rather
than additional identities.

Every selected record has a locked archive URL/path, SHA-256, archive size,
bounded extraction limits and verification facts, executable artifact path,
target architecture/runtime/loader, license, license source, and explicit
four-layer execution policy. The 80-identity increment consists of the 23
reviewed deferred records, 37 Debian Bookworm AArch64 package records, and 20
Alpine 3.22 AArch64 APK records.

## CI evidence

| Tier | GitHub Actions run | Commit | Result |
|---|---:|---|---|
| PR | `36303770796` | `eb65e8569113cda5a11590434bfdd562d87f9e74` | full 100-identity real-sample matrix and all PR checks passed |
| Nightly rehearsal | `36303781357` | `194dae011939386c3ed4b116f0cd1804dc4f5396` | full 100-identity matrix, fixture-nightly, runtime matrix, bionic, musl, fuzz/stress, and evidence checks passed |
| Release rehearsal | `36304139025` | `194dae011939386c3ed4b116f0cd1804dc4f5396` | full 100-identity matrix, release fixture evidence, runtime matrix, bionic, musl, and release package smoke passed |

The retained real-sample artifact bundles were downloaded from all three
runs and independently checked with:

```text
python3 scripts/check-real-sample-evidence.py fixtures/real-samples/manifest.json --tier pr --artifact-root .../pr
python3 scripts/check-real-sample-evidence.py fixtures/real-samples/manifest.json --tier nightly --artifact-root .../nightly
python3 scripts/check-real-sample-evidence.py fixtures/real-samples/manifest.json --tier release --artifact-root .../release
```

Each tier contains 100 project directories, each with a result, normalized
fingerprint, bounded readelf record, source/provenance record, archive and
artifact hashes, and `raw-inputs-removed=true`. Each aggregate reports
`identityCount=100`, `approvedTargetProjectCount=100`, and `shortfall=0`.
The release artifact independently matched every manifest artifact path and
archive hash, verified every AArch64 ELF identity, matched result and
fingerprint artifact hashes, and recorded `accepted-and-runs` for all 100
static layers.

## Local checks

- `python3 scripts/validate-real-samples.py ... --tier pr` — 100 unique
  projects; glibc, musl, and bionic runtime classes validated.
- The same registry validator passed for `nightly` and `release`.
- `scripts/check-real-sample-evidence.py` passed for all three downloaded
  CI tiers and checked all 100 projects plus all four layers in each tier.
- The focused real-sample manifest, fingerprint, aggregate, evidence, and
  security suites passed in the producing CI jobs.
- The complete selected set retained no raw archive, ELF, package root, or
  extracted runtime input under the uploaded artifact roots.

## Claim limits

The corpus is ecology and parser/static-validation evidence. Ordinary public
samples without `urp_entry` remain HostContext `not-applicable`, and package
observations do not promote outer, HostContext, TLS, or runtime claims. The
release package job performed bundle smoke and retained evidence; GitHub
release asset publication remains intentionally skipped by the rehearsal
workflow because this run is not a publishing tag.
