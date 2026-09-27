# Audit: 100-identity public AArch64 sample corpus

## Registry and identity counts

- Selected registry: **100** distinct project IDs and **100** distinct
  `identityKey` values; required and target counts are both 100.
- Candidate ledger: **103** records, comprising 100 selected and 3 rejected.
- Increment: **80** identities, exactly 23 promoted deferred Debian records,
  37 additional Debian Bookworm ARM64 records, and 20 Alpine v3.22 AArch64 APK
  records.
- Runtime mix: **78 glibc / 21 musl / 1 bionic**. Archive mix: 79 `.deb`, 20
  `.apk`, and one existing Alpine BusyBox `tar.gz` rootfs.
- The distinct-identity aggregate baseline now reports 100/100 with shortfall
  zero. Feature dispositions contain 55 reviewed feature clusters; the local
  evidence gate verifies every feature at/above its 5% identity threshold has
  a disposition.

## Locked package evidence and local preflight

Research indexes and package/ELF bytes live only under `/tmp` and are not
tracked. The Debian Bookworm ARM64 `Packages.xz` index hash is
`2ddb1737692e8c45c53e8d57c0ce4cd21c78c5703b830c3226b1423566a06c00`; the
Alpine v3.22 main/aarch64 APK index hash is
`1f7a5be0ef6c857f2aa1013f2be0b678d2c5dd2ad3a4eee5760a184be58bbe20`.

Independent local checks performed in this working session:

- Verified all **100/100** downloaded local archive SHA-256 values against
  the selected registry; `archiveSizeBytes` and
  `boundedExtraction.localArchiveBytes` match on every record, and every
  archive is within the 64 MiB limit.
- Checked all **60/60** new/pinned Debian package-control records for package
  name, version, and `arm64` architecture with `dpkg-deb`.
- Checked all **20/20** APK `.PKGINFO` files for package name/version,
  `aarch64`, origin, and license. All have `.SIGN.*`, `.PKGINFO`, and direct
  payload members; none contains a nested `data.tar.gz`.
- Ran the current bounded extractor against all **20/20** actual APKs; package
  metadata matched the candidate lock, declared artifacts resolved inside the
  extracted roots, and executable mode was present.
- Ran a complete local static preflight over **100/100** inputs: locked
  archive hash, bounded extraction, artifact/symlink resolution, `readelf`
  inspection, fingerprint invariant comparison, and managed CLI
  `validate --no-analysis` all passed.
- All 100 manifest/candidate records now carry exact archive size and matching
  bounded-extraction witnesses under the shared 100,000-member/2 GiB/64 MiB
  limits. The local sanitized 100-project evidence root at
  `/tmp/real-sample-corpus/full-evidence` has all four layer results and cleanup
  markers; `check-real-sample-evidence.py` passed for 100 project directories.
  This is local verification, not GitHub Actions release evidence.

## Implemented contract changes

- `scripts/real_sample_schema.py` owns shared archive-byte, member-count,
  expanded-size, and APK metadata bounds consumed by the extractor/validator.
- `scripts/extract-real-sample.py` safely extracts Alpine APK direct tar
  members, validates `.PKGINFO` against locked package/version/architecture/
  origin/license metadata, and retains path/link/special-file/size limits.
- `scripts/run-real-sample-matrix.sh` passes those selected metadata locks to
  the extractor and gets the byte cap from the shared schema owner.
- `scripts/validate-real-samples.py` validates all selected CI-only acquisition
  limits, required detailed extraction witnesses, all manifest/candidate
  provenance fields, source-index digests, source/runtime mix, and the reviewed
  23+37+20 increment.
- The baseline aggregate, feature dispositions, selection report, README, and
  runtime/quality specs describe 100 identities without upgrading any ELF,
  outer, HostContext, or runtime support claim.

## Local tests

- Real-sample unit/integration suite: **35 passed**.
- Managed solution suite: **140 passed**.
- Fixture matrix: **24 passed**; regression matrix: **5 passed**.
- Registry validator passed for `pr`, `nightly`, and `release` with network
  unused.
- Deterministic registry-baseline JSON/Markdown regeneration matched the
  checked-in files exactly.
- Local full-set evidence check: `checked 100 projects and all layers`.
- APK metadata/extraction/artifact checks: 20/20; all 100 archive digests and
  static validation preflights passed.
- Fixture manifest, runtime-matrix registry, shell syntax, Python compilation,
  and `git diff --check` passed.

## CI status / remaining gate

The latest successful PR/push runs before this change, `36293074081` and
`36293071468`, used commit `370080c6f2dbbb97b0bd5db3a080c64d2a76791f` and
therefore tested the old 20-project registry. They do not count as proof for
this 100-project revision. A fresh native AArch64 PR run must acquire all 100
archives, validate the real APK format and exact hashes, retain every project
and all layers, sanitize/remove all raw inputs, and pass the complete evidence
gate. Nightly and release must then pass the same full registry and verify
release claims/aggregate counts. Keep this task and its acceptance criteria
open until these updated-run artifacts are inspected and checked.
