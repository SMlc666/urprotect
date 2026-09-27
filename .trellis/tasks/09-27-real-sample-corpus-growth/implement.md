# Implementation plan: public corpus growth to 100

## Dependencies

- Depends on the existing architecture/evidence owners and real-sample schema
  v2 pipeline; no product compatibility feature is added.
- Must be completed before final compatibility-release integration so the
  release matrix/report reflects the approved target and current aggregate.
- Keep `fixtures/real-samples/` metadata-only; actual package/ELF bytes remain
  under temporary CI paths.

## Ordered checklist

- [x] Review all 23 deferred candidate records against current provenance,
      package identity, source license, artifact location, and runtime facts;
      promote only records that pass.
- [x] Retrieve Debian Bookworm ARM64 and Alpine 3.22.2 ARM64 package indexes
      into temporary research storage; lock 37 new Debian package URLs and 20
      new Alpine APK URLs with exact versions, SHA-256, and license metadata.
- [x] Select 80 distinct additional upstream projects, including at least 20
      musl/APK projects, and verify non-duplication against project IDs,
      identity keys, upstream projects, and existing candidate records.
- [x] Download candidate packages to `/tmp`, verify hashes, bounded-extract,
      identify each actual AArch64 ELF executable, record its path/loader/type,
      inspect license notices, and run `dotnet validate --no-analysis` as a
      local preflight; never add raw package or ELF files to Git.
- [x] Extend `scripts/extract-real-sample.py` to safely treat the declared
      `apk` format as the already bounded tar archive format; add positive and
      nearest-traversal/special-file extraction tests and check actual locked
      `.PKGINFO` package/version/architecture/origin/license values.
- [x] Update candidate dispositions and manifest selected records with exact
      provenance, target runtime/loader, executable path, static expectation,
      selection rationale, tiers, acquisition bounds, and all layer policies.
- [x] Set the approved selected count to 100, regenerate registry-only
      aggregate files, revise `selection.md`, `README.md`, and
      `.trellis/spec/backend/runtime-compatibility.md` to report the actual
      count and diversity without support overclaim.
- [x] Recompute distinct-identity baseline feature counts and update
      `feature-dispositions.json` for every observed frequency at/above 5%.
- [x] Update validators, unit tests, output assertions, PR summary, regression
      budgets, and evidence expectations that currently assume 20 projects;
      preserve fixed result vocabulary, four-layer results, hash checks, raw
      input cleanup, and complete-100-set CI selection.
- [x] Run native AArch64 PR CI. Fix acquisition, archive, license, path,
      extraction, parser, or evidence failures from their retained logs; do not
      waive rows or convert failures to unavailable/success.
- [x] Verify all 100 sample evidence directories, aggregate counts, feature
      histograms, source/artifact hashes, cleanup markers, and sanitized
      artifacts; follow with nightly/release CI for the current registry.

## Validation commands

```sh
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_fingerprint.py
python3 tests/test_real_sample_aggregate.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_real_sample_security.py
python3 scripts/render-real-sample-report.py \
  fixtures/real-samples/manifest.json --tier pr --registry-only \
  --artifact-root fixtures/real-samples \
  --output-json fixtures/real-samples/baseline-aggregate.json \
  --output-markdown fixtures/real-samples/baseline-aggregate.md
python3 scripts/run-real-sample-matrix.sh --help
```

The actual `run-real-sample-matrix.sh --tier pr` acquisition and its evidence
gate run only in required native AArch64 GitHub CI. Validate the retained CI
artifact after completion with `scripts/check-real-sample-evidence.py` and
verify that no raw archive, ELF, package root, or binary-like file was
uploaded.

## Rollback point

If any part of the 80-identity increment fails provenance, identity, local ELF
inspection, or the complete CI evidence gate, remove the entire unproven
increment from selected manifest records, leave entries deferred with exact
reasons, regenerate the metadata baseline, and keep the parent target/shortfall
truthful. Do not archive this child until the selected count is 100 and PR,
nightly, and release evidence is complete.
