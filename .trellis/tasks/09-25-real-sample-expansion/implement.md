# Implementation plan: real-sample expansion and failure taxonomy

## Dependencies

- Architecture foundation owner inventory and shared evidence decisions are
  required before changing common validators.
- Existing 20-project registry and CI runner remain the rollback baseline.
- Feature implementation children consume this child’s aggregate output; they
  do not manually infer prevalence from individual logs.

## Checklist

- [ ] Baseline current registry, candidate ledger, fingerprint, evidence, and
      result schemas.
- [ ] Capture current 20-project aggregate and identify missing fingerprint
      fields.
- [ ] Extend bounded inspection and normalized schema for relocation/PLT/GOT,
      dependency graph/path tags, symbol versions, TLS, GNU properties,
      hardening, producer, loader, and page size.
- [ ] Add schema and security tests for missing/unknown/oversized fields.
- [ ] Add shared first-failure/result normalization without duplicating runner
      policy logic.
- [ ] Add feature-frequency aggregation over distinct project identities.
- [ ] Add report fixtures/golden output and stable schema versioning.
- [ ] Review and add public candidates in increments; preserve licenses,
      archive/extracted hashes, internal paths, and selection rationale.
- [ ] Run metadata validation after each increment.
- [ ] Run CI-only sample execution on native ARM64 and verify evidence gates.
- [ ] Publish the histogram/disposition artifact for the next feature children.

## Validation

```sh
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_fingerprint.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_real_sample_security.py
python3 scripts/check-real-sample-evidence.py \
  fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json \
  --tier pr
```

On the native CI runner:

```sh
./scripts/run-real-sample-matrix.sh --tier pr
python3 scripts/check-real-sample-evidence.py \
  fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json \
  --tier pr \
  --artifact-root .artifacts/real-samples/pr
```

The exact evidence command and generated artifact paths must be recorded after
the runner changes; local environments never substitute for the CI oracle.

## Quality and rollback gates

- No raw archive, ELF, shared object, or rootfs enters git or uploaded evidence.
- No result is silently omitted because a layer is unavailable or inapplicable.
- No feature support row changes in this child.
- New schema fields are consumed by all report/evidence readers before merge.
- A bad candidate increment rolls back to the last locked registry; aggregate
  reports retain the previous schema/version and selection reason.
