# Implementation plan: architecture and quality foundation

## Rules

- Keep this child behavior-preserving and support-claim-neutral.
- Start with baseline evidence before code changes.
- Use one active migration boundary at a time.
- No source-wide rewrite, generic framework, line-count-only extraction, or
  duplicate production implementation.
- Each refactor includes preserved behavior, owner boundary, migration order,
  rollback point, validation, and performance comparison when relevant.

## Ordered checklist

### A. Capture baseline and flow maps

- [ ] Record git baseline and local tool availability (dotnet, native compiler,
      musl tools, Docker, Python, readelf, page size).
- [ ] Run the managed solution tests on the required SDK host.
- [ ] Run native runtime `contract-check` and `test` on native AArch64.
- [ ] Run launcher self-test and full launcher integration where dotnet/musl
      prerequisites are present.
- [ ] Run regression/fixture/real-sample metadata validation and Python tests.
- [ ] Run PR fuzz/stress smoke where toolchain prerequisites allow.
- [ ] Capture current frame/layout probe, representative golden reports,
      diagnostic assertions, launcher process observations, and parser/codec
      benchmark output.
- [ ] Draw and document the four principal data flows listed in `design.md`.

### B. Build architecture inventory

- [ ] Inventory all contract literals: frame versions/offsets, HostContext
      sizes/capabilities, ELF dynamic tags/relocations, diagnostic codes,
      profile markers, result strings, manifest IDs, evidence path rules.
- [ ] Map producer/consumer/test/spec/CI ownership for each contract.
- [ ] Search for duplicate checked arithmetic, address translation, dynamic
      tag decoding, schema validation, and evidence path logic.
- [ ] Review monolithic files for concrete mixed responsibility, coupling,
      duplicated owner, or testability failure; file length alone is not a
      finding.
- [ ] Prioritize refactors by correctness risk, feature-growth impact,
      cross-language drift risk, and available characterization coverage.

### C. Protect contracts with characterization tests

- [ ] Add focused coverage for any changed behavior not currently protected in
      parser malformed/property tests, golden report tests, CLI tests, payload
      frame tests, pack tests, native self-tests, and evidence validator tests.
- [ ] Pin diagnostic codes/order and machine-readable fields; assert messages
      only where user-facing stability requires them.
- [ ] Record frame bytes/layout, native probe output, identity/publication
      guarantees, and process-level wrapper observations.
- [ ] Establish before/after performance measurements for parser/frame paths
      selected for refactoring.

### D. Refactor the first owner boundary

- [ ] Select the first hotspot based on audit findings; document a short ADR in
      the task artifacts or a durable spec if it changes architecture rules.
- [ ] Extract only one responsibility while retaining public facade and output.
- [ ] Migrate all consumers; remove duplicate active code after parity passes.
- [ ] Run focused, owning full, contract, and relevant fuzz/stress tests.
- [ ] Compare benchmark and allocation results; explain any material change.
- [ ] Update directory, quality, error-handling, and runtime specs where rules
      changed.

### E. Handoff readiness

- [ ] Produce architecture/data-flow map and contract owner inventory.
- [ ] List each remaining hotspot with evidence, proposed owner, containment
      rule, dependencies, and which child should own its refactor.
- [ ] Confirm compatibility manifests and claims are unchanged.
- [ ] Provide a parent handoff checklist before any broad compatibility child
      starts implementation.

## Validation commands

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
make -C native/urprotect-launcher test
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_fingerprint.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_real_sample_security.py
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
./scripts/run-coverage-fuzz.sh --tier pr
./scripts/run-regression-stress.sh --tier pr
```

Only commands relevant to the changed boundary may be scoped during iterative
development; the final child check records all required gates and any genuine
environment prerequisite separately.

## Rollback points

1. **Characterization-only:** keep tests even if the extraction design changes.
2. **One-boundary extraction:** revert only the extracted owner and consumer
   migration; retain tests/audit.
3. **Contract-owner tooling:** revert generator/shared schema if it creates a
   second source of truth; retain existing C# constants, C headers, layout test,
   literal inventory, and probe.
4. **Final child:** do not update compatibility claims as part of this
   behavior-neutral foundation.
