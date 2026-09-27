# Compatibility and release integration audit

## Result

The final integration preserves one source of truth for feature status and
evidence: `fixtures/manifest.json` contains 38 unique feature rows with 25
`validated`, 7 `proven`, and 6 `rejected` rows; the real-sample registry
contains 100 distinct identities with a zero shortfall. Feature references in
the fixture cases resolve to declared rows, and the outer, HostContext,
parser/model, and runtime-specific claims remain separate.

Current frame/profile terminology is explicit: frame v3 is the production
contract, `outer-execveat` and `host-context-entry` are selected profiles, and
v1/v2 plus Wrapper 0.2 are migration evidence only. The native runtime and
launcher retain separate owners for preflight, sealed-image loading, symbol
lookup, release, and ABI drift checks. Rejected path-search, text-relocation,
unsupported-relocation-table, Android packed-relocation, version-definition,
dynamic-TLS, unmanaged-thread, and unavailable 16KiB-kernel boundaries remain
explicit rather than being promoted by loader or sample observations.

## Cross-layer validation

The following local gates passed on the native AArch64 host or against the
retained CI evidence:

- `dotnet test UrProtect.sln --configuration Release --no-restore` — 140
  managed tests passed.
- `make -C native/urprotect-runtime contract-check` — ABI probe passed with
  current HostContext/frame sizes and offsets.
- `make -C native/urprotect-runtime test` — entry, threaded TLS, PLT,
  import-version, dependency graph, environment, and loader-rollback tests
  passed.
- Fixture, regression, real-sample manifest/fingerprint/aggregate/evidence/
   security suites passed; the release fixture validator reports 13 cases.
- Release compatibility and real-sample reports rendered successfully; the
  release aggregate reports `identityCount=100` and shortfall zero.
- Release evidence gates passed for the fixture matrix and all 100 real-sample
  projects/all four layers.
- `scripts/run-regression-stress.sh --tier pr` — 6 tests passed.
- `scripts/run-coverage-fuzz.sh --tier pr` — coverage-guided fuzz passed.
- The local launcher/fixture release attempts correctly stopped at missing
  local musl/Zig tooling; the required native CI lanes independently passed
  the same launcher, fixture, musl, fuzz/stress, and release-smoke gates. This
  is an environment fact, not a product pass or a silent fallback.

## CI and release evidence

| Tier | GitHub Actions run | Commit | Result |
|---|---:|---|---|
| PR full gate | `36303770796` | `eb65e8569113cda5a11590434bfdd562d87f9e74` | build/test, 100-identity real-sample, bionic, and runtime-matrix jobs passed |
| Nightly rehearsal | `36303781357` | `194dae011939386c3ed4b116f0cd1804dc4f5396` | fixture-nightly, full 100-identity matrix, fuzz/stress, musl, bionic, and runtime evidence passed |
| Release rehearsal | `36304139025` | `194dae011939386c3ed4b116f0cd1804dc4f5396` | release fixture evidence, full 100-identity matrix, runtime matrix, bionic, musl, package, and release smoke passed |

The release artifact was downloaded and independently checked: both ARM64
archives passed `SHA256SUMS`, contained the published validator, static native
launcher, launcher self-test, provenance, SBOM, compatibility contract, and
fixture manifest. The release job intentionally skipped GitHub release asset
publication because this was a non-tag rehearsal; package creation and smoke
validation still passed.

## Remaining boundaries

- No general-purpose in-process loader or arbitrary dependency graph is
  claimed.
- Public ordinary samples remain HostContext `not-applicable` without the
  declared `urp_entry` ABI.
- Native bionic evidence is limited to the pinned Termux/container adapter
  slice; it does not claim Android devices, OEM kernels, AVD, QEMU, or a native
  bridge.
- The 16KiB kernel row remains `environment-unavailable`/`unknown` when the
  native host is 4KiB; aligned user-space ELF observations do not change it.
- Release rehearsal artifacts are evidence, not a published release, until a
  tag-triggered publishing workflow is intentionally run.
