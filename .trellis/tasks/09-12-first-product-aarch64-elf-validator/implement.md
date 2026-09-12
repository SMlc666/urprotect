# Implementation Plan

Do not run `task.py start` until this plan is reviewed and explicitly approved.

## 1. Product contract

- [x] Confirm the final CLI option grammar and documented exit-code matrix.
- [x] Add product version constants and a single report schema-version owner.
- [x] Add `ReportV1` DTOs and deterministic JSON serialization.
- [x] Add human-output formatting that shares diagnostic projections with JSON.

Validation:

```text
dotnet test --filter Category=Cli
dotnet test --filter Category=Report
```

Rollback: retain the current human CLI path until report/exit-code tests pass.

## 2. CLI behavior and atomic reports

- [x] Replace ad hoc argument handling with a small testable command parser.
- [x] Map core diagnostics and filesystem failures to exit codes 0/2/3/4/5/10.
- [x] Add `--json <path|->` and keep stdout JSON-clean in stream mode.
- [x] Atomically publish report files and preserve the existing no-op copy rules.
- [x] Add tests for malformed options, missing values, missing input, output
  conflict, report failure, identity mismatch, and unexpected exceptions.

Validation:

```text
dotnet test --filter Category=Cli
dotnet test --filter Category=NoOp
```

## 3. Report completeness and golden contracts

- [x] Project ELF identity, load-map/segment counts, dynamic metadata,
  symbols/version entries, notes/properties, relocation counts, analysis
  boundaries, and ordered diagnostics.
- [x] Include source/output byte lengths and SHA-256 values when applicable.
- [ ] Add checked-in golden JSON files for synthetic valid, stripped, warning, and invalid
  cases.
- [x] Verify repeated runs produce identical JSON apart from explicitly excluded
  path/timing fields.

Validation:

```text
dotnet test --filter Category=Report
```

## 4. Publish profiles

- [ ] Add explicit `linux-arm64` glibc and `linux-musl-arm64` publish profiles
  compatible with `global.json` and locked restore.
- [ ] Produce self-contained archives with versioned names, notices, checksums,
  and a manifest containing SDK/AsmStone/fixture provenance.
- [ ] Run each packaged executable with `--help`, `validate`, `--json`, and
  `--copy` on its matching native profile.
- [ ] Add SBOM/dependency inventory generation without adding runtime parser
  dependencies.

Validation:

```text
dotnet restore UrProtect.sln --locked-mode
dotnet publish src/UrProtect.Cli --configuration Release --runtime linux-arm64 --self-contained true
dotnet publish src/UrProtect.Cli --configuration Release --runtime linux-musl-arm64 --self-contained true
```

Rollback: do not publish a bundle until both runtime profiles execute the same
acceptance fixture.

## 5. Release CI and evidence

- [ ] Add a release packaging job triggered only by published releases or an
  explicit manual release rehearsal input.
- [ ] Reuse native glibc fixture, pinned musl container, and Android JNI jobs;
  keep Android native-bridge opt-in for manual non-release dispatches.
- [ ] Upload archives, checksums, SBOM, report goldens, environment manifests,
  fixture logs, and failed ELF/APK inputs with `if: always()`.
- [ ] Add a release smoke script that installs/extracts each archive in a clean
  temporary directory and checks the documented commands.

Validation:

```text
python3 scripts/validate-fixtures.py fixtures/manifest.json release --emit
git diff --check
```

## 6. Documentation and final review

- [ ] Rewrite README around the first product quickstart, supported boundary,
  report example, no-op guarantee, and explicit non-goals.
- [ ] Add release/operator documentation for glibc versus musl packages and
  Android validation labels.
- [ ] Run the PRD convergence pass and ensure design/implementation contracts
  agree.
- [ ] Run task context validation and final review; update specs with any new
  executable contract.
- [ ] Present the final planning summary and wait for explicit implementation
  approval.

Rollback point: if a stable report or package contract cannot be demonstrated,
keep the existing infrastructure MVP and do not introduce transformation code.
