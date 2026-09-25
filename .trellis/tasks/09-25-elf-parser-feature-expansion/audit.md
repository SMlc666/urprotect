# ELF parser feature expansion audit

## Scope

This child extracts symbol-version parsing behind a dedicated managed parser
owner and adds an observation-only `DT_VERDEF`/`DT_VERDEFNUM` model. The slice
extends the symbol-version parser family after measured real-sample evidence;
the version-definition row remains parser/model-only and does not promote
runtime support.

## Evidence

- A compiler/linker-produced AArch64 `ET_DYN` fixture contains three version
  definitions and is retained with its source, version script, build recipe,
  and SHA-256
  `4fb8ffa362ce8a18590eff735c971aaf217eb4dcd338bf071810fe0b3c971ae8` at the
  manifest evidence path.
- The latest real-sample PR artifact (GitHub Actions run `36099119871`) has
  fingerprints for 20 distinct project identities: 19/20 (95%) expose symbol
  version requirements (`DT_VERSYM`/`DT_VERNEED`), while 0/20 expose
  `DT_VERDEF`. Thus symbol-version parsing clears the 5% family-frequency
  trigger; definition records remain an explicitly fixture-proven parser
  completeness slice, not a claimed real-sample prevalence or runtime feature.
  The artifact's raw-input removal marker is present for each project.
- Twelve focused parser/report tests cover the positive model, unversioned
  baseline,
  unmapped table, count overflow, missing count, broken/overlapping record and
  auxiliary chains, and invalid/empty auxiliary names.
- `dotnet test UrProtect.sln --configuration Release --no-restore` passed with
  124 managed tests, including the version-definition report projection.
- `python3 tests/test_fixture_matrix.py` passed 24 tests; regression matrix
  passed 5; real-sample manifest/fingerprint/evidence/security/aggregate suites
  passed 12/2/3/3/5 tests. Both `pr` and `release` fixture metadata validation
  and the regression-matrix metadata validator passed.
- The PR-tier coverage-guided fuzz script completed successfully; the PR-tier
  concurrency/large-input stress script passed all six tests.
- Benchmark harness comparison at 5,000 iterations was captured from baseline
  commit `8ff9b99` and the final parser. Parse elapsed was 110.45 ms baseline
  versus 70.14 ms current; allocations were 15,488,032 bytes versus
  11,909,440 bytes (about 23% fewer). The shared dynamic-tag lookup now uses
  indexed iteration rather than boxing an interface enumerator on each lookup.
  Wall-clock measurements are noisy characterization, not a universal
  performance claim.
- GitHub CI for the parser change is pending after its implementation commit;
  the real-sample child CI already passed on the preceding PR revision.

## Ownership and contract

- `ElfSymbolVersionParser` owns version-index, version-need, and new
  version-definition table interpretation; `ElfParserUtilities` owns checked
  ranges, LoadMap conversion, string reads, and arithmetic helpers.
- `ElfParser` remains the public parse facade and no longer duplicates the
  symbol-version reader or the shared alignment helper.
- `VersionDefinitionTableMalformed` is a stable diagnostic for malformed or
  unmapped definitions. Unknown/unsupported runtime semantics remain data or
  rejection, not speculative acceptance.
- The controlled matrix row `elf.symbol-version.definitions` is `proven` only
  for parser/model observation. `runtime.host-context.symbol-version` remains
  rejected; no outer or HostContext claim changed.

## Rollback

Revert the extraction and model row together while retaining the existing
symbol-version malformed tests. If later runtime work is attempted, keep this
model observation and add a separate positive/negative native oracle rather
than widening this parser-only row.
