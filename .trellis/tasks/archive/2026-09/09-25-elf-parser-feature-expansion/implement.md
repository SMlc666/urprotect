# Implementation plan: ELF model/parser refactor and feature expansion

## Dependencies

- Wait for architecture foundation audit and first sample histogram.
- Preserve current parser/validator, malformed corpus, property, golden report,
  and fuzz contracts while extracting responsibilities.
- Coordinate any feature that reaches native HostContext with the relocation /
  symbol child; do not duplicate a feature-specific parser in C# and C.

## Checklist

- [x] Capture parser diagnostics, model snapshots, malformed behavior, fuzz
      no-throw behavior, and parse/validation benchmark baseline.
- [x] Define parse context and ownership map for table readers, diagnostics,
      address conversion, and model records.
- [x] Extract the first audited cohesive parser boundary and remove duplicate
      implementation paths.
- [x] Extend feature fingerprint/model records required by the selected sample
      cluster.
- [x] Add positive linker-produced fixture and nearest-negative/malformed
      fixture before acceptance logic.
- [x] Add stable diagnostics and golden/projection assertions.
- [x] Add native/profile oracle if the selected feature affects runtime
      (not applicable: this slice is parser/model-only and HostContext remains
      rejected).
- [x] Promote minimized fuzz input to deterministic regression when relevant
      (no new fuzz finding was introduced by this bounded extraction).
- [x] Update manifest, contract inventory, report, specs, and evidence paths.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
./scripts/run-coverage-fuzz.sh --tier pr
./scripts/run-regression-stress.sh --tier pr
```

For a native-relevant feature:

```sh
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
```

## Rollback and quality gate

- Revert one extraction or one feature family independently.
- Keep model observation and negative corpus when removing acceptance.
- Preserve diagnostics and no-throw behavior.
- Reject completion if a consumer reparses bytes, duplicates address math, or
  claims a runtime/profile layer without its oracle.
