# Implementation plan: outer-execveat compatibility expansion

## Dependencies

- Architecture foundation complete enough to identify profile policy ownership.
- Current frame v3/profile/launcher contract remains stable.
- Sample fingerprint identifies the first executable class with useful impact.

## Checklist

- [x] Capture current launcher and managed handoff behavior baseline.
- [x] Select dynamic `ET_EXEC` and write its exact accepted/rejected contract.
- [x] Add a real-toolchain fixture and nearest-negative parser/pack/native cases.
- [x] Extend baseline/wrapper comparison to status, streams, argv, environment,
      cwd, inherited descriptor, declared file, and signal termination.
- [x] Validate launcher ELF, frame round-trip, source digest, and anonymous
      handoff invariants.
- [x] Add the native AArch64 glibc baseline/wrapper oracle and local evidence;
      do not claim musl runtime coverage from the accepted path suffix.
- [x] Update the parser/outer feature rows, compatibility docs, runtime spec,
      and local evidence artifacts.
- [x] Confirm pushed GitHub CI retains the native glibc fixture artifacts and
      passes the post-run evidence gate (runs `36220305079` and `36220307292`).
- [x] Audited the touched parser, pack, and launcher boundaries; the class
      policy remains in their existing owners and no large new branch warrants
      a broader refactor in this slice.

## Real-sample impact

| Project / case | Feature and layer | Oracle / expected result | Evidence path |
| --- | --- | --- | --- |
| Caddy (`caddy`) | `elf.identity.aarch64-et-exec`, static parser validation | `run-real-sample-matrix.sh`; `accepted-and-runs` for static parsing; baseline, outer wrapper, and HostContext remain `not-applicable` because the package input lacks its dependency closure | `.artifacts/real-samples/pr/caddy/{result.json,elf-fingerprint.json,urprotect-report.json}` |
| Python (`python`) | `elf.identity.aarch64-et-exec`, static parser validation | `run-real-sample-matrix.sh`; `accepted-and-runs` for static parsing; baseline, outer wrapper, and HostContext remain `not-applicable` because the package input lacks its dependency closure | `.artifacts/real-samples/pr/python/{result.json,elf-fingerprint.json,urprotect-report.json}` |
| `c-gcc-glibc-et-exec` | `elf.outer.dynamic-et-exec`, native outer-wrapper behavior | `run-packed-fixture-matrix.sh`; baseline/wrapper status and process observations must match on native AArch64 glibc | `.artifacts/packed/pr/c-gcc-glibc-et-exec/` |

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-launcher test
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr --execution native-linux
python3 scripts/check-evidence.py fixtures/manifest.json --feature elf.outer.dynamic-et-exec
```

## Rollback

Revert the class-specific pack acceptance, fixture, launcher probe, and matrix
row as one slice. Retain the new negative test if it documents a still-valid
boundary.
