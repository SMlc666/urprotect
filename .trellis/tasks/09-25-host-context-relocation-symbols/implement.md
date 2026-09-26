# Implementation plan: HostContext relocation and symbol expansion

## Dependencies

- Architecture foundation and ELF model ownership are required.
- Real-sample expansion supplies the first frequency-prioritized family.
- Dependency/path child owns graph/search semantics; this child must not invent
  a conflicting dependency policy.

## Checklist

- [x] Record current RELATIVE/RELR/GLOB_DAT model, adapter, fixture, status,
      handle, and release behavior.
- [x] Select exact weak undefined JUMP_SLOT and define symbol/target/binding
      contract before acceptance changes.
- [x] Existing typed PLT relocation model already represents JUMP_SLOT; native
      static preflight tests cover the new acceptance boundary without broadening parser policy.
- [x] Add native adapter preflight; ABI/layout unchanged.
- [x] Add linker-produced AArch64 PLT fixture and nearest-negative mutations.
- [x] Entry observes unresolved weak function as zero/status 53; negatives assert zero image handle.
- [x] Run managed HostContext handoff and retain native AArch64 glibc evidence.
- [x] Reconcile the existing libc dependency fixture's DT_VERSYM/DT_VERNEED use with the formerly overbroad rejected symbol-version row.
- [x] Add a distinct, bounded single-libc import-version contract while keeping versioned definitions and entry selection rejected.
- [x] Validate GNU-hash-derived VERSYM table bounds, version-need filenames/counts/chains, auxiliary strings/hashes/indices/flags, and zero-handle outcomes for nearest malformed or unsupported cases.
- [x] Reject R_AARCH64_JUMP_SLOT in ordinary DT_RELA so it cannot bypass the dedicated PLT contract.
- [x] Update manifest, docs, contract inventory, and runtime spec; no report schema change.
- [x] Push the implementation and confirm native AArch64 glibc PR CI retains
      and gates both managed runtime oracles. PR run `36232680887` passed
      `build-and-test`, `real-sample-matrix`, and `bionic-native-arm64`; its
      uploaded `test-evidence-36232680887` includes the version self-test log,
      GNU-hash-only fixture/readelf report, and managed dependency status 37,
      with the HostContext evidence gate passing.

## Real-sample impact

The authoritative native PR artifact `real-samples-pr-36220307292` was
downloaded and inspected. Its 20 identity fingerprints report `DT_GNU_HASH`
and PLT/JUMP_SLOT relocations in 20/20 identities and symbol-version metadata
in 19/20. This is frequency evidence only; the registry's existing policy remains
unchanged, and none of these normal executables is a declared HostContext
`urp_entry` image.

| Project IDs | Observed feature / layer | Oracle and expected outcome | Evidence path |
| --- | --- | --- | --- |
| `busybox`, `caddy`, `cmake`, `curl`, `ffmpeg`, `git`, `gnu-bash`, `gnu-coreutils`, `jq`, `nano`, `nginx`, `nodejs`, `openssl`, `perl`, `postgresql`, `python`, `redis`, `ripgrep`, `sqlite`, `vim` | `relocations.family.plt`; static fingerprint | `run-real-sample-matrix.sh` + `inspect-real-sample.py`; preserve each recorded static `accepted-and-runs`, with HostContext `not-applicable` because these artifacts do not declare the entry ABI | `.artifacts/real-samples/pr/<project-id>/{elf-fingerprint.json,result.json,readelf.txt}`; aggregate `.artifacts/real-samples/pr/aggregate.json` |
| `caddy`, `cmake`, `curl`, `ffmpeg`, `git`, `gnu-bash`, `gnu-coreutils`, `jq`, `nano`, `nginx`, `nodejs`, `openssl`, `perl`, `postgresql`, `python`, `redis`, `ripgrep`, `sqlite`, `vim` | `symbol-versions` + `DT_GNU_HASH`; parser/fingerprint observation | Same real-sample matrix; preserve each static `accepted-and-runs`; HostContext remains `not-applicable`; the controlled `libc.so.6` GNU-hash requirement fixture, not frequency, proves the bounded import slice | `.artifacts/real-samples/pr/<project-id>/{elf-fingerprint.json,result.json,readelf.txt}`; aggregate `.artifacts/real-samples/pr/aggregate.json` |
| `native/urprotect-runtime/host_context_dependency_fixture.c` (generated AArch64 shared object) | `runtime.host-context.dependency-symbol-version-requirements`; HostContext glibc | `test_managed_host_context.sh`; accepted GNU-hash-backed libc version-need chain, entry status 37; malformed/out-of-slice mutations return stable status and zero handle | `.artifacts/host-context/managed/{dependency-version-metadata.txt,version-self-test.log,dependency-result.txt}` |

Real-sample artifact metadata and raw ELF inputs are not committed; the
downloaded CI artifact was used only to verify frequencies, project IDs, and
the expected layer classifications.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
PATH=/root/.dotnet:$PATH DOTNET=/root/.dotnet/dotnet \
  bash native/urprotect-runtime/test_managed_host_context.sh
python3 tests/test_fixture_matrix.py
./scripts/run-coverage-fuzz.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json \
  --feature runtime.host-context.weak-undefined-jump-slot
python3 scripts/check-evidence.py fixtures/manifest.json \
  --feature runtime.host-context.dependency-symbol-version-requirements
```

## Rollback

Keep the current validated rows and return the new family to explicit rejected
or unknown status if any runtime oracle, capability contract, or negative
boundary is incomplete.
