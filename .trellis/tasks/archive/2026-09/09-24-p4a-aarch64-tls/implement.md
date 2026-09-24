# P4-A Implementation Plan

- [x] Select the first TLS model from real AArch64 fixtures: initial-exec with
      `R_AARCH64_TLS_TPREL64`.
- [x] Define module ownership and release ordering for the single-thread slice;
      the system loader owns allocation and release.
- [x] Add a positive TLS fixture, managed profile oracle, malformed boundary,
      and unsupported-model rejection coverage.
- [x] Retain separate glibc/musl/bionic evidence where executed.
- [ ] Update HostContext contract, matrix, and runtime documentation.

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```
