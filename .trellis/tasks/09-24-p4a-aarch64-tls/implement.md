# P4-A Implementation Plan

- [ ] Select the first TLS model from real AArch64 fixtures.
- [ ] Define module/thread ownership and release ordering.
- [ ] Add threaded positive, race, teardown, malformed, and unsupported tests.
- [ ] Retain separate glibc/musl/bionic evidence where executed.
- [ ] Update HostContext contract, matrix, and runtime documentation.

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```
