# Implementation plan: bounded HostContext dependency graph

## Dependencies

- Architecture foundation and outer/profile ownership are complete.
- HostContext weak JUMP_SLOT and exact libc import-version symbol semantics are
  complete; this slice preserves both.
- TLS/lifecycle consumes the release policy below and must not add thread/TLS
  ownership here.

## Ordered checklist

- [x] Preserve the singleton recognized-libc row and document the closed graph
      predicate plus real-sample selection evidence (16/20 glibc identities
      include `ld-linux-aarch64.so.1`).
- [x] Extend native dynamic preflight to bound at most two names and accept
      either the existing singleton or the exact unique pair
      `{libc.so.6, ld-linux-aarch64.so.1}`; reject duplicates, unknown names,
      missing libc, and a third dependency before loader handoff.
- [x] Return bounded dependency-count metadata from the validator; gate the new
      pair in `host_adapter.c` on empty `LD_LIBRARY_PATH`, `LD_PRELOAD`, and
      `LD_AUDIT` without changing the old singleton path.
- [x] Add the native linker-produced pair fixture, readelf output, and direct
      native self-test. Verify positive handle acquire/release, status 37,
      constructor/destructor side effects, zero handles on metadata negatives,
      and a fake-loader environment path that never reaches entry. Add a valid
      pair image with an unresolved strong import to force `dlopen` failure and
      prove memfd/descriptor rollback with a zero handle.
- [x] Extend the managed HostContext oracle to pack/run the pair fixture and
      retain graph metadata, self-test, environment, output, status, and release
      marker evidence.
- [x] Add exact feature row and negative obligations to the compatibility
      manifest; wire its evidence gate into PR CI; update README,
      `COMPATIBILITY.md`, native runtime docs, contract inventory, runtime spec,
      and regression matrix as needed.
- [ ] Confirm the PR's native AArch64 glibc CI retains and passes both the old
      singleton oracle and the new pair oracle; do not claim musl/bionic support.

## Real-sample impact

Observed from `real-samples-pr-36232924362` on commit
`ce21e9bd1a73ebe369e38a5f0972ebaf79c9fc32`; normal samples remain HostContext
`not-applicable` because they lack the entry ABI.

| Project IDs | Feature / layer | Oracle and expected result | Evidence path |
|---|---|---|---|
| `cmake`, `curl`, `ffmpeg`, `git`, `gnu-bash`, `gnu-coreutils`, `jq`, `nano`, `nginx`, `openssl`, `perl`, `postgresql`, `python`, `redis`, `sqlite`, `vim` | `DT_NEEDED libc.so.6` + glibc loader; static fingerprint | preserve static `accepted-and-runs`; HostContext `not-applicable` | `.artifacts/real-samples/pr/<project-id>/{elf-fingerprint.json,readelf.txt,result.json}` and `aggregate.json` |
| `host_context_dependency_fixture.c` pair variant | `runtime.host-context.bounded-glibc-loader-dependency`; HostContext | native glibc status 37 + release marker; malformed names/paths/environment fail before handoff | `.artifacts/host-context/managed/{dependency-graph-readelf.txt,graph-self-test.log,graph-result.txt,graph.stdout,graph.stderr}` |
| `host_context_graph_loader_failure_fixture.c` | `runtime.host-context.bounded-glibc-loader-dependency`; HostContext adapter rollback | preflight accepts the exact pair; unresolved strong GLOB_DAT makes RTLD_NOW fail with `LOAD_FAILED`, zero handle, one memfd attempt, and unchanged descriptor count | `.artifacts/host-context/managed/{dependency-graph-loader-failure-readelf.txt,graph-self-test.log}` |

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
PATH=/root/.dotnet:$PATH DOTNET=/root/.dotnet/dotnet \
  bash native/urprotect-runtime/test_managed_host_context.sh
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json \
  --feature runtime.host-context.bounded-glibc-loader-dependency
PATH=/root/.dotnet:$PATH ./scripts/run-regression-stress.sh --tier pr
```

PR CI completion is required before archiving this child task. The producing
native AArch64 glibc job must retain both singleton and pair oracles and pass
the feature evidence gate.

## Rollback

Remove the exact two-name graph acceptance and its new row/positive oracle as a
single slice if the evidence gate fails. Keep the singleton libc behavior,
symbol-version contract, existing path rejections, and negative boundaries.
