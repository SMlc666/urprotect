# Implementation plan: TLS and lifecycle expansion

## Dependencies

- Architecture foundation and current HostContext owner map.
- Relocation/symbol semantics for TLS relocation classification.
- Dependency/path semantics for constructor/destructor and release ordering.
- Runtime matrix cells selected for each threaded oracle.

## Checklist

- [x] Characterize current initial-exec TLS, constructor, destructor, handle,
      entry-once, and release behavior; native and managed regression oracles
      pass.
- [x] Implement the size-versioned optional `URP_HOST_CAP_THREAD_LIFETIME`
      extension, owner-thread create/join callbacks, non-reused opaque handles,
      and launch-args image handle without changing legacy minimum sizes.
- [x] Enforce required-capability preflight before load, hide optional
      extensions from non-thread frames, preserve bounded legacy args, reject
      same-thread recursive dispatch, and exercise concurrent independent
      runtime dispatch.
- [x] Complete injected `pthread_create`/`pthread_join` failure rollback tests;
      deterministic invalid/null/foreign/repeated/self/owner/spawn-after-release
      checks and missing-capability/callback checks are present.
- [x] Add linker-produced initial-exec threaded TLS positive and dynamic-TLS
      nearest-negative fixtures. Deterministic inherited event/gate pipes cover
      explicit join, automatic release join, failing entry cleanup,
      constructor/entry/worker/TLS-teardown/destructor markers, values, and
      memfd-preflight rejection.
- [x] Exercise serial wrapper reruns and two concurrent independent dispatches
      using separate images and TLS instances.
- [x] Retain native AArch64 glibc runtime identity, exact readelf facts,
      capability/status results, lifecycle markers, hashes, and evidence-gated
      feature row. No musl/bionic threaded claim is made.
- [x] Update compatibility matrix, README/COMPATIBILITY, runtime/quality/error
      specs, contract inventory, and regression matrix.

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
  --feature runtime.host-context.threaded-initial-exec-tls
PATH=/root/.dotnet:$PATH ./scripts/run-regression-stress.sh --tier pr
```

The PR producer must pass `build-and-test`, `real-sample-matrix`, and
`bionic-native-arm64`; the HostContext feature gate runs in the glibc native
job. The additional threaded-TLS claim remains glibc-only.

## Real-sample impact

| Project IDs | Observed fact / feature | Layer and expected result | Evidence |
|---|---|---|---|
| `caddy`, `perl`, `ripgrep` | `PT_TLS` fingerprint; 3/20 identities (15%), covering Go, GCC, and Rust producers on glibc | Preserve existing parser/static classifications; HostContext remains `not-applicable` because these executables do not declare `urp_entry`; use only as prioritization evidence | CI artifact `real-samples-pr-36248424559`, `pr/{caddy,perl,ripgrep}/{elf-fingerprint.json,readelf.txt,result.json}` and `pr/aggregate.json` |
| Controlled initial-exec threaded shared object | current-thread and registered-worker TLS, image lifetime and release order | Native AArch64 glibc validated by linked fixture + managed packed wrapper; dynamic TLS rejected before memfd and non-glibc threaded claims remain unknown/out of scope | `.artifacts/host-context/managed/{threaded-tls-readelf.txt,dynamic-tls-negative-readelf.txt,threaded-tls-runtime.txt,threaded-tls-lifecycle.txt,threaded-tls-concurrent.txt,thread-adapter-self-test.log,sha256.txt}` |

## Rollback

Remove only the new TLS/lifecycle capability and positive path, retain
characterization and negative tests, and keep the previous validated row.
