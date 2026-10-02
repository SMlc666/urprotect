# Current compatibility evidence research

## Repository observations

- `fixtures/real-samples/manifest.json` contains 100 identities: 78 glibc, 21 musl, and one bionic; 96 are `ET_DYN` and four are dynamic `ET_EXEC`.
- All 100 are statically applicable. Only `busybox` currently has a complete declared baseline rootfs policy. All 100 currently declare outer-wrapper `not-applicable` and HostContext `not-applicable`.
- `scripts/run-real-sample-matrix.sh` maps a successful `urprotect validate` invocation to the static result `accepted-and-runs`; the sample itself is not launched in that branch. This makes the current static result vocabulary unsuitable for compatibility claims.
- The runner already has bounded extraction, hash verification, bubblewrap isolation, result artifacts, and cleanup markers. The missing pieces are dependency-closure acquisition, per-sample invocation policy, outer-wrapper execution, and bionic outer-loader support.
- The current outer packer and native launcher accept only interpreter names ending in `ld-linux-aarch64.so.1` or `ld-musl-aarch64.so.1`. The public bionic identity uses `/system/bin/linker64`.

## CI baseline

- Required native ARM64 build/fixture/packed-fixture jobs run on Ubuntu ARM64/glibc.
- The current PR runtime matrix includes current glibc and the locked bionic lane, but the extended musl runtime cells are scheduled/manual/release.
- The existing bionic lane builds a fixture and HostContext adapter in a locked Termux container; it does not run managed function protection or outer-wrapped public samples.
- The Android x86_64 AVD/native-bridge lane is a separate, slower platform test and is outside the first-phase bionic requirement.

## Planning consequence

The compatibility work must first correct result semantics and then add a closure-driven runtime orchestrator. Full nightly coverage means every identity receives a baseline and outer-wrapper attempt in its declared runtime. Function transforms remain a separate explicit-selector layer and must not be inferred from sample availability.
