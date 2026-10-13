# Repository research: runtime and evidence baseline

## Current verified baseline

The narrow current glibc vertical slice has a successful Release build with zero warnings/errors, 175 managed tests, protection E2E, Protected Image rehydration, sealed memfd handoff, execveat execution, and baseline/protected stream/status comparison.

## Runtime contracts already present

- `fixtures/runtime-matrix.json` owns pinned glibc, musl, and bionic runtime cells and toolchain/environment identity.
- `fixtures/manifest.json` owns feature IDs, positive/negative fixture declarations, tiers, and evidence paths.
- Existing native/runtime contracts already distinguish glibc, musl, and bionic; observations from one runtime do not promote another.
- Existing TLS evidence covers a bounded initial-exec slice and glibc threaded lifecycle. Dynamic TLS, broader TLS models, and musl/bionic threaded claims are current boundaries.
- Existing relocation evidence covers bounded RELATIVE/RELR, GLOB_DAT, and a narrowly specified weak JUMP_SLOT form; broader relocation semantics remain explicit boundaries.

## Required expansion

The selected scope promotes complete semantic features separately on glibc, musl, and bionic. Each promoted feature needs its own native positive/negative evidence, pinned environment identity, baseline/protected behavior comparison, and post-run evidence validation.
