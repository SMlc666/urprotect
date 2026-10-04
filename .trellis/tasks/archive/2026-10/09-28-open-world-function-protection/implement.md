# Implementation plan

This plan is intentionally ordered so that compatibility evidence becomes
truthful before the binary writer and protection passes are allowed to publish
rewritten files.

## Phase A — Freeze contracts and evidence vocabulary

1. Update the real-sample schema/result vocabulary so static success is
   `validated`, not `accepted-and-runs`.
2. Add explicit baseline, outer-wrapper, and function-protection policy fields
   to the registry/selector manifests while preserving the 100 identity set.
3. Add schema/gate tests for:
   - all 100 IDs present exactly once;
   - 78/21/1 runtime counts;
   - static validation never claiming execution;
   - nightly baseline and outer layers required for every identity;
   - protection `not-applicable` only when no explicit selector exists; and
   - no raw runtime closure or executable uploaded as evidence.
4. Correct `run-real-sample-matrix.sh`, report rendering, aggregate checks, and
   docs to distinguish structural, baseline, outer, HostContext, and protection
   outcomes.

Validation:

```sh
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_real_sample_aggregate.py
python3 tests/test_real_sample_security.py
```

Rollback point: revert only schema/orchestrator changes; no managed/native
runtime behavior should have changed yet.

## Phase B — Build reproducible full-corpus runtime closures

1. Define the closure manifest format: base identity, package index identity,
   exact archive rows, dependency edges, extracted artifact path, argv/cwd/env,
   expected status, and resource limits.
2. Generate and review the glibc Debian Bookworm ARM64 closure for all 78
   identities. Verify every direct/transitive package archive hash and that
   each declared executable resolves inside the assembled rootfs.
3. Generate and review the musl Alpine closures for BusyBox and all 20 APK
   identities, including the pinned Alpine 3.22 base and the existing BusyBox
   minirootfs baseline.
4. Extend the locked Termux/bionic package closure for Node.js and its runtime
   dependencies. Retain package lock, image digest, loader identity, and
   before/after package inventories.
5. Implement bounded offline closure acquisition/extraction under
   `RUNNER_TEMP`; never use host libraries, network, or package indexes after
   the locked acquisition phase.
6. Add per-sample safe invocation policies. Every command must launch the
   declared artifact, be networkless, be bounded, and retain only normalized
   streams/status/side-effect evidence.

Validation:

```sh
python3 tests/test_real_sample_manifest.py
python3 scripts/validate-runtime-matrix.py fixtures/runtime-matrix.json
python3 tests/test_runtime_matrix.py
```

Runtime validation on native ARM64:

```sh
./scripts/run-real-sample-matrix.sh --tier nightly --shard ...
python3 scripts/check-real-sample-evidence.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier nightly \
  --artifact-root .artifacts/real-samples/nightly
```

Rollback point: retain the previous metadata-only registry runner and keep the
new closure runner behind the nightly feature/policy gate until one complete
100-identity run is independently checked.

## Phase C — Add bionic outer profile and full wrapper oracle

1. Extend managed pack validation to recognize `/system/bin/linker64` as a
   bionic runtime interpreter while keeping malformed/unrecognized paths
   rejected.
2. Extend the native launcher interpreter predicate and launcher self-tests for
   bionic. Verify the launcher itself remains static AArch64 PIE with no
   dependency on the target runtime.
3. Add path-sensitive outer profile handling. Preserve the no-path
   `outer-execveat` contract for proven path-independent inputs and add the
   explicit path-preserving mode for RPATH/RUNPATH/`$ORIGIN` cases.
4. Make the real-sample runner pack and execute every nightly identity, then
   compare original and wrapped behavior in the same runtime closure.
5. Add nearest-negative tests for unsupported interpreter, missing interpreter,
   duplicate interpreter, path-policy mismatch, and wrapper/profile mismatch.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-launcher test
./scripts/run-packed-fixture-matrix.sh --tier pr
./scripts/run-bionic-fixture.sh
```

## Phase D — Add merged function-symbol inventory and selectors

1. Extend the ELF model/parser with checked `.symtab`/linked-string-table
   records and normalized `STT_FUNC` metadata; retain `.dynsym` identities.
2. Implement merged inventory, alias/overlap detection, exact selector
   resolution, table/index/address disambiguation, and stable diagnostics.
3. Add the explicit `protect` CLI request model and JSON report. No transform
   flags or function selectors means no transform operation.
4. Add fixture binaries with `.symtab`, `.dynsym`, duplicate names, aliases,
   zero-size functions, stripped sections, and out-of-range symbols.

Validation:

```sh
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj \
  --configuration Release --no-restore --filter Category=ElfParser
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj \
  --configuration Release --no-restore --filter Category=Protect
python3 tests/test_regression_matrix.py
```

## Phase E — Build the AsmStone-backed IR, CFG, and state/resource layer

1. Expand the adapter to retain all supported semantic operands, implicit
   effects, register constraints, target kinds, and encoder provenance without
   exposing third-party types.
2. Add decode/encode/decode round-trip tests for the instruction families used
   by the transform fixtures, including register views, SP/ZR, memory
   writeback, calls, branches, PC-relative references, flags, and barriers.
3. Implement symbol-bounded CFG/worklist analysis and reject incomplete
   control flow explicitly.
4. Implement machine-state effects, ABI call boundaries, register banks/views,
   NZCV, stack alignment, memory effects, pressure/interference, and spill-slot
   planning.
5. Add dry-run reporting for selected functions before any writer is invoked.

Validation:

```sh
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj \
  --configuration Release --no-restore --filter Category=Aarch64
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj \
  --configuration Release --no-restore --filter Category=ProtectAnalysis
./scripts/run-coverage-fuzz.sh --tier pr
```

Rollback point: the dry-run/analysis layer can ship without enabling output
rewriting. Any unsupported semantic or insufficient resource must stop the
selected function with a report, not fall through to a heuristic pass.

## Phase F — Implement ELF rewrite and transformation passes

1. Add layout planning for transformed code regions, program/section metadata,
   branch ranges, veneers, PC-relative references, owned relocations, symbols,
   and unwind/CFI obligations.
2. Implement transactional output writing and post-write parse/decode checks.
3. Implement control-flow flattening for the first eligible CFG subset,
   preserving call/return/ABI and generated state resources.
4. Implement register permutation over the flattened IR with ABI edge shuffles,
   parallel-copy cycle resolution, and verified spills where allowed.
5. Support independent pass selection and fixed composition order:
   flattening, then permutation.
6. Add direct function fixture tests for each pass, combined passes, resource
   exhaustion, unsupported control flow, branch-range overflow, PC-relative
   repair, and atomic no-output failure.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
python3 tests/test_fixture_matrix.py
./scripts/run-regression-stress.sh --tier pr
```

## Phase G — Required PR and full nightly E2E

1. Add the deterministic symbolized transform fixture to glibc, musl, and
   Termux/bionic PR lanes. Run register permutation alone, flattening alone,
   and the combined ordered recipe.
2. Add the PR real witnesses: BusyBox/musl, coreutils `ls`/glibc, and Termux
   Node.js/bionic. Compare original/protected behavior and retain hashes,
   selector reports, runtime identity, and first-failure layer.
3. Make musl runtime protection E2E a required PR gate rather than an extended
   nightly-only cell.
4. Shard nightly by runtime/project ID and run all 100 baseline + outer-wrapper
   identities. Merge evidence and assert exact 100-ID coverage.
5. Run protection only for explicit entries in the protection policy; report
   unselected projects as no-transform, never as protected.
6. Upload only text/JSON/hash evidence. Keep all archives, rootfs trees, and
   executables in temporary storage and delete them before evidence validation.

Validation:

```sh
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
./scripts/run-protection-e2e.sh --tier pr --runtime musl
./scripts/run-protection-e2e.sh --tier pr --runtime bionic
python3 scripts/check-real-sample-evidence.py fixtures/real-samples/manifest.json \
  --tier nightly --artifact-root .artifacts/real-samples/nightly
```

## Final quality gate before implementation approval

- `prd.md`, `design.md`, and `implement.md` agree on explicit selector scope,
  atomic failure, pass ordering, three PR runtimes, and full 100 nightly
  baseline/outer execution.
- `implement.jsonl` and `check.jsonl` contain real spec/research entries.
- `python3 ./.trellis/scripts/task.py validate open-world-function-protection`
  passes.
- No product code or CI workflow is changed before the user approves this
  final planning summary and the task is moved to `in_progress`.
