# Implementation plan: complete five-model TLS semantics and runtime matrix

## Phase 0 — Planning and contract inventory

1. Freeze the G0-G2 current contract and identify every existing TLS parser,
   relocation, semantic extension, layout, HostContext, fixture, and evidence
   owner.
2. Record the exact AArch64 TLS relocation constants and linker-produced sequence
   shapes in the research/fixture inventory; do not infer encodings from model
   names.
3. Define stable diagnostic categories, semantic snapshot fields, profile
   requirements, runtime requirements, and the matrix row schema before coding.


## Phase 0A — AArch64 encoding ownership and test correction

3a. Inventory every production manual instruction-word writer and every fixture/golden helper that constructs AArch64 words. Classify each occurrence as instruction encoding, ELF constant/relocation data, binary test data, or unrelated native/protocol data.
3b. Add the project-owned AsmStone-backed AArch64 instruction encoder adapter with bounded project types, stable diagnostics, and mandatory decode round-trip validation.
3c. Route branch, ADR/ADRP, literal, immediate, load/store, move-wide, register-move, compare, return, and resolver-call output encoding through the adapter. Keep relocation target calculation and TLS ownership validation in UrProtect.
3d. Convert TLS and protection fixture builders to the adapter or to explicitly named GNU assembler/linker oracle inputs. Add nearest-negative mutations from structured valid encodings and remove unexplained new opcode literals.
3e. Add a focused differential test matrix proving AsmStone output against GNU assembler/linker output for every promoted instruction family and proving that valid instruction encodings do not imply valid TLS relocation or sequence semantics.
## Phase 1 — Structural TLS facts

4. Add bounded `TlsSegmentFacts` and `TlsDynamicFacts` under `StructuralElf`.
5. Parse PT_TLS template/zero-fill/alignment/permission/owning-load facts and
   TLS dynamic relocation/symbol/module metadata through existing bounded readers.
6. Add valid, truncated, overflow, overlap, permission, malformed relocation,
   and model-confusion corpus cases. Structural parsing must remain independent
   of instruction decoding and runtime acceptance.
The first local-dynamic recognizer fixture is bounded to the TLSLD ADRP/ADD + resolver CALL26 + DTPREL ADD/ADD sequence. It must retain exact source relocation ordering, resolver target, register ownership, dynamic DTPMOD64 GOT ownership, and PT_TLS facts; other TLSLD forms are nearest-negative cases.

## Phase 2 — Typed five-model semantic IR

7. Replace the string-only TLS model with typed `TlsAccessModel`,
   `TlsRelocationFamily`, `TlsBinding`, `TlsAddressExpression`, instruction
   sequence, module/symbol, and runtime/profile requirement records.
8. Add AArch64 sequence recognizers for local-exec, initial-exec, local-dynamic,
   general-dynamic, and TLSDESC. Recognizers must retain source ranges,
   register/resource effects, paired relocations, calls/resolvers, access sizes,
   and addends.
9. Reject incomplete or inconsistent sequences deterministically; never silently
   reinterpret one model as another.
10. Add semantic tests for every model, nearest model-confusion pair, unknown
    target, register conflict, relocation mismatch, and demand-driven dependency.

## Phase 3 — Snapshot and current artifact integration

11. Extend the existing `SemanticTlsBindingExtension` owner to encode/decode the
    typed five-model contract canonically. Keep bounds, deterministic ordering,
    duplicate checks, digest coverage, and malformed/unsupported diagnostics.
12. Keep Payload Frame v3, Protected Image ABI identifier/version, and existing
    operation meanings unchanged. Extend the sole Protected Image v1 operation
    grammar atomically with one bounded SemanticPlanSnapshot operation containing
    canonical bytes plus digest, using SemanticPlanSnapshotCodec as the only codec.
    Require and validate it for semantic TLS fixups; reject transformed TLS streams
    missing the snapshot. Do not add a migration reader or parallel TLS codec.
13. Add snapshot round-trip, canonical digest, extension-boundary, and tamper tests
    for every model and relocation family.

## Phase 4 — Rewrite and shared layout/materialization
The first rewrite/materialization vertical slice is local-dynamic TLSLD only. It must re-encode the owned ADRP/ADD, exact `__tls_get_addr` `CALL26`, and DTPREL ADD/ADD sites through the existing semantic/address-map path while preserving the loader-owned DTPMOD64 GOT relocation, PT_TLS template/zero-fill, and dynamic relocation tables. Publication fails closed on resolver, range, register, addend, source/output map, GOT, or PT_TLS mismatch.
The bounded TLSDESC producer slice is now implemented as a second exact vertical slice. It admits only the four-site ADRP/LD64/ADD/TLSDESC_CALL form with one validated 16-byte descriptor owner and paired resolver tags/stub. Marker-owned `BLR X1` fallthrough remains physically adjacent under flattening so shared layout validation can prove the eight-word sequence. Relaxed TLSDESC forms and all native runtime rows remain separate evidence work.

14. Build TLS semantic fixups that preserve thread-relative/module-relative
    expressions, symbol/module identity, access width, and addend.
15. Connect TLS fixups to the existing `ProtectionWorkflow`, semantic plan,
    address map, `ElfLayoutPlanner`, and `ElfLayoutMaterializer`.
16. Preserve PT_TLS template, zero-fill, alignment, GOT/TLSDESC state, dynamic
    relocation ownership, and lifecycle metadata. Reject any output overlap or
    implicit TLS metadata movement without a typed layout contract.
17. Reparse and semantically validate every transformed model before publication.
18. Add output/hash/rollback tests for layout overlap, address-map conflicts,
    relocation failure, profile mismatch, materialization failure, and no partial
    artifact/evidence publication.

## Phase 5 — Runtime-neutral fixture and lifecycle contract

19. Produce one linker-controlled positive fixture per model with initialized TLS,
    zero-fill, symbol/module identity, and a deterministic entry result.
20. Add nearest-negative fixtures for malformed PT_TLS, wrong relocation family,
    incomplete sequence, unsupported permission/layout, broken GOT/TLSDESC,
    unresolved module/symbol, and lifecycle/release failures.
21. Preserve separate current-thread and registered-worker lifecycle contracts.
    Worker lifetime remains opt-in and profile-specific; teardown must precede
    image destruction when claimed.
22. Capture readelf facts, toolchain/linker/runtime identity, baseline/output
    streams/status, per-thread values, zero-fill, constructor/destructor/worker
    markers, release order, and all hashes.

## Phase 6 — Independent runtime matrix

23. Add one matrix row for every model/profile/runtime/lifecycle tuple. Each row
    independently runs baseline, transformed/re-hydrated image, loader handoff,
    behavior comparison, and evidence checking.
24. Run native AArch64 glibc, musl, and bionic lanes independently. Missing
    capability is `environment-unavailable`, never a substitute pass.
25. Keep existing initial-exec and threaded-initial-exec rows as baselines until
    they pass the complete managed semantic rewrite/equivalence gate.
26. Add CI/checker coverage for row completeness, profile/ABI/workflow owner,
    hashes, first-failure stage, rollback witness, and no cross-runtime claim
    promotion.

## Validation commands

The encoding-boundary gate must also run the focused AsmStone-backed encoder and fixture checks. The grep audit is informational during migration and becomes a failure for any new production instruction-word writer:

```sh
rg -n 'TryEncodeFields|AsmStoneApi\\.TryEncode|Aarch64InstructionEncoder' src/UrProtect.Core tests/UrProtect.Core.Tests
rg -n 'EmitWord\\(|words\\.Add\\(|0x[0-9A-Fa-f]{8}' src/UrProtect.Core/Application/Protection src/UrProtect.Core/SemanticPlanning src/UrProtect.Core/ElfLayout
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-restore --filter 'FullyQualifiedName~AsmStoneAdapterTests|FullyQualifiedName~Aarch64InstructionEncoderTests|FullyQualifiedName~TlsLocalExecWorkflowTests'
```

The second audit must classify existing migration debt rather than blindly reject required ELF constants or relocation masks. New production instruction encoders and new fixture opcode literals fail review unless they use the adapter or name the independent GNU oracle.
```sh
python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-tls-relocation-runtime-matrix
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build --no-restore
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
make -C native/urprotect-launcher test
python3 scripts/check-architecture-boundaries.py
python3 scripts/check-architecture-boundaries.py --fixture tests/ArchitectureFixtures/ForbiddenStructuralDependency.cs --self-test
git diff --check
```

The runtime-specific producer commands must additionally run the five-model
positive/negative matrix and its evidence checker on native AArch64 glibc, musl,
and bionic lanes. The exact commands and retained artifact paths are added to
`fixtures/manifest.json` only with their corresponding fixture/oracle.

## Rollback points

- Structural TLS facts and diagnostics;
- typed five-model semantic IR and recognizers;
- snapshot/artifact extension contract;
- rewrite/fixup/layout integration;
- lifecycle fixtures;
- AArch64 encoding ownership and fixture/golden migration debt;
- each independent runtime matrix lane.

A failed phase is reverted or narrowed at its own boundary. No compatibility
wrapper, alternate writer, guessed relocation, or runtime fallback is added to
recover a failed phase.

## Phase 5/6 bounded evidence increment

The existing Protected Image producer evidence checker now accepts an optional
`tlsEvidence` projection. It validates the five TLS model names, profile/runtime/
lifecycle binding, source/transformed/artifact hashes, bounded PT_TLS facts,
per-thread/zero-fill/teardown observations, first-failure classification, and
publication/rollback invariants. `accepted-and-runs`,
`environment-unavailable`, and `runtime-failure` remain distinct; no result
promotes a different runtime. Existing producer stages without this optional
projection remain valid.

Verified locally:

- `python3 -m unittest discover -s tests -p 'test_*.py'` — 300 passed;
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`;
- `python3 scripts/validate-regression-matrix.py tests/regression-matrix.json`;
- `python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-tls-relocation-runtime-matrix`;
- native runtime and launcher contract tests with `CC=aarch64-linux-gnu-gcc`.

The local cell is native AArch64 with GNU cross-tooling, 4 KiB pages, no
`musl-gcc`, and no Docker/Podman. Musl and bionic transformed TLS runtime rows
remain explicit CI environment/evidence work and are not promoted locally.
