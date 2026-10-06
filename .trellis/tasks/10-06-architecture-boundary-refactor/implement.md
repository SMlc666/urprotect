# Implementation plan: architecture boundary refactor and current-contract purge

## Execution gates

This task is a prerequisite for production implementation in the TLS, CFI/unwind, indirect-control/jump-table, and final workflow tasks. Do not start those feature implementations until Gates G0-G2 below pass and the parent task records the dependency.

Each phase is a separately reviewable commit boundary. No compatibility alias, fallback implementation, historical fixture, or alternate production path may be introduced to make a phase pass.

## G0 — Freeze and purge the current contract

1. Create a current-contract inventory covering the canonical CLI grammar, managed APIs, current Payload Frame v3/profile contract, current Protected Image artifact contract, HostContext ABI, reports, evidence rows, and workflow owners.
2. Remove all production API compatibility surfaces:
   - `Aarch64Analyzer` wrapper;
   - Boolean `analyzeInstructions` overloads;
   - `--no-analysis` and every protected-image option alias;
   - duplicate snapshot operation aliases where one canonical operation is sufficient;
   - any obsolete public forwarding names.
3. Make the current managed codec v3-only. Delete v1/v2 constants, encoders, decoders, wrapper discovery branches, and legacy host projection. Keep one current version/profile validator and one current encoder/decoder path.
4. Make native launcher/runtime v3-only. Delete v1/v2 header constants, parser branches, migration adapter projections, v1/v2 self-test construction, and `--adapter-v2` or equivalent test targets.
5. Delete all v1/v2 and other historical migration-format test data, positive or negative, from managed tests, native self-tests, fixture manifests, compatibility reports, task evidence, and current evidence checkers. Do not replace it with a historical decoder or format-specific rejection fixture. Retain only current-contract tests and generic malformed-input tests.
6. Remove the direct `FunctionProtectionService.Protect` production route only after the current workflow seam exists in G2; before then, mark the call sites and freeze new use.
7. Reconcile current documentation/specs so retired behavior is described as absent, not as migration evidence or an available historical path.

**G0 gate:** repository-wide search finds no reachable retired alias/version/fallback path, current manifests contain only current rows, and current managed/native contract tests pass.

## G1 — Establish namespace-first ownership boundaries

1. Define explicit directories/namespaces and `internal` contracts for:
   - `StructuralElf` / structural models and parser;
   - `Aarch64Semantics` / decoder adapter and selected-function analysis;
   - `SemanticPlanning` / rewrite and protection plans;
   - `ElfLayout` / contracts, planning, materialization, and output validation;
   - `ArtifactProtocol` / current frame and Protected Image contracts;
   - `Application` / use-case requests and workflow results;
   - `Infrastructure` / filesystem, publication, reports/evidence, metrics, and native handoff;
   - `Cli` / parsing, commands, rendering, and process entry.
2. Move or split central files without changing behavior beyond the G0 current-contract purge:
   - split `CliApplication` into dispatch, command parsers/handlers, output/report writing, atomic file writing, and embedded launcher adapter;
   - split `NoOpPipeline` into structural validation, explicit observation, and identity-copy publication;
   - split `SemanticModel` into concept-oriented model files and move plan-building validation out of the model catalog;
   - split `SemanticPlanSnapshot` into model, canonicalizer, encoder, decoder, and extension-codec seams;
   - split `ElfLayout` into contracts, planner, materializer, validation, and evidence files;
   - split `PayloadFrame` into current contracts, encoder/decoder, compression, and wrapper/trailer handling;
   - split `ElfPackService`, `FunctionProtectionService`, and `GenericRehydrationEngine` around policy/planning/materialization/publication/evidence responsibilities.
3. Add dependency checks or compile-time `internal` seams that prohibit domain/semantic/layout code from depending on CLI, filesystem, process, or native handoff details.
4. Keep the number of assemblies unchanged unless a concrete invalid dependency cannot be prevented inside the current project. Record any assembly split and its forbidden dependency in the contract inventory.
5. Split tests by ownership: structural/core, CLI/application, integration/workflow, artifact/protocol, and native contract; move cross-layer tests to the integration owner rather than hiding them in Core tests.

**G1 gate:** each extracted boundary has one reason to change, dependency checks pass, no duplicate model/codec/writer exists, and the full managed suite remains green.

## G2 — Build one current workflow and complete HostContext materialization

1. Define the current application workflow interfaces and typed requests/results for validation, pack, protect, protected-image production, and rehydration.
2. Extract one shared protection planning operation:
   - canonical selectors and passes;
   - structural source index;
   - selected-function analysis;
   - semantic rewrite/protection plan;
   - deterministic diagnostics.
3. Extract one shared physical materialization operation:
   - `SemanticRewritePlan`/`ProtectionPlan` to `ElfLayoutPlan`;
   - profile-independent placement/edit validation;
   - profile-specific image invariants;
   - reparsing and output identity checks;
   - atomic publication.
4. Route `protect`, `protect-image`, and `rehydrate-image` through the same planning/materialization owners. `protect` becomes a facade that publishes the final image; staged commands expose the same current intermediate contract. Delete the old direct writer once all callers use the shared workflow.
5. Implement the `HostContextEntry` materializer as a first-class profile path:
   - validate the source/output as the current HostContext entry-image class (`ET_DYN`, AArch64, no process interpreter, bounded declared entry symbol, executable entry mapping, and the current native preflight subset);
   - consume the same current Protected Image operation stream and semantic/layout plans as `OuterExecveat`;
   - preserve or rewrite program headers, dynamic metadata, TLS/RELRO/STACK/PROPERTY/NOTE facts through the common layout planner;
   - emit a valid HostContext native image and profile-bound descriptor without invoking the outer `execveat` materializer;
   - bind the current v3 HostContext frame metadata, entry symbol, capabilities, and source/artifact digests before publication;
   - invoke the native HostContext handoff oracle against the rehydrated image and retain status, release-order, loader, and hash evidence.
6. Make profile-specific failures occur before any output/evidence publication. HostContext materialization must not be represented by a generic late `RehydrationLayoutUnavailable` branch.
7. Add current positive, nearest malformed, profile mismatch, and rollback tests for both profiles. Do not add retired-format fixtures.

**G2 gate:** all three commands share the same current workflow, direct writer is gone from production routing, both current profiles complete materialization and validation, and native outer/HostContext oracles pass independently.

## G3 — Contract and evidence convergence

1. Update current CLI help, reports, contract inventory, README, compatibility spec, native README, fixture manifest, runtime matrix, and evidence checkers to describe only current behavior.
2. Remove migration/fallback wording from parent and child plans; record G0-G2 as hard prerequisites for TLS, CFI, indirect-control, and runtime-promotion work.
3. Add static checks for:
   - retired alias names and old frame constants absent from production and current test/evidence data;
   - one workflow owner per command;
   - no domain-to-infrastructure dependency inversion;
   - HostContext profile not accepted by an ownerless path;
   - no partial artifact/evidence publication on failure.
4. Run the full final validation matrix and retain exact commands/results in the task record.

## Validation commands

### Static and managed

```sh
python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-architecture-boundary-refactor
git grep -n -E -- 'Aarch64Analyzer|analyzeInstructions|--no-analysis|URP_FRAME_VERSION_V1|URP_FRAME_VERSION_V2|TryEncodeHostContext|TryEncode\(' src native tests fixtures scripts README.md COMPATIBILITY.md .trellis/spec .trellis/tasks
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet restore UrProtect.sln --locked-mode
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build --no-restore
```

The grep is an absence check after purge; its expected result must be empty or contain only explicitly approved current symbols/documentation. No historical fixture data may be added to satisfy it.

### Contract and repository checks

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
make -C native/urprotect-runtime test
make -C native/urprotect-launcher test
scripts/check-evidence.py fixtures/manifest.json --tier pr --execution native-linux

git diff --check
```

### Runtime/evidence gates

```sh
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
./scripts/run-protection-e2e.sh --tier pr --runtime musl
./scripts/run-protection-e2e.sh --tier pr --runtime bionic
./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc --profile outer-execveat
./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc --profile host-context-entry
./scripts/run-rehydration-e2e.sh --tier pr --runtime musl --profile outer-execveat
./scripts/run-rehydration-e2e.sh --tier pr --runtime bionic --profile outer-execveat
./scripts/check-runtime-matrix-evidence.py pr .artifacts/runtime-matrix/pr .artifacts/bionic/c-termux-bionic-pie
```

The HostContext rehydration command/oracle is a new current workflow gate owned by this task. It must run on native AArch64 glibc for the HostContext row; musl/bionic rows are separate and are not promoted from glibc observations.

## Risky files and rollback points

- `src/UrProtect.Core/Pack/PayloadFrame.cs` and native frame/runtime headers: current wire contract; managed/native changes must land together.
- `src/UrProtect.Core/Protect/FunctionProtectionService.cs`, `ProtectionPlan.cs`, and `ProtectedImageV1.cs`: shared workflow/artifact ownership.
- `src/UrProtect.Core/Rehydrate/GenericRehydrationEngine.cs`: profile-specific materialization and publication boundary.
- `src/UrProtect.Cli/CliApplication.cs`: public CLI grammar and command routing.
- `native/urprotect-runtime/runtime.c`, `host_context_launcher.c`, and self-tests: HostContext handoff and current frame parsing.
- `fixtures/manifest.json`, compatibility specs, and evidence scripts: current support claims.

Rollback is by reverting the specific committed slice. Do not reintroduce old paths to recover a failed slice; fix forward or revert the whole slice.

## Final review gates before task start

- PRD has no unresolved product decision.
- Design and implementation plan agree that the task implements the HostContext materialization path and deletes all historical migration data.
- Parent and remaining child plans explicitly depend on this task's G0-G2 gates.
- `implement.jsonl` and `check.jsonl` contain real spec/research entries.
- The final planning summary is presented to the user; implementation starts only after a subsequent explicit approval and `task.py start`.
