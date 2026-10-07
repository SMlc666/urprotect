# Implementation plan: unified current protection workflow

## Steps

1. Verify G0 current contract and G1 ownership seams; freeze the workflow input/output contracts.
2. Define typed application requests/results and one `ProtectionWorkflow` orchestration owner.
3. Extract the shared selector/pass/selected-function planning path from direct protection and producer paths.
4. Connect the semantic/protection plan to the shared `ElfLayoutPlanner`/`ElfLayoutMaterializer` without a second writer.
5. Add profile-aware materializer dispatch and complete `HostContextEntry` validation/materialization.
6. Route `protect`, `protect-image`, and `rehydrate-image` through the workflow; remove direct production writer calls.
7. Add atomic publication, profile-specific descriptors, current reports, and first-failure/evidence binding.
8. Add native HostContext rehydration/handoff oracle and current outer/HostContext positive, malformed, mismatch, and rollback cases.
9. Run G2 gates and hand stable workflow contracts to downstream TLS/CFI/indirect tasks.

## Validation

```sh
python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-unified-protection-workflow
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build --no-restore
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
make -C native/urprotect-runtime test
make -C native/urprotect-launcher test
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc --profile outer-execveat
./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc --profile host-context-entry
git diff --check
```

HostContext materialization must have native AArch64 evidence. Musl/bionic evidence is separate and cannot be substituted for the HostContext glibc handoff claim.

## Rollback points

- Typed workflow seam.
- Shared planner/materializer integration.
- HostContext profile materializer and native handoff.
- CLI route deletion/direct-writer removal.
- Publication/report/evidence convergence.

Revert a failed stage; never restore a direct writer or compatibility path.
