# Implementation plan: namespace-first responsibility boundaries

## Steps

1. Verify G0 current-contract purge is complete and freeze file ownership before moving code.
2. Add the ownership map, namespace rules, forbidden dependency check, and test ownership map.
3. Extract CLI dispatch/parsing/commands/rendering/publication/native handoff seams.
4. Extract structural validation/observation/copy publication from `NoOpPipeline`.
5. Extract shared protection request/selection/analysis planning from `FunctionProtectionService.Plan` and `.Protect`.
6. Split semantic model/snapshot/layout/frame bucket files into concept-oriented files and codecs.
7. Split pack/rehydration orchestration from policy, materialization, publication, metrics, and evidence adapters.
8. Move/rename tests to their owning layer and update project namespaces without adding compatibility test aliases.
9. Run dependency checks, build/tests, inspect the complete diff, and hand off the stable seams to G2.

## Validation

```sh
python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-responsibility-boundaries
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build --no-restore
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
git diff --check
```

The dependency check must include a deliberate forbidden-reference fixture and must pass the current production tree without relying on historical namespaces or wrappers.

## Rollback points

- Namespace/ownership map and dependency checker.
- CLI/application/infrastructure extraction.
- Protection planner extraction.
- Semantic/layout/artifact file splits.
- Test project ownership moves.

Revert a failed seam rather than adding a reverse dependency or compatibility forwarding type.
