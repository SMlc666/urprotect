# Coverage-guided fuzzing implementation plan

1. Pin SharpFuzz/libFuzzer inputs and record licenses/provenance.
2. Add the fuzz project, compatibility runner, and ELF/frame target modes.
3. Build or verify the bridge and add corpus/size/time/RSS controls.
4. Add PR and nightly/release scripts with artifact retention and
   minimization.
5. Promote any finding to a minimized deterministic regression and retain the
   current random/mutation tests.

Validation:

```sh
PATH=/root/.dotnet:$PATH ./scripts/run-coverage-fuzz.sh --tier pr
PATH=/root/.dotnet:$PATH ./scripts/run-coverage-fuzz.sh --tier nightly
./scripts/run-parser-fuzz.sh
```

The new wrapper must print the exact selected engine, input corpus, seed, and
budgets before execution.
<!-- End of task artifact. -->
