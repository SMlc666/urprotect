# End-to-end regression implementation plan

1. Map current CLI, launcher, managed handoff, HostContext, fixture, musl,
   bionic, and Android commands to the 14 rows in
   `tests/regression-matrix.json`.
2. Reuse the focused managed and native scenarios already present for
   status/stream/identity/rejection behavior.
3. Implement the matrix validator, negative schema tests, and tier-specific
   machine-readable plan output.
4. Wire PR/nightly/release jobs and upload failure artifacts with `always()`.
5. Run the applicable local rows and verify unknown/optional compatibility
   statuses remain honest.

Validation:

```sh
python3 scripts/test-regression-matrix.py
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
make -C native/urprotect-runtime test
```
<!-- End of task artifact. -->
