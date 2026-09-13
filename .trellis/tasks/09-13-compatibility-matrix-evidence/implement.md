# Implementation Plan

## Ordered Checklist

1. [ ] Define and validate the matrix schema with feature and case records.
2. [ ] Convert the existing manifest records from profiles to cases and add
       feature references without changing fixture source behavior.
3. [ ] Rename selection arguments from --profile to --tier and update all
       project-owned scripts, README, and CI callers.
4. [ ] Rename container/package metadata to image, environment, or variant
       facts; preserve external Cargo profile syntax.
5. [ ] Add status, obligation, oracle, and evidence validation.
6. [ ] Add current legacy wrapper, current Android JNI, compiler, and parser
       cases to the matrix with honest statuses.
7. [ ] Connect new HostContext and AArch64 feature IDs from the other child
       tasks.
8. [ ] Add the native ARM64 Termux/bionic case with the pinned source commit,
       OCI image digest, linker/page-size facts, direct no-fallback checks, and
       a runtime oracle.
9. [ ] Generate a stable matrix report and CI summary.
10. [ ] Add drift checks for manifest, scripts, README, and workflow references.

## Risk and Rollback Points

- Keep a read-only compatibility reader for the old manifest during migration.
- Do not accept both old and new writable schemas in the same code path.
- Do not rewrite Cargo's external profile.release or archived task records.
- If evidence is incomplete, mark the row unknown rather than weakening the
  schema validator.

## Validation

    python3 scripts/validate-fixtures.py --tier pr
    ./scripts/run-fixture-matrix.sh --tier pr
    ./scripts/run-packed-fixture-matrix.sh --tier pr
    ./scripts/run-bionic-fixture.sh
    rg -n --glob '!third_party/**' --glob '!**/archive/**' -- '--profile|profiles'
    PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release

The final search is expected to find only external Cargo syntax or explicitly
documented migration compatibility code. The bionic lane is expected to fail
closed if it is run outside a native ARM64 Termux userspace or if its pinned
image/linker evidence is unavailable.
