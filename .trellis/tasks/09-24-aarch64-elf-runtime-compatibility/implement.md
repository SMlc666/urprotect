# Implementation plan: AArch64 ELF Compatibility and Runtime Semantics

## Execution rules

- Work one child phase at a time; do not start the parent as an implementation
  target while child deliverables are active.
- A child enters `in_progress` only after its own PRD, design, implementation
  plan, and context manifests pass review.
- Every cross-layer contract change updates managed code, native headers and
  consumers, tests, fixtures, matrix declarations, and documentation together.
- A feature remains `unknown` or `rejected` until its declared oracle and CI
  evidence pass.
- No compatibility fallback is introduced for a stale frame, launcher ABI, or
  execution profile.

## Ordered phase checklist

### Phase 0 — Converge the current packaging contract

- [ ] Create and review the P0 child task.
- [ ] Define the current frame version and explicit profile field; prefer a new
      version over reinterpreting v1/v2 offsets.
- [ ] Define profile-specific metadata and reserved-field validation for
      `outer-execveat` and `host-context-entry`.
- [ ] Define the profile/launcher ABI marker and mismatch diagnostics.
- [ ] Update managed `PayloadFrameCodec`, native `payload_frame.h`, runtime
      parser, contract probe, and layout tests from the same owner table.
- [ ] Add explicit managed pack profile selection and input validation.
- [ ] Implement the current outer profile end-to-end oracle.
- [ ] Implement the current HostContext profile end-to-end oracle using the
      existing sealed-memfd adapter and entry fixture.
- [ ] Remove implicit legacy selection and classify historical v1/v2 tests as
      migration evidence or delete them.
- [ ] Update `COMPATIBILITY.md`, `fixtures/manifest.json`, README, reports, and
      error handling for the current profile contract.

Validation gate:

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
make -C native/urprotect-runtime contract-check
native/urprotect-launcher/test_launcher.sh
native/urprotect-launcher/test_managed_handoff.sh
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 tests/test_regression_matrix.py
```

P0 also requires the managed pack/dispatch oracle on
the native AArch64 evidence host.

Rollback point: revert the frame/profile contract as one change and leave the
production-pack matrix row `unknown` until the old current behavior is restored
or a new complete oracle exists.

### Phase 1 — Expand the outer AArch64 wrapper

- [ ] Create and review the P1 child task.
- [ ] Inventory current parser and pack rejection reasons against real AArch64
      producer outputs.
- [ ] Choose one smallest new input class at a time: stripped/sectionless
      variants first, then static/different executable kinds only with a launch
      contract.
- [ ] Add positive toolchain fixtures and paired malformed/boundary fixtures.
- [ ] Extend baseline/wrapped behavior comparison for exit status, streams,
      argv, envp, signals, and relevant file observations.
- [ ] Add runtime-specific rows only for retained glibc, musl, or bionic facts.
- [ ] Run the full fixture and evidence gates for each tier.

Validation gate:

```sh
dotnet test UrProtect.sln --configuration Release
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

Rollback point: remove only the new input-class row, fixture, and acceptance
branch; preserve the P0 profile contract and existing validated rows.

### Phase 2 — Expand relocation and symbol semantics

- [ ] Create and review the P2 child task.
- [ ] Select the first relocation family from real AArch64 fixtures.
- [ ] Specify symbol lookup scope, binding, weak symbols, visibility, conflicts,
      target permissions, and failure status before implementation.
- [ ] Add managed model rules where applicable and native adapter checks at the
      HostContext boundary.
- [ ] Add positive fixtures, mutation-based negative tests, and per-family
      diagnostics.
- [ ] Validate glibc/musl/bionic separately; loader acceptance alone is not the
      acceptance oracle.
- [ ] Update the relocation feature rows and contract inventory.

Validation gate:

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-coverage-fuzz.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

Rollback point: keep the relocation family explicitly rejected and retain the
previous RELATIVE/RELR validated row if any new symbol or relocation oracle is
incomplete.

### Phase 3 — Dependencies, path search, and lifecycle

- [ ] Create and review the P3 child task.
- [ ] Define explicit dependency roots and path-search precedence.
- [ ] Define dependency graph ownership, sharing, cycle behavior, rollback, and
      release order.
- [ ] Define constructor/destructor order, reentrancy, callback failure, and
      `urp_entry`/`release_image` lifecycle.
- [ ] Implement the smallest deterministic subset and fail closed on the rest.
- [ ] Add dependency-bearing and lifecycle-bearing fixtures with teardown
      assertions and retained logs.
- [ ] Update HostContext documentation, matrix rows, and CI evidence gates.

Validation gate:

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

Rollback point: disable the new dynamic metadata subset at the adapter
boundary, retain the previous rejection rows, and remove any fixture that
depends on unspecified search or lifecycle behavior.

### Phase 4-A — AArch64 TLS

- [ ] Create and review the P4-A child task.
- [ ] Define TLS module, relocation, current-thread, new-thread, unload, and
      release ownership semantics.
- [ ] Add a real threaded fixture and deterministic concurrency oracle.
- [ ] Exercise failure and teardown paths under the supported runtime facts.
- [ ] Retain evidence separately for glibc, musl, and bionic where executed.

Validation gate:

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```

Rollback point: retain PT_TLS as an explicit rejected boundary and revert only
the incomplete positive TLS path.

### Phase 4-B — GNU property / BTI / PAC

- [ ] Create and review the P4-B child task.
- [ ] Define the bounded property-note subset and host negotiation rules.
- [ ] Define BTI/PAC instruction-state and protection obligations.
- [ ] Add property-bearing fixtures and runtime observations.
- [ ] Separate parser recognition, outer-wrapper execution, and HostContext
      acceptance in the matrix.

Validation gate:

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-fixture-matrix.sh --tier release
python3 scripts/check-evidence.py fixtures/manifest.json --tier release
```

Rollback point: retain PT_GNU_PROPERTY as a rejected HostContext feature and
keep any outer-wrapper observation in its own lower-layer row.

## Final integration gate

- [ ] All child tasks are individually checked and their artifacts archived or
      ready for archive.
- [ ] Parent PRD, design, implementation plan, runtime spec, README,
      `COMPATIBILITY.md`, and rendered matrix agree.
- [ ] `ContractInventory.md` has no duplicated current offsets or stale profile
      names.
- [ ] Full managed tests, native tests, fixture matrix, fuzz smoke, stress
      profile, manifest validation, and evidence checks pass at their declared
      tiers.
- [ ] No `unknown` matrix row is counted as support.
- [ ] The final commit contains implementation plus contract/evidence updates,
      not a planning-only status change.

## Review gates and ownership

The parent owner reviews cross-phase data flow and matrix claims. Each child
owner reviews its own feature contract and evidence. A phase may proceed only
when its predecessor's current contract is stable in the repository and its
acceptance criteria are observable. The parent remains the integration and
documentation owner throughout the roadmap.
