# Indirect Control and Jump-Table Work Plan

**Status:** in progress; migrated from the active child workstream on 2026-10-24.

## Goal

Resolve bounded indirect targets and ambiguous jump tables with checked source
proofs, address-map-aware layout, fail-closed publication, and measured runtime
evidence. Analysis is selected-function-rooted and table queries are bounded
and demand-driven.

## Scope already completed (scoped claims only)

- Structural ELF validation is decoder-independent by default; protection
  begins at explicit selected functions and uses the common semantic/layout
  pipeline.
- A signed-relative-32 private-table row exercises indices 0–3 and binds each
  entry to its target and output mapping.
- The controlled same-image static callback, imported `GLOB_DAT`/`getpid`,
  read-only shared-table clone, and scoped external-provider consumer slices
  have managed and/or native AArch64/glibc evidence as recorded in the
  [runtime compatibility contract](../../engineering/specs/backend/runtime-compatibility.md).
- Managed `Ambiguous` fallback exists only for the bounded in-image signed-32
  table with the exact selected ADRP/ADD reference when no validated extra-owner
  pair is available. It clones to a distinct `PF_R` range, retargets the
  selected consumer, and preserves the original and unselected/unknown refs.
  This does not infer private ownership or establish runtime support.
- Runtime identity evidence checkers enforce unique file-backed and page-rounded
  `p_memsz` `PT_LOAD` ownership. With known bias, wrong-VA candidates are skipped
  before permission filtering; address-matching incompatible owners and
  duplicate owners reject.

## Acceptance state

- [x] **complete: child.ambiguous-safe-default** — the narrow managed
  `Ambiguous` clone-and-retarget policy and rehydration rederivation tests pass
  for the exact signed-32 table/reference family; no broader ownership or
  runtime claim follows.
- [ ] **open: child.general-ownership** — complete consumer-owner enumeration
  and private-versus-shared inference beyond a validated additional-owner pair
  are not established. Also unproven are other table encodings/instruction
  chains, fully symbol-less selection, native metadata-missing variants, and
  general indirect-call or runtime target-translation behavior. Absence of an
  observed extra owner does not prove privacy.
- [ ] **open: child.cross-runtime-evidence** — scoped AArch64/glibc rows do not
  cover the declared cross-runtime matrix. In hosted run `40216643128`, the
  repaired Bionic result JSON's `imageDigest` matched its pinned Termux image;
  the Bionic ordinary exact-root checker and musl ordinary/shared exact-root
  checkers passed. Bionic shared-table production and runtime behavior also
  passed, but its independent checker rejected the valid `.relro_padding`
  `SHT_NOBITS` section because `sh_offset + sh_size` extends past the ELF file
  (the section has no file-backed bytes). The corrected checker now passes all
  four retained ordinary/shared Bionic/musl roots locally; rerun hosted evidence
  before closing this criterion. Musl/Bionic are not promoted by glibc or
  checker-only results.

## Evidence facts and non-promotion constraints

- The ordinary signed-relative-32 jump-table row passed identity-required
  exact-root checks in post-merge hosted run `39864478180`. This is a scoped
  observation only, not runtime/feature promotion; it does not close the
  cross-runtime criterion above.
- The external-provider feature stays `unknown` and
  `scoped-observation-not-promoted`. Hosted provider producer/checker/root-bound
  runs `39559228628` (PR #25) and `39561529902` (merged main) passed their
  declared gates. They do not establish branch-protection mapping or general
  runtime support.
- Current preserved local provider positive-root checking fails with
  `retained build provenance tar has an unexpected member count`; current local
  rollback-root checking fails because
  `evidence-tools/run-external-provider-rollback-oracle.sh` is absent. Do not
  rewrite or regenerate those roots to hide the discrepancy. A future exact-root
  pass must use newly produced, run-specific artifacts and current checkers.
- Historical task/evidence archives remain in Git history, not as current
  acceptance state.

## Implementation and verification approach

1. Read [engineering specifications](../../engineering/specs/README.md), the
   [quality/safety contract](../../engineering/specs/backend/quality-guidelines.md),
   and the [runtime identity rules](../../engineering/specs/backend/runtime-compatibility.md)
   before touching a layer.
2. Use test-first changes: add the nearest regression and show it fails for the
   intended reason; implement the smallest fix; run focused tests, then relevant
   broader suites and independent evidence checks.
3. Keep changes to one owner boundary at a time. Never use a missing owner,
   stale root, checksum closure, fixture presence, or one runtime as evidence
   for a different claim.
4. Before closing either open criterion, get a fresh independent review of the
   source-derived checker and newly produced exact-root evidence. Report local
   and hosted results separately.

## Relevant verification commands

```sh
python3 -m unittest tests.test_shared_jump_table_evidence tests.test_rehydration_evidence
python3 tests/test_regression_matrix.py
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-runtime-matrix-evidence.py
```

Runtime producers require native AArch64 toolchains and must use unique evidence
roots. Do not substitute emulation, glibc for musl/Bionic, or historical roots
for a fresh required execution.

### Task 1: Bionic runtime image digest provenance

**Files:**
- Modify: `scripts/run-bionic-fixture.sh` (runtime result JSON producer)
- Test: `tests/test_bionic_artifact_permissions.py` (execute the actual embedded JSON emitter)
- Update: this plan's cross-runtime evidence state

**Interfaces:**
- Consumes the pinned `image` argument already passed to the runtime result producer.
- Produces `result.json.imageDigest`, exactly the digest suffix after `@` in `result.json.image`.

- [x] **Step 1: Write a failing producer-output regression test**
  Execute the Python emitter embedded in `run-bionic-fixture.sh` with a pinned
  image digest and controlled package-lock/fixture inputs; assert that the
  emitted JSON retains the image and its exact `imageDigest`.
- [x] **Step 2: Run the focused test and verify the expected missing-field failure**
  Run: `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bionic_artifact_permissions.BionicArtifactPermissionTests.test_fixture_result_reports_locked_image_digest`
  Expected: FAIL because the emitted JSON is missing `imageDigest`.
- [x] **Step 3: Add the exact image digest to the producer JSON**
  Derive it from the already pinned `image` input; do not invent a second source of truth.
- [x] **Step 4: Run focused and full Python evidence tests**
  Run the focused test, then `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bionic_artifact_permissions tests.test_rehydration_evidence`.
  Expected: both commands pass.
- [ ] **Step 5: Re-run hosted Bionic and musl exact-root evidence**
  Validate only fresh run-specific artifacts with the current independent checkers;
  leave `child.cross-runtime-evidence` open unless all declared rows pass. Run
  `40216643128` proved the producer fix and Bionic ordinary/musl rows; the
  patched checker subsequently accepted all four retained roots locally.

### Task 2: Respect valid SHT_NOBITS section ranges in the shared checker

**Files:**
- Modify: `scripts/check-shared-jump-table-evidence.py` (`parse_elf` section bounds)
- Test: `tests/test_shared_jump_table_evidence.py` (bounded synthetic ELF regressions)
- Update: this plan and its execution ledger

**Interfaces:**
- Consumes bounded ELF section headers for the independent shared-table checker.
- Produces validated section facts without treating `SHT_NOBITS` as file-backed;
  all other section payloads remain bounded by the ELF bytes.

- [x] **Step 1: Add parser boundary tests**
  Construct a minimal bounded AArch64 ELF containing an `SHT_NOBITS` section
  whose conceptual range extends past EOF, plus nearest negatives for an
  equally out-of-bounds file-backed section and overflowing 64-bit
  `sh_offset + sh_size` arithmetic.
- [x] **Step 2: Run the focused tests and verify the intended failure**
  Run: `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_shared_jump_table_evidence.SharedJumpTableEvidenceTests.test_nobits_section_range_is_not_required_to_be_file_backed`
  Expected before the fix: the valid `SHT_NOBITS` case failed with
  `synthetic ELF has an out-of-bounds section`; the overflow negative also
  lacked its checked-add diagnostic.
- [x] **Step 3: Correct only the section backing rule**
  Permit non-file-backed `SHT_NOBITS` conceptual ranges after checked unsigned
  64-bit offset-plus-size arithmetic. Keep file bounds mandatory for every
  other section type and retain the existing virtual-range overflow check.
- [x] **Step 4: Run focused and related local verification**
  Run the focused regression, then
  `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_shared_jump_table_evidence tests.test_rehydration_evidence`.
  Expected: every test passes without ambient `PYTHONPATH`.
- [x] **Step 5: Recheck retained hosted artifacts with the corrected checker**
  Against run `40216643128`, independently check Bionic ordinary/shared and
  musl ordinary/shared evidence roots. Expected: all four root checks pass;
  the Bionic image digest remains bound to the pinned image.
- [ ] **Step 6: Push and run fresh hosted cross-runtime evidence**
  Push the reviewed fix, then trigger the authorized full CI workflow and
  inspect Bionic and musl job results and exact-root artifacts. Expected: the
  fresh Bionic shared independent checker accepts the valid `SHT_NOBITS`
  section and both hosted runtime rows pass. Keep unrelated failing CI lanes
  separately classified; do not claim the global quality gate passed unless it
  did.

### CI triage from run `40216643128` (before Task 2 fix)

- Bionic native ARM64 reached the shared Bionic exact-root checker and failed
  only on the source ELF's valid `SHT_NOBITS` section boundary; Task 2 now passes
  all four retained Bionic/musl ordinary/shared roots locally.
- `managed-tests` reported one failure:
  `LinuxSafeFileInputTests.RejectsFifoPromptlyWithoutAnExternalWriter` exceeded
  its 2-second completion assertion. Three isolated local AArch64 runs passed;
  treat this as unresolved timing sensitivity until the fresh full suite passes.
- `fixture-nightly` failed on required `zig-musl`: the produced ELF has an
  ownerless `PT_TLS` with `p_filesz=0`, nonzero `p_vaddr`, and nonzero `p_memsz`.
  The current managed parser has an explicit negative test for ownerless
  zero-file TLS with nonzero virtual address. Do not weaken that parser contract
  as part of Task 2; resolve the fixture-versus-contract question separately.
- `real-sample-matrix` could not acquire the locked Node.js sample (HTTP 404);
  the subsequent environment-unavailable/evidence-accounting errors are
  downstream consequences. This is the known external sample availability
  blocker, not a Task 1/2 regression.
- The global quality gate consequently remained failed. Fresh hosted evidence
  and a full-suite rerun are still required; these lane findings are not proof
  that the checker-only fix caused or resolved them.
