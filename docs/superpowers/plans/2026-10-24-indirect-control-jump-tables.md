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
- [x] **complete: child.cross-runtime-evidence** — hosted run `40220438826`
  passed the Bionic native and musl container evidence jobs. The current
  independent checkers also pass all four fresh ordinary/shared Bionic/musl
  exact roots from that run, and the Bionic `imageDigest` matches the pinned
  image suffix. This closes only these scoped evidence rows: the same run had a
  separate runtime-matrix artifact handoff failure, tracked in Task 3, and no
  general ownership or runtime-support claim follows. Musl/Bionic are not
  promoted by glibc or checker-only results.

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
- [x] **Step 5: Re-run hosted Bionic and musl exact-root evidence**
  Against fresh run `40220438826`, the Bionic result retained its exact pinned
  image digest, both Bionic and musl workflow jobs passed, and independent
  rechecks passed the ordinary/shared exact roots for both runtimes. This is
  limited to the declared evidence rows; it does not promote general support.

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
  Construct a valid minimal AArch64 `ET_REL` ELF with a non-allocated
  `SHT_NOBITS` section (`sh_addr=0`, `sh_offset=EOF`) whose conceptual range
  extends past EOF, plus nearest negatives for an equally out-of-bounds
  file-backed section and overflowing 64-bit `sh_offset + sh_size` arithmetic.
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
- [x] **Step 6: Push and run fresh hosted cross-runtime evidence**
  Push the reviewed fix, then trigger the authorized full CI workflow and
  inspect Bionic and musl job results and exact-root artifacts. Hosted run
  `40220438826` passed the fresh Bionic shared checker (including the valid
  `SHT_NOBITS` section) and both Bionic/musl evidence jobs; independent checks
  passed all four exact roots. Keep the runtime-matrix handoff and unrelated
  failing lanes separately classified; the global quality gate did not pass.

### Task 3: Preserve the Bionic artifact root in runtime-matrix handoff

**Evidence:** The Bionic upload includes both `.artifacts/bionic/` and
`.artifacts/indirect-control/`, so `upload-artifact` stores paths relative to
`.artifacts`. The runtime-matrix job downloads that artifact into
`.artifacts/bionic`, producing `.artifacts/bionic/bionic/c-termux-bionic-pie`
while the runner expects `.artifacts/bionic/c-termux-bionic-pie`; hosted run
`40220438826` failed at this boundary after the Bionic and musl producer jobs
passed.

**Files:**
- Modify: `.github/workflows/ci.yml` (runtime-matrix artifact download destination)
- Test: `tests/test_protected_image_workflow.py` (Bionic upload/download root contract)
- Update: this plan and its execution ledger

- [x] **Step 1: Write a failing workflow-root regression test**
  Assert the Bionic artifact is downloaded by the runtime-matrix job to
  `.artifacts`, while the expected Bionic subtree remains
  `.artifacts/bionic/c-termux-bionic-pie`.
- [x] **Step 2: Run the focused test and verify the current nested-root failure**
  Run: `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_protected_image_workflow.ProtectedImageWorkflowTests.test_runtime_matrix_download_preserves_bionic_artifact_root`
  Expected: FAIL because the workflow currently downloads into
  `.artifacts/bionic`.
- [x] **Step 3: Download the artifact at its actual archive root**
  Change only the runtime-matrix download `path` to `.artifacts`; retain the
  upload layout and the runner's expected Bionic subtree.
- [x] **Step 4: Run focused and related workflow tests**
  Run the focused test, then
  `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_protected_image_workflow tests.test_runtime_matrix tests.test_ci_push_pr_dedup`.
  Expected: all tests pass with no ambient `PYTHONPATH`.
- [ ] **Step 5: Push and verify a fresh hosted runtime-matrix handoff**
  Use the authorized full CI dispatch. Expected: runtime-matrix downloads the
  Bionic tree at the expected root, runs its covering set, and its retained
  evidence checker passes. Keep unrelated fixture and real-sample failures
  separately classified; do not claim the global quality gate passed unless
  it does.

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

### CI triage from run `40220438826` (after Tasks 1–2, before Task 3)

- `bionic-native-arm64` and `musl-container-smoke` passed. The Bionic image
  digest matched the pinned image suffix, and independent current checkers
  passed all four ordinary/shared Bionic/musl exact roots.
- `runtime-matrix-native-arm64` failed during its covering set, after the
  initial musl smoke and launcher tests but before consuming the Bionic root.
  The upload contains paths rooted at `bionic/`, while the download target was
  `.artifacts/bionic`; the runner therefore could not find
  `.artifacts/bionic/c-termux-bionic-pie`. Task 3 changes only the download
  destination to `.artifacts`.
- `managed-tests` passed, so the previous FIFO completion-time failure was not
  reproduced in this run.
- `fixture-nightly` again failed only at `zig-musl`; its retained validator
  output is `TlsMetadataMalformed @0x3380`, and `readelf` shows the zero-file,
  nonzero-memory `PT_TLS` has no unique containing `PT_LOAD` with a matching
  file/virtual mapping. This remains a separate fixture-versus-parser contract
  issue, not part of Task 3.
- `real-sample-matrix` again failed to acquire the required locked Node.js
  sample: `curl` received HTTP 404. Follow-on environment/evidence-accounting
  failures are downstream; the external sample availability blocker remains.
- The overall workflow and quality gate failed for these independent lanes.
  Task 3 still requires a fresh hosted run to verify the corrected artifact
  handoff; no global green CI result is claimed.
