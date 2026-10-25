# Current-source jump-table ownership and runtime-lane audit

**Task:** `.trellis/tasks/10-06-indirect-control-jump-tables`
**Audited source:** `e281a94` (`feat/indirect-control-runtime-evidence`), after PR25 integration
**Purpose:** answer the PRD's open ownership-policy question from current production source/tests, separate bounded accepted behavior from unsupported families, and define the next native glibc/musl/Bionic evidence slice.
**Disposition at audit time:** audit and task-documentation only. The audit itself changed no product code, evidence root, manifest, CI, PRD checkbox, task status, journal, or existing divergence investigation.

## Follow-up implementation checkpoint: one ordinary musl row (2026-10-21)

A separately reviewed bounded slice now wires the ordinary signed-relative-32 table row through runner-only `--runtime musl` selection, a dedicated `build/musl-indirect-control` helper/fixture build, native process identity retention/verification, and the existing pinned `musl-container-smoke` job. Its distinct unit is `runtime.indirect-control.jump-table.musl.host-context-entry`. This is producer/checker/CI wiring, not an observed native run: this local environment lacks `musl-gcc` and Docker, and the hosted exact-root result remains pending. No fixture registry claim or PRD acceptance checkbox has been promoted. Fresh ordinary glibc evidence also requires the native identity carrier; historical glibc roots remain readable in default checker mode. The full six-identity ordinary/shared matrix is still open: the glibc pair exists, the ordinary musl row is wired but not yet observed, and shared musl plus both Bionic rows remain future slices. The shared runner/checker, provider path, resolver/publication admission, Bionic path, protected journal, and divergence investigation are unchanged.

## Executive result

The current product does **not** establish a complete inventory of every consumer of a table. It has deliberately implemented a conservative policy for one narrow, demand-driven family: a bounded **in-image, signed-relative-32** AArch64 switch table reached by the selected function through the compiler-shaped `ADRP / ADD / LDRSW / ADR / ADD / BR` chain and a proven `CMP / B.HI` index guard. For this family, incomplete owner evidence is not a rejection and is not mislabeled as private: the semantic plan records `Ambiguous`, `OwnerInventoryComplete=false`, copies the table to a distinct read-only (`PF_R`) output range, and retargets the selected consumer only. When an additional consumer is positively proven by a section-linked relocation pair, the table is recorded `Shared` and the same safe copy/retarget policy applies. The original table remains byte-identical, so unselected and unknown consumers retain their original reference.

The source-level contract, tamper regressions, source rederivation at Native Image publication, and current native-glibc ordinary/shared rows make that bounded family substantially fulfilled. They do **not** close the PRD's broader ownership policy for all table/owner families, prove an exhaustive owner inventory, or promote musl/Bionic table execution. The glibc-only external-provider observation is a separate, pinned `dlmopen` path. Its hosted producer/checker and root-bound tests were observed passing on PR #25 run `39559228628` and merged-main run `39561529902`; its feature row nevertheless remains `unknown` / `scoped-observation-not-promoted` pending final documentation/registry review. These hosted observations do not establish arbitrary external-table or cross-runtime support.

## Production source contract and proof boundary

### Resolver and accepted shape

`src/UrProtect.Core/Aarch64Semantics/Aarch64JumpTableResolver.cs` is demand-driven from the selected function. Its promoted switch resolver recognizes the checked index and relative dispatch sequence, not arbitrary `BR` instructions. It requires the signed 32-bit indexed load (`LDRSW`), fixed scale of one, a lower bound of zero, a bounded range/table size, two selected table-base producers, and the default target in the decoded selected-function closure. It computes each target by adding the signed table entry to the decoded target-base address. Every entry must be file-backed through the load map, resolve without overflow, land aligned in an executable `PT_LOAD`, and identify an instruction inside the selected function. The code also rejects architectural W/X index aliases or writes that invalidate the guard, including producer-chain clobbers after the table load. The configured maximum is an implementation safety bound, not a claim that every table up to that size has production fixture coverage.

These constraints are real admission boundaries. A table with non-zero lower bound, another width/encoding/scale/addend, an unproved default or index, an invalid entry, a cross-function target, or unsupported dispatch chain does not become supported by the existence of a `BR`; the producer fails with `IndirectTargetUnresolved` before Protected Image publication. Ordinary indirect `BLR` admission is separate and remains fail-closed except for separately typed bounded modes.

### Ownership policy: what is classified and what is preserved

`SemanticJumpTableOwnership` is a stable semantic wire contract, but enum availability is not an implementation claim. The current in-image producer emits only:

- **`Shared`** when at least one additional consumer has a positively checked section-linked `ADRP`/`ADD` relocation pair to the table, with `SHT_RELA.sh_info`, the owning function section/range and relocation sites validated against the source ELF; or
- **`Ambiguous`** when such positive additional-owner evidence is absent or incomplete.

The producer sets `OwnerInventoryComplete=false`. It does not scan every executable function or claim that its recorded relocation rows are exhaustive. A global/default-visible object symbol, missing/stripped metadata, or absence of discovered relocation rows proves neither private, external, nor runtime ownership. It cannot claim `SelectedFunctionPrivate` merely because no additional owner was found. For the current bounded in-image table family, the safe fallback is instead `Ambiguous` plus copy-and-retarget.

The layout request and publication validator accept only the current signed-32, `Shared`/`Ambiguous`, two-selected-reference-producer, distinct-output-range contract. They require a clone of exactly the source table's extent with `PF_R` permissions, per-entry mapped target/base bindings, and a retargeted selected reference. The layout/materializer preserves the source table; it does not rewrite it in place. For the established shared fixture, `urp_entry` reads the clone while the unselected `urp_observer` still reads the unchanged source table. That is the proved scope; the `Ambiguous` policy is safe because of preservation, not because the system knows every unknown consumer.

### Source rederivation and publication

The ownership facts are not accepted solely because the Protected Image snapshot says so. On rehydration, `GenericRehydrationEngine` reparses the supplied Source Image, reanalyzes the selected function and table expression, and compares the rederived table bounds, entries, target base, selected source reference producers, ownership classification and carried owner facts against the snapshot before Native Image publication. The selected source chain and section-linked owner facts are cross-checked against source sections, symbol identities and RELA rows. The planner/materializer then validates distinct clone placement, file-backed output mapping, permissions, entry bindings and final emitted references. Failures leave no Native Image or loader handoff.

This rederivation path is tested by refreshed-snapshot/artifact tampering cases for missing/forged owner evidence, selected producer-site substitution, mismatched self-reported owner sections, changed source references, and layout/materialization range or mapping failures. It is a fulfilled property of the bounded family, not a universal guarantee for currently unsupported formats.

## Current-source production tests and retained feature rows

Relevant tests read and exercised include:

- `tests/UrProtect.Core.Tests/Application/FunctionProtectionTests.cs`: bounded relative table acceptance and snapshot path; checked-index/W-X alias clobber and malformed/out-of-closure/out-of-executable-target negatives; ordinary indirect call remains fail-closed.
- `tests/UrProtect.Core.Tests/Integration/SharedJumpTableOwnerWorkflowTests.cs`: exact source function/section facts, observed shared owner, global-visible selected-only and stripped/incomplete-owner cases staying ambiguous and using the clone, conflicting selected relocations failing before publication, and rehydration rejection of omitted/forged owner or selected reference facts.
- `tests/UrProtect.Core.Tests/Layout/ElfLayoutTests.cs` and `tests/UrProtect.Core.Tests/Integration/GenericRehydrationWorkflowTests.cs`: distinct read-only clone, output range/address-map bindings, final source reparse, and pre-publication mapping/range failures.
- `scripts/check-indirect-control-evidence.py`, `scripts/check-shared-jump-table-evidence.py`, `tests/test_rehydration_evidence.py`, and their runner-produced artifacts: byte-derived target/source/output facts, actual selected/observer source and transformed handoffs, and refreshed-manifest tamper rejection.

The ordinary registry feature ID is `runtime.indirect-control.jump-table.glibc.host-context-entry`. The shared fixture registry feature ID is `runtime.indirect-control.shared-jump-table-copy.glibc.host-context-entry`; its evidence-unit/runner ID is separately `runtime.indirect-control.shared-table.glibc.host-context-entry`. Both are validated, scoped glibc rows. `fixtures/manifest.json` and `tests/regression-matrix.json` keep their assertions narrow: the ordinary row covers the four signed-relative entries and negative producer boundaries; the shared row covers one controlled selected/unselected pair. The `protection-and-tls` CI lane explicitly invokes the ordinary and shared table E2Es on its native AArch64/glibc runner. These are stronger than fixture-presence or byte-inequality claims: they exercise source and transformed HostContext behavior and independent checks.

The separate `runtime.indirect-control.external-provider.glibc.host-context-entry` row is still `unknown`. The single provider positive in current task artifacts is an exact, self-contained provider/consumer with trusted SONAME/build-ID/SHA pins and an isolated glibc `dlmopen` namespace. Its publication and source-loader rollback work do not turn arbitrary imported tables into accepted in-image tables and do not imply a musl or Bionic provider.

## Explicitly unsupported or unpromoted cases

| Family / claim | Current disposition |
|---|---|
| Bounded in-image signed-relative-32 switch table, exact recognized sequence, valid selected closure | **Supported within the stated pattern.** Both incomplete-owner/`Ambiguous` preservation and observed-shared clone-and-retarget cases have managed tests; native behavior evidence is glibc-only. |
| Exhaustive owner inventory; private-vs-shared certainty from absence of references | **Unsupported.** `OwnerInventoryComplete` is false; absence of a discovered owner is never a proof of privacy. The current ambiguous safe-copy fallback is narrower than a general inventory policy. |
| Unique/private in-place table rewrite; `SelectedFunctionPrivate` production path | **Not implemented/claimed.** The enum is retained as a schema value, but snapshot/layout admission rejects that current rewrite class. |
| Absolute/pointer tables, 8/16/64-bit or other relative widths, different scales/addends, arbitrary compiler shapes, nonzero lower bounds, unknown default/CFG or cross-function table targets | **Unsupported by this producer.** The fixed recognized family and closure checks fail closed; no adaptation/veneer policy is provided for these tables. |
| Arbitrary indirect branch/call or function-pointer table; imported table with no verified provider contract | **Unsupported.** `BR`/`BLR` alone is not admitted; the existing negative imported-table case records an actual producer failure. Separate static-local-function-pointer and imported-call rows do not broaden table support. |
| External/runtime-owned table classification in the generic in-image table extension | **Not implemented as a generic owner mode.** Stable enum ordinals do not create an admission path. The one separate provider extension is explicitly pinned and glibc-only, with its registry row still unknown. |
| Musl or Bionic table clone/selected/unselected transformed execution | **No validated evidence row today.** The ordinary musl producer/checker path is now wired into its pinned job, but no fresh hosted exact-root result has been observed; shared-musl and both Bionic rows remain unwired. Existing runtime/protection lanes alone do not establish table behavior. |
| All three runtime rows and final general indirect-control report | **Open PRD criteria.** Do not mark complete based on glibc evidence or parser/runtime smoke tests. |

## Baseline runtime lanes before ordinary-musl wiring: what they proved and the exact gap

| Runtime lane | Existing planned/production path | Why it is not a jump-table row yet |
|---|---|---|
| **glibc** | `.github/workflows/ci.yml` `protection-and-tls` runs `scripts/run-indirect-control-e2e.sh` and `scripts/run-shared-jump-table-copy-e2e.sh`, then independent ordinary/shared checkers. Both use `run-host-context-rehydration-e2e.sh --runtime glibc`. | This is the only runtime whose current rows execute and independently check selected-table and observer behavior. Keep its existing fresh-root discipline. |
| **musl** | At the baseline audit, required `musl-container-smoke` was a native AArch64 Linux container with pinned `musl=1.2.3-1`, `musl-dev` and `musl-tools`; `run-musl-container-smoke.sh` exercised a simple C PIE via direct execution and `urprotect validate --copy`. `run-protection-e2e.sh --runtime musl` also covered its existing basic protection fixture. The broader runtime-matrix's source-built musl 1.2.4 / Alpine 1.2.5 cells are nightly/release, and use simple `probe.c` parser-copy fixtures. | Before the follow-up, no lane built the jump-table HostContext assembly fixture with musl or validated native identity. The current ordinary-musl producer/checker is now wired into this job, but must still execute and pass the fresh exact-root checker; the PR runtime-matrix tier itself still has no musl cell. It is not valid to infer table support from a basic musl smoke or a glibc table row. |
| **Bionic** | `bionic-native-arm64` runs on native Ubuntu ARM64 with a native `linux/arm64` Docker server, a digest-pinned Termux image/source commit, and an eight-package version/SHA-locked Clang/LLD closure (`clang`/`lld` 21.1.8-3 in the current lock). The Android runtime is explicitly false; no emulator/Waydroid fallback is allowed. `/system/bin/linker64` is checked. `BIONIC_PROTECTION_E2E` protects `urp_transform_target` with register permutation; the HostContext check builds/runs a basic `host-context-entry-fixture.so`. | Neither existing positive is a table dispatch/clone/observer test: one is simple function protection, the other a HostContext adapter smoke. Add the table fixture through the same pinned Bionic build/container and native handoff boundary. Preserve Bionic's section/relocation constraints and exact linker identity; a Bionic-labelled ELF or a baseline loader pass alone is insufficient. |

The baseline audit found that the ordinary runner and HostContext runner hardcoded glibc. The reviewed follow-up now provides explicit glibc/musl runner selection for the ordinary row and an isolated musl build directory; the shared-table runner still intentionally invokes the HostContext runner as glibc, and no Bionic table dispatch was added. Do not infer completion from the command surface: the musl fixture must still run in the pinned job and its exact-root check must pass before a musl evidence claim can be considered.

## Remaining runtime slices after ordinary-musl wiring

Keep semantic admission fixed to the already implemented signed-32 family. Remaining work is runtime execution/evidence integration, not a resolver broadening. The complete matrix is six total row identities (ordinary + shared for each runtime); the two glibc rows are established, and ordinary musl is now wired but awaits a fresh pinned-host result. After that result, the remaining rows are shared musl and ordinary/shared Bionic. Retain separate, empty roots; never copy/relabel a glibc root as musl/Bionic.

### 1. Runner/checker and build prerequisites

1. **Remaining runner scope:** add runtime-specific shared-table execution and the separate pinned Bionic table path in later slices. Keep the current ordinary path limited to glibc/musl. Reject unsupported host/runtime combinations; never fall back from a missing loader or toolchain. Continue using runtime-isolated build directories.
2. **Remaining checker scope:** extend shared-table evidence only in its own slice. The ordinary and rehydration checkers now validate the optional native identity carrier when present; fresh ordinary glibc invokes them with `--require-runtime-identity`, and musl always requires it. Preserve source ELF, final Native Image, mapping, clone bytes/permissions, selected dispatch semantics, observer, status, release, stdout/stderr, and closed-root validation.
3. **Musl ordinary row:** run the wired producer inside the existing native AArch64 `musl-container-smoke` job/container. The runner uses the installed pinned musl toolchain (`CC=musl-gcc`; never host-glibc defaults), captures exact musl version and mapped loader/libc identity, executes source and rehydrated images in that environment, and invokes exact-root checkers. The PR row uses the existing musl 1.2.3 container; source-built 1.2.4/Alpine 1.2.5 runtime-matrix cells may add extended evidence but do not replace this transformed HostContext row. The hosted fresh exact-root run remains the gate.
4. **Bionic lane:** extend `run-bionic-fixture.sh` with a dedicated table E2E hook or create a wrapper that consumes the existing eight-package/image/source lock and writes a separate feature evidence root. Compile inside the pinned Termux container with its Clang/LLD, preserve real section headers and section-linked relocation facts, disable unsupported packed RELR for these fixtures (`--pack-dyn-relocs=none`), retain `/system/bin/linker64` and `android_runtime=false`, and run source/Native Image through the same Bionic HostContext `dlopen(/proc/self/fd/...)` adapter. Any unsupported Bionic fixture layout is an explicit failed/unavailable row, not a substitute glibc execution.
5. Keep each row's command, source/toolchain identity, source/Protected/Native Image hashes, loader identity, actual handoff records, per-process and entry statuses, stdout/stderr bytes/hashes, layout evidence, table/owner facts, and checker result in a fresh closed root. Use the normal Release CLI/GenericRehydrationEngine path; a successful `protect` call, parser copy, or native self-test alone is not the observation.

### 2. Command templates

Current **glibc ordinary** commands require identity for fresh evidence (run with fresh roots on the native AArch64/glibc lane):

```bash
RUN=.artifacts/indirect-control/three-runtime-<run-id>
./scripts/run-indirect-control-e2e.sh --tier pr \
  --unit runtime.indirect-control.jump-table.glibc.host-context-entry \
  --artifact-root "$RUN/glibc/jump-table"
python3 scripts/check-indirect-control-evidence.py "$RUN/glibc/jump-table" \
  --tier pr --runtime glibc --require-runtime-identity \
  --unit runtime.indirect-control.jump-table.glibc.host-context-entry

./scripts/run-shared-jump-table-copy-e2e.sh --tier pr \
  --unit runtime.indirect-control.shared-table.glibc.host-context-entry \
  --artifact-root "$RUN/glibc/shared-table"
python3 scripts/check-rehydration-evidence.py \
  "$RUN/glibc/shared-table/runtime.indirect-control.shared-table.glibc.host-context-entry" \
  --tier pr --runtime glibc \
  --unit runtime.indirect-control.shared-table.glibc.host-context-entry
# Then run check-shared-jump-table-evidence.py with the selected urp_entry dynsym
# extracted from that root's retained source ELF/readelf report.
```

The ordinary musl CLI shape is now implemented and wired to the existing pinned job; the hosted execution remains pending. Bionic still requires a separate future runner/fixture/checker integration. Use distinct fresh roots and row IDs:

```bash
./scripts/run-indirect-control-e2e.sh --tier "$tier" --runtime musl \
  --unit runtime.indirect-control.jump-table.musl.host-context-entry \
  --artifact-root "$RUN/musl/jump-table"
python3 scripts/check-indirect-control-evidence.py "$RUN/musl/jump-table" \
  --tier "$tier" --runtime musl --require-runtime-identity \
  --unit runtime.indirect-control.jump-table.musl.host-context-entry

./scripts/run-shared-jump-table-copy-e2e.sh --tier "$tier" --runtime musl \
  --unit runtime.indirect-control.shared-table.musl.host-context-entry \
  --artifact-root "$RUN/musl/shared-table"
# Run the runtime-aware rehydration and shared-table checkers against that exact unit.

BIONIC_INDIRECT_CONTROL_E2E=true \
BIONIC_INDIRECT_CONTROL_ARTIFACT_ROOT="$RUN/bionic" \
  ./scripts/run-bionic-fixture.sh
# Independently check ordinary and shared Bionic unit roots with --runtime bionic;
# retain the Bionic fixture's locked package/image and linker identity evidence.
```

Use PR tier on PRs. The exact command root must not already exist. Add the Bionic feature root to the Bionic job's always-uploaded artifacts (and any cross-job consumer artifact if required); retain existing `.artifacts/bionic` provenance separately. Wire fresh artifact producers/checkers into required CI jobs only after the scripts and exact-root tests exist.

### 3. Required behavior, nearest negatives, and rollback boundary

For each ordinary row, the independent checker must bind source symbols and all four exact case results (`17, 103, -7, 91`) to the actual table and transformed output, the source and transformed process/entry results, and actual stream bytes. For each shared row, it must additionally prove a distinct file-backed PF_R clone, unchanged source table bytes, selected-consumer reference to the clone, unchanged `urp_observer` code/reference to the original, and source/transformed observer execution/release. Do not infer target selection from table contents, a success flag, or a branch count.

Keep the existing ordinary producer negatives in every new runtime build: malformed/out-of-closure table, checked-index-clobber, out-of-range target, and imported/external table without its exact provider contract. Require the actual failed producer stage, stable diagnostic/source binding, and absence of Protected Image, Native Image and loader invocation. For shared-owner policy, retain as positives the cases where incomplete/stripped/mismatched external owner metadata correctly remains `Ambiguous` and is preserved by cloning; do not mutate those into false `Shared` evidence. Retain selected-site relocation conflict, forged/omitted owner/source-reference snapshot, clone alias/range, and output target/base mapping failures as pre-publication negatives. Each run must preserve command, stdout, stderr, exit status and first-failure stage. A failed producer must not leave a Native Image or a loader marker. Do not reuse the external-provider loaded-rollback oracle as a table rollback claim; it belongs to the separate glibc provider row.

### 4. Promotion gate and rollback

Do not update the PRD checkboxes or mark the manifest rows `validated` until all required fresh glibc/musl/Bionic ordinary and shared runs, independent exact-root checkers, native test jobs, fixture/regression validators, and final evidence review pass. The provider row remains `unknown` / `scoped-observation-not-promoted` pending final documentation/registry review despite its hosted producer/checker and root-bound tests passing on PR run `39559228628` and merged-main run `39561529902`; it remains glibc-scoped. If a runtime fails, retain its diagnostics and label only that runtime row failed/unavailable; keep the already accepted glibc rows intact and keep general table/provider claims open. Revert only new runner/checker/CI wiring for a failed runtime slice if necessary; do not relax the semantic resolver or erase accepted evidence to force a green matrix.

## Historical Bionic staged-merge failures: current evidence is not a causal explanation

There are two historical records and they should not be conflated:

1. `research/current-gap-audit.md:121` says full Python discovery failed in three Bionic staged-merge cases, described as the directory-over-symlink case and two replacement cases. That record does not retain the exact per-case command output, traceback, exit status or stderr needed to diagnose them.
2. The later 432-test checkpoint in `implement.md` records one failure and one skip in `test_staged_merge_rejects_directory_symlink_type_conflicts`, specifically `symlink-over-directory`, with empty stderr. It separately states the first three-case report remains untouched. This is not proof of the earlier directory-over-symlink/two replacement outcomes.

Later historical full suites (including 446 and 470 tests) pass, and this audit reran `tests.test_bionic_node_runner`: **40/40 passed** on the current source. Those green results show the current suite can pass; they do not recover the missing earlier traceback or explain why the prior `symlink-over-directory` run failed. Keep both historical discrepancies as residual risk. A follow-up should reproduce the named `directory-over-symlink`, `symlink-over-directory`, and replacement subcases on the merged current source, capture each exact exit/stdout/stderr and execution identity (including `setpriv` availability/behavior), and compare pre/post staging tree state. Do not mark the historical risk resolved solely because a later full suite passed.

## Verification and audit limits

On current `HEAD=e281a94`, this audit ran:

- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore --filter 'FullyQualifiedName~RelativeJumpTable|FullyQualifiedName~SharedJumpTableOwnerWorkflowTests' --logger 'console;verbosity=minimal'` — passed, **21 tests**.
- `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_bionic_node_runner` — passed, **40 tests**. This is a current unit-suite result only, not native Bionic execution or historical root-cause evidence.
- `git status --short`, `git rev-parse --short HEAD`, and `git rev-parse --git-path MERGE_HEAD` — confirmed HEAD `e281a94`, the pre-existing journal modification and untracked divergence investigation, and no active merge.

This environment is AArch64 but has neither Docker nor `musl-gcc`; therefore no native glibc/musl/Bionic E2E or runtime-matrix cell was produced or rewritten during the audit. No full solution/Python suite, fixture-manifest update, provider rerun, task status transition, stage, commit, push, merge, archive or journal/investigation write was performed. The Trellis current-session pointer reports none; this report uses the explicit task path already supplied in the session context.
