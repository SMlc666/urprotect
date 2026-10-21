# R5 TLS Matrix: Current-Filesystem Audit

Read-only audit of the TLS registry, matrix producer/checker, fixture binaries, CI wiring, native handoff/protection paths, and retained artifact roots. No builds, matrix producers, generated build/runtime-evidence artifacts, implementation/spec edits, or row reclassifications were performed. This note is the only research artifact written. The current task resolves to `.trellis/tasks/10-06-unify-elf-protection-infrastructure` (`task.py current --source`).

## Findings at a glance

1. **The currently declared and checker-enforced promoted set is four rows, not one:**
   - `initial-exec.host-context-entry.glibc.current-thread`
   - `local-dynamic.host-context-entry.glibc.current-thread`
   - `general-dynamic.host-context-entry.glibc.current-thread`
   - `tlsdesc.host-context-entry.glibc.current-thread`

   The exact set is in `fixtures/tls-runtime-matrix.json:31-36`, `PROMOTED_MODELS` in `scripts/run-tls-runtime-matrix.py:30-58`, and `PROMOTED_ROWS` in `scripts/check-tls-runtime-matrix-evidence.py:37-42`. The latest task PRD and measured-evidence spec also say four (`prd.md:87,93`; `.trellis/spec/backend/tls-evidence-oracle.md:39-42`). The older task research note `research/r5-tls-transformed-runtime-audit.md` says only initial-exec; that conclusion is stale relative to the current producer, checker, registry, and available full matrix.

2. **The current filesystem's `.artifacts/tls-runtime/pr` is not a closed retained matrix root.** It has no root `matrix.json`, `environment.json`, or `SHA256SUMS`; it contains only an initial-exec row directory and a shared managed-gate log. The required read-only checker invocation failed immediately with `TLS runtime evidence SHA256SUMS is missing`. The one row directory is also incomplete as a standalone accepted row (e.g. no `source-handoff.json`, baseline/target streams, or `tls-template.bin`). No current promotion can be attested from this `pr` root.

3. A dated, alternative root **does** contain a full matrix that passes the current checker: `.artifacts/tls-runtime/oracle-integration-final-20261014T092753Z` (its matrix tier is `release`). It has 60 rows, a closed `SHA256SUMS`, and exactly the four accepted IDs above; `python3 scripts/check-tls-runtime-matrix-evidence.py ... --registry fixtures/tls-runtime-matrix.json` returns `TLS runtime evidence valid: 60 rows`. The four source-image hashes in that root match the pre-existing TLS fixture binaries currently in `native/urprotect-runtime/build/`. This validates the retained root as it stands, but does **not** make `.artifacts/tls-runtime/pr` complete or mean a PR-tier root is currently present.

4. `.artifacts/tls-runtime/canonical-convergence-20261014` also contains a 60-row `pr` matrix and lists those same four as accepted, but the current checker rejects it with `retained glibc runtime identity fields are malformed`. Its inventory manifest exists, but it is not checker-valid retained TLS evidence. The current standalone `.artifacts/protected-image/tls/tls.initial-exec.glibc.host-context-entry` is also stale against current validators: protected-image checking reports missing `expectedEntryStatus`, `nativeImagePath`, `nativeImageSha256`, `runtimeIdentity`, and `runtimeIdentitySha256`; rehydration checking reports `HostContext handoff process status does not bind the observed entry status`. Do not use those roots as substitutes for the checker-valid matrix root.

## Evidence layers: support is not promotion

The five fixture binaries below are the model-specific `sourceFixtures` entries in `fixtures/tls-runtime-matrix.json:24-29`. Their matching source inputs are under `native/urprotect-runtime/` (C or assembly as listed). Hashes in the validated alternative matrix match the pre-existing generated fixture binaries currently under `native/urprotect-runtime/build/`. This table separates four levels that must not be collapsed.

| TLS model | Managed semantic/layout support | Native baseline evidence | Transformed execution evidence | Canonical promotion |
|---|---|---|---|---|
| `local-exec` | **Bounded managed support exists.** `FunctionProtectionPlanning.cs:804-900` includes local-exec, and the recognizer/test suite covers exact TPREL instruction sequences (`Aarch64TlsSequenceRecognizer.cs:201-208,490-505`; `TlsLocalExecWorkflowTests.cs:38-89,1024-1150`). The matrix source is `host_context_tlsle_fixture.S`; current binary has `PT_TLS` and static `R_AARCH64_TLSLE_A` code relocations. | The full matrix's `host-image-validation-probe` source preflight is accepted (status 0). That is not a source-entry execution or a proof that a DSO local-exec TLS sequence works through a particular loader/profile. | **None in the full matrix.** `local-exec` is absent from `PROMOTED_MODELS`; the TLS wrapper's model switch rejects it (`run-tls-host-context-rehydration-e2e.sh:41-47`). No baseline-vs-transformed handoff for this tuple is retained there. | **Not promoted.** `local-exec` appears in registry/model coverage and source preflight only. No row declares it promoted.
| `initial-exec` | **Bounded managed support exists.** Exact IE relocation/sequence shapes are handled in `FunctionProtectionPlanning.cs:858-864` and tested in `TlsLocalExecWorkflowTests.cs` (including lines 310-425, 613-684). | The source fixture `host_context_tls_fixture.c` has `__thread int urp_tls_value = 43`; the validated row includes actual source `host-context-image-handoff` execution on native AArch64 glibc, not just a preflight. | **Yes for this one tuple only.** Its retained row binds source, protected/native hashes, source and target handoff records, process/entry status 43, streams, comparison/oracle, and current-thread observation. | **Yes:** `initial-exec.host-context-entry.glibc.current-thread`.
| `local-dynamic` | **Bounded managed support exists.** The planner constrains the exact TLSLD ADRP/ADD + direct `__tls_get_addr` + DTPREL form (`FunctionProtectionPlanning.cs:865-871,894-896`); the selected workflow test is at `TlsLocalExecWorkflowTests.cs:92-196`. | Native preflight validates bounded `PT_TLS` and DTPMOD64/DTPREL64 ownership. For the accepted tuple, the source fixture is also executed as the real baseline by the HostContext runner. | **Yes for HostContext/glibc/current-thread only.** The matrix row's measured source and target both return 43 and behavior comparison passes. The source fixture includes a 16-byte `.tbss` tail; matrix evidence correctly leaves zero-fill `not-run`, not observed. | **Yes:** `local-dynamic.host-context-entry.glibc.current-thread`.
| `general-dynamic` | **Bounded managed support exists.** The planner checks exact TLSGD and paired DTPMOD64/DTPREL64 owners (`FunctionProtectionPlanning.cs:872-877,894-897`); test anchor `TlsLocalExecWorkflowTests.cs:255-308`. | Native preflight supports the bounded DTPMOD64/DTPREL64 metadata form; accepted tuple additionally has source/baseline HostContext execution. | **Yes for HostContext/glibc/current-thread only.** Retained baseline and transformed handoffs each observe status 43 and pass the comparison oracle. | **Yes:** `general-dynamic.host-context-entry.glibc.current-thread`.
| `tlsdesc` | **Bounded managed support exists.** The planner requires the exact TLSDESC marker sequence and validated descriptor owner (`FunctionProtectionPlanning.cs:878-893,894-898`); workflow test anchor `TlsLocalExecWorkflowTests.cs:198-253`. | Native preflight recognizes the bounded `R_AARCH64_TLSDESC` dynamic owner; accepted tuple additionally has source/baseline HostContext execution. | **Yes for HostContext/glibc/current-thread only.** Retained baseline and transformed handoffs each observe status 43 and pass the comparison oracle. | **Yes:** `tlsdesc.host-context-entry.glibc.current-thread`.

The full checker-valid alternative root records these four accepted rows, each with `expectedEntryStatus=43`, `perThread=observed`, a distinct source/protected/native hash, and the row-specific behavior oracle. Their hashes are:

| Row ID | Source SHA-256 | Protected SHA-256 | Native-image SHA-256 |
|---|---|---|---|
| `initial-exec.host-context-entry.glibc.current-thread` | `b67e9ffb799f4855ec77a46a493178afdf63589b08624755aeafeb7caf05ab3a` | `421bf53594516cda39cb88161edcf2ad5c3c8af50ccacfe258efa574e7333ef8` | `2d185b98113ad9fa1c9b73271a6e41c6a8d66039cb501a10fa7f440963dbd9ac` |
| `local-dynamic.host-context-entry.glibc.current-thread` | `e978c082670d524fb93725fb36374a8d193f5c4badbe261b6b76445ff62bcb55` | `06a78c31222b85b7605ddda97368a9b5e599a38ef267342ba2701b38bee2920f` | `57378e3c369fe8456b4bc541daea4842824855744a017c4aa5c68d476a5bbfe4` |
| `general-dynamic.host-context-entry.glibc.current-thread` | `a7df0b5a4a8a4d5a0a9bb5453d7090d1409fa0a8666b07e2e48cb2fd16ebc69e` | `d2c2091bd66232987bcdc58f419bd9475c4221e3d13103de82e5ab217d54b5c0` | `c15491de55a3d253983409ff1d7b5c8d21e9253c80966b837eb6879fba7e87e0` |
| `tlsdesc.host-context-entry.glibc.current-thread` | `fa5fd0c9f9c0ce01262b9d2a9c0f16a50cb6dfbb5d1f94440eab669520cbbf5b` | `dcfa0ed371cdb49a5ee078014686bbe1c419000240125a48f991313cb6e70b56` | `8c66d06e6ee68338a1728f1123feb0b496f207210ab7f12644d26a2778c778af` |

The matrix evidence contract (`.trellis/spec/backend/tls-evidence-oracle.md:43-63`) correctly makes current-thread `perThread=observed` distinct from worker isolation. `zeroFill=not-run` on a fixture with a non-empty zero-fill tail is not proof of zero-fill behavior. Current-thread `teardown` observes image release, not a TLS-key destructor or registered-worker lifecycle.

## Exact tuple result table (all 60 declared tuples)

Each cell is `current-thread / registered-worker`, in the dimension order `model × profile × runtime × lifecycle`. These are the observed results in the full checker-valid `oracle-integration-final-20261014T092753Z` root and match the current producer's branch order. `N/A-sem` means `not-applicable` with `firstFailureStage=semantic`; `N/A-scope` means `not-applicable` with `firstFailureStage=scope`; `EU-env` means `environment-unavailable` with `firstFailureStage=environment`. **These codes are not present as a valid 60-row result in `.artifacts/tls-runtime/pr`, which lacks `matrix.json`.**

| Model | Profile | glibc: current / worker | musl: current / worker | bionic: current / worker | Concrete blocker for non-promoted tuples |
|---|---|---|---|---|---|
| local-exec | outer-execveat | N/A-sem / N/A-scope | EU-env / N/A-scope | EU-env / N/A-scope | No outer TLS-aware selected-function/protection/rehydration/handoff runner. LE is not in the promoted-model map and the shared TLS wrapper rejects it. On this host, musl and default Docker capability are absent. |
| local-exec | host-context-entry | N/A-sem / N/A-scope | EU-env / N/A-scope | EU-env / N/A-scope | Managed LE exists, but no transformed runtime configuration or runner: absent from `PROMOTED_MODELS`, rejected by wrapper model dispatch. Worker oracle also absent. |
| initial-exec | outer-execveat | N/A-sem / N/A-scope | EU-env / N/A-scope | EU-env / N/A-scope | Native generic `execveat` exists, but the TLS wrapper is HostContext-only and the matrix never invokes a TLS-aware OuterExecveat runner. |
| initial-exec | host-context-entry | **accepted-and-runs / N/A-scope** | EU-env / N/A-scope | EU-env / N/A-scope | The current-thread glibc tuple is promoted. The worker is only separate native baseline/adapter evidence, not transformed worker execution. Musl/bionic have no independent TLS transformed oracle. |
| local-dynamic | outer-execveat | N/A-sem / N/A-scope | EU-env / N/A-scope | EU-env / N/A-scope | No outer TLS-aware transformed runner; no outer worker lifecycle. |
| local-dynamic | host-context-entry | **accepted-and-runs / N/A-scope** | EU-env / N/A-scope | EU-env / N/A-scope | The current-thread glibc tuple is promoted. No transformed worker lifecycle oracle; no musl/bionic transformed HostContext TLS loader/handoff. |
| general-dynamic | outer-execveat | N/A-sem / N/A-scope | EU-env / N/A-scope | EU-env / N/A-scope | No outer TLS-aware transformed runner; no outer worker lifecycle. |
| general-dynamic | host-context-entry | **accepted-and-runs / N/A-scope** | EU-env / N/A-scope | EU-env / N/A-scope | The current-thread glibc tuple is promoted. No transformed worker lifecycle oracle; no musl/bionic transformed HostContext TLS loader/handoff. |
| tlsdesc | outer-execveat | N/A-sem / N/A-scope | EU-env / N/A-scope | EU-env / N/A-scope | No outer TLS-aware transformed runner; no outer worker lifecycle. |
| tlsdesc | host-context-entry | **accepted-and-runs / N/A-scope** | EU-env / N/A-scope | EU-env / N/A-scope | The current-thread glibc tuple is promoted. No transformed worker lifecycle oracle; no musl/bionic transformed HostContext TLS loader/handoff. |

Accounting from that valid root: **4 `accepted-and-runs`, 36 `not-applicable`, 20 `environment-unavailable`, 0 `runtime-failure`.** The 36 N/A rows comprise 30 worker rows plus the five glibc OuterExecveat current-thread rows and local-exec/HostContext/glibc/current-thread. The 20 environment rows are the ten current-thread musl tuples and ten current-thread bionic tuples. Local inspection found `uname -m=aarch64` but no `musl-gcc`, `docker`, or `podman`; the validated root's environment record likewise has `muslToolchain=false` and `bionicContainerRuntime=null`.

### OuterExecveat vs HostContext worker applicability

- `OuterExecveat` is a separate process handoff: `native/urprotect-runtime/native_image_handoff.c` calls `execveat` on the image, while `run-rehydration-e2e.sh` dispatches `outer-execveat` versus `host-context-entry`. It has no registered HostContext image-thread API/lifetime. Thus all 15 OuterExecveat × registered-worker tuples are correctly N/A-scope in this matrix. Generic outer handoff evidence is not an OuterExecveat TLS row.
- The TLS-specific runner `scripts/run-tls-host-context-rehydration-e2e.sh:38-46,87-97` rejects non-glibc and non-HostContext inputs and allows only current-thread; its model switch admits only IE, LD, GD, and TLSDESC. The matrix producer invokes it with hard-coded `--profile host-context-entry --runtime glibc --lifecycle current-thread` (`run-tls-runtime-matrix.py:267-320` and `:474-490`). No TLS-aware OuterExecveat runtime command is wired.
- Native registered-worker support is separate **baseline** evidence, not transformed TLS support. `fixtures/manifest.json:573-604` and `native/urprotect-runtime/test_managed_host_context.sh:340-373` exercise the glibc initial-exec worker fixture/harness, including per-thread values, explicit/automatic joins, teardown ordering, and concurrent dispatch. `native/urprotect-runtime/host_adapter.c:248-359,361-460,496-503` compiles thread callbacks only for glibc and joins workers before `dlclose`. README and compatibility contract limit this extension to initial-exec glibc (`native/urprotect-runtime/README.md:38-52`; `COMPATIBILITY.md:157-171`). None of those paths transform a selected TLS function and then run a worker-aware baseline-vs-transformed oracle. Dynamic TLS worker lifecycle and musl/bionic threading remain outside the native adapter contract.

## Producer, checker, CI, and exact gate gaps

### Producer behavior

- `scripts/run-tls-runtime-matrix.py:405-429` deletes/recreates its output root, builds all five native fixtures and the validation probe; `:436-455` runs one filtered managed test command and copies the same log into every row. This audit did **not** invoke this producer because it builds and writes artifacts.
- It runs actual transformed source/baseline plus rehydrated native-image handoff only through `run_promoted_evidence` for the four hard-coded promoted models (`:30-58,267-392,472-491`). This is a real row execution path, not a declaration-only path.
- For all other rows, `base_row` copies the source fixture, PT_TLS template, the shared managed-gate log, and the result of `host-image-validation-probe`; it records null protected/native hashes, `loaderStatus=not-run`, and no row-specific behavior oracle (`:143-235,556-581`). This is common source preflight and classification, not 56 transformed executions.
- Availability branch ordering is decisive (`:493-555`): OuterExecveat registered-worker is N/A-scope first; every other registered-worker is N/A-scope before checking runtime availability; only current-thread musl/bionic consult tool presence; when tools exist, those current-thread rows become N/A because no independent transformed oracle is registered. Local-exec/OuterExecveat glibc current-thread are N/A-semantic. This preserves distinct environment vs scope claims but means tool presence alone never executes musl/bionic TLS rows.
- `has_musl` is only `shutil.which("musl-gcc")`; `has_bionic` is only `shutil.which(BIONIC_CONTAINER_RUNTIME or "docker")`. The producer does not call a musl linker/loader or a Termux/bionic container for non-promoted rows.

### Checker behavior

- `scripts/check-tls-runtime-matrix-evidence.py:116-141` requires a closed root `SHA256SUMS` with exact file-set and digest agreement. It then enforces 60 unique tuple identities, exact fixture identities, native preflight source binding, bounded PT_TLS facts, runtime identity, and a stable promoted set (`:532-575,565+`).
- For every accepted row it requires source/protected/native artifacts, stage/rehydration/handoff, source handoff, baseline/target stdout and stderr, a behavioral comparison/oracle and TLS template; it checks hashes/status/entry 43 and recomputes stream/status equality (`:431-509` plus `check_behavioral_oracle`). This is a strong four-row execution gate.
- For `environment-unavailable`, it rejects invented protected/native hashes and per-thread/zero-fill observations (`:510-518`). For `not-applicable`, it only requires a `scope`/`semantic` failure stage and `publicationResult=not-published` (`:519-523`); it does **not** require null protected/native hashes, `loaderStatus=not-run`, or per-thread/zero-fill `not-run`. The producer currently emits the safe values, but the checker would not fully prevent an N/A row from carrying execution-like claims if the sums were regenerated.
- All 60 rows cite a copy of the same global managed semantic-gate log and a row-bound but common native preflight. The checker validates those artifacts, but that does not create row-specific semantic/runtime oracles for the other 56 tuples.

### CI wiring gaps

- `.github/workflows/ci.yml:193-215` runs `run-tls-runtime-matrix.py` then the checker under `.artifacts/tls-runtime/${tier}` on the `build-and-test` native `ubuntu-24.04-arm` job. CI separately invokes the direct initial-exec runner at `:140-178`; the matrix producer is what invokes the other three promoted model runners.
- In the same build-and-test job, explicit musl package installation occurs later (`ci.yml:354-356`), after the TLS matrix step. More importantly, even if `musl-gcc` is available at matrix time, the current producer's musl path emits N/A and never executes a transformed TLS loader oracle.
- The later general runtime-matrix job installs musl for extended tiers and downloads bionic evidence (`ci.yml:590-659`), and a separate native bionic job checks generic bionic fixture/HostContext handoff (`:662-725`). Neither invokes `run-tls-runtime-matrix.py` against a musl or bionic TLS fixture. The existence of those generic runtime jobs does not promote TLS tuples.
- The PRD still leaves R5 unchecked and explicitly limits current transformed proof to the four native glibc HostContext current-thread models (`prd.md:87,93`). The `tls-evidence-oracle.md:39-42` contract says the same; the prior one-row audit has not been updated.

## Commands and observed gate outcomes

Read-only commands/checks used:

```text
python3 ./.trellis/scripts/task.py current --source
  -> .trellis/tasks/10-06-unify-elf-protection-infrastructure

python3 scripts/check-tls-runtime-matrix-evidence.py .artifacts/tls-runtime/pr --registry fixtures/tls-runtime-matrix.json
  -> FAIL: TLS runtime evidence SHA256SUMS is missing

python3 scripts/check-tls-runtime-matrix-evidence.py .artifacts/tls-runtime/oracle-integration-final-20261014T092753Z --registry fixtures/tls-runtime-matrix.json
  -> PASS: TLS runtime evidence valid: 60 rows

python3 scripts/check-tls-runtime-matrix-evidence.py .artifacts/tls-runtime/canonical-convergence-20261014 --registry fixtures/tls-runtime-matrix.json
  -> FAIL: retained glibc runtime identity fields are malformed

python3 scripts/check-protected-image-evidence.py .artifacts/protected-image/tls/tls.initial-exec.glibc.host-context-entry --tier pr --runtime glibc --unit tls.initial-exec.glibc.host-context-entry
  -> FAIL: tlsEvidence is missing fields expectedEntryStatus, nativeImagePath, nativeImageSha256, runtimeIdentity, runtimeIdentitySha256

python3 scripts/check-rehydration-evidence.py .artifacts/protected-image/tls/tls.initial-exec.glibc.host-context-entry --tier pr --runtime glibc --unit tls.initial-exec.glibc.host-context-entry
  -> FAIL: HostContext handoff process status does not bind the observed entry status
```

The producers/build commands (not run) are the CI invocations at `.github/workflows/ci.yml:193-215` and the model-aware wrapper signature in `.trellis/spec/backend/tls-evidence-oracle.md:13-18`.

## Residual risks / interpretation

- A complete registry and 60 classified rows are not 60 runtime proofs. The only checker-valid retained full matrix found is a dated `release` root outside the configured `pr` location; current `.artifacts/tls-runtime/pr` cannot be accepted as a closed root.
- The exact four promoted tuples are narrow: native AArch64 glibc, HostContext, current-thread, selected fixture function, status 43. They do not transfer to local-exec, OuterExecveat, workers, musl, or bionic.
- The existing glibc worker evidence is native adapter/packed-wrapper baseline evidence for initial-exec; it is not transformed worker TLS evidence. `perThread=observed` in current-thread rows does not imply worker isolation; zero-fill on the LD fixture remains unobserved.
- Even beyond the local missing musl/Android tooling, there is no transformed runner path for those runtime/profile tuples; installing tools alone cannot promote a row under the current producer.
- The full checker-valid alternative root and current standalone/PR roots disagree in validity/versioning. The direct artifacts should be treated according to current checkers, not their directory names or old status fields.

This is an audit result only. No matrix row classification was changed and no TLS feature acceptance is asserted.
