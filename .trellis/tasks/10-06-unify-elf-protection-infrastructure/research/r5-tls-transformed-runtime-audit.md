# R5 TLS Transformed-Runtime Audit

Read-only audit of the active parent, archived `10-06-tls-relocation-runtime-matrix`, and current managed/native evidence. No production or task-state files were changed.

## Bottom Line

Parent R5 is still open. The only transformed runtime row with execution evidence is:

```text
initial-exec x host-context-entry x glibc x current-thread
```

This is the parent’s explicit boundary at `.trellis/tasks/10-06-unify-elf-protection-infrastructure/prd.md:86-93`, and the archived TLS implementation record repeats it at `.trellis/tasks/archive/2026-10/10-06-tls-relocation-runtime-matrix/implement.md:204-210`.

The archived child is marked completed and its semantic/evidence-projection checkboxes are checked, but that closes only the bounded managed/evidence increment. It does not close the parent’s transformed-runtime requirement.

## Matrix Accounting

`fixtures/tls-runtime-matrix.json:4-35` declares:

```text
5 models x 2 profiles x 3 runtimes x 2 lifecycles = 60 rows
```

The checked-in PR artifact `.artifacts/tls-runtime/pr/matrix.json` passes its checker, with this actual distribution:

| Row group | Count | Current result | Interpretation |
|---|---:|---|---|
| Initial-exec, HostContext, glibc, current-thread | 1 | `accepted-and-runs` | Real transformed producer, rehydration, sealed-memfd handoff, status 43, and release evidence. |
| Other glibc current-thread rows | 9 | `not-applicable` / `semantic` | Managed semantic/layout support exists; no row-specific transformed runtime oracle is registered. |
| Musl current-thread rows | 10 | `environment-unavailable` locally | No local `musl-gcc`; no transformed musl row ran. |
| Bionic current-thread rows | 10 | `environment-unavailable` locally | No local Docker/Podman; no transformed bionic row ran. |
| All registered-worker rows | 30 | `not-applicable` / `scope` | Outer profile has no worker lifecycle; HostContext has no dedicated transformed worker oracle. |

Observed counts are 1 accepted, 20 environment-unavailable, and 39 not-applicable.

All 60 rows share one source hash (`b67e...5ab3a`) and one PT_TLS template hash (`7c9b...4ccc7`). The 59 non-control rows have no protected/native transformed hashes and `loaderStatus=not-run`. This follows from `scripts/run-tls-runtime-matrix.py:143-183` (common `base_row` evidence) and `:281-344` (classification-only rows); only `:235-279` invokes the real transformed runner.

The matrix is therefore a closed classification projection, not 60 transformed executions.

## What Is Implemented

### Structural and managed semantic layers

- Bounded PT_TLS template, zero-fill, alignment, owning-load, static/dynamic relocation, and descriptor facts: `src/UrProtect.Core/StructuralElf/TlsFacts.cs:1-76`, `ElfTlsParser.cs:1-190`.
- Five typed access models and five relocation families: `src/UrProtect.Core/SemanticPlanning/TlsSemanticModels.cs:6-24`.
- Positive model theory for all five models: `tests/UrProtect.Core.Tests/Semantics/Aarch64TlsSequenceRecognizerTests.cs:10-50`.
- Canonical snapshot coverage for all five models: `tests/UrProtect.Core.Tests/Semantics/SemanticPlanSnapshotTests.cs:295-340`.
- Shared plan/layout fixup validation for the five model names: `src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs:1270-1406`.
- Bounded dynamic and TLSDESC output encoding/reparse paths: `src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs:2239-2347`.

The current managed slices are exact bounded forms, not every ABI relocation form:

| Model | Implemented managed slice | Evidence |
|---|---|---|
| Local-exec | ADD TPREL HI12/LO12, ADD HI12/LDST32, and MOVW G1/G0_NC variants with shared layout/reparse. | `FunctionProtectionPlanning.cs:173-179`; `TlsLocalExecWorkflowTests.cs:36-89` |
| Initial-exec | LD_GOTTPREL_PREL19, MOVW G1/G0_NC, and ADRP/LD64 GOTTPREL pairs with a preserved TPREL64 GOT owner. | `FunctionProtectionPlanning.cs:180-186`; `TlsLocalExecWorkflowTests.cs:277-327` |
| Local-dynamic | Exact TLSLD ADRP/ADD + `__tls_get_addr` + DTPREL ADD/ADD with DTPMOD64 owner. | `FunctionProtectionPlanning.cs:187-194`; `TlsLocalExecWorkflowTests.cs:90-162` |
| General-dynamic | Exact TLSGD ADRP/ADD + `__tls_get_addr` with DTPMOD64/DTPREL64 owners. | `FunctionProtectionPlanning.cs:195-200`; `TlsLocalExecWorkflowTests.cs:222-275` |
| TLSDESC | Exact four static markers, 16-byte descriptor owner, resolver PLT/GOT contract, and adjacent BLR fallthrough. | `FunctionProtectionPlanning.cs:201-208`; `TlsLocalExecWorkflowTests.cs:165-220` |

The archived GNU oracle documents explicitly call TLSLD and TLSDESC shape evidence, not transformed runtime evidence: `research/aarch64-tlsld-oracle.md:1-5` and `research/aarch64-tlsdesc-oracle.md:1-8`.

### Native capability actually present

- Ordinary native symbolic RELA accepts only ABS64, GLOB_DAT, and `R_AARCH64_TLS_TPREL64`: `native/urprotect-runtime/host_image_validation.c:510-552`. There is no native HostContext acceptance path there for TLSGD, TLSLD, or TLSDESC dynamic relocation families.
- HostContext PT_TLS handoff requires one non-empty readable segment with a writable PT_LOAD owner: `native/urprotect-runtime/host_image_validation.c:1664-1690`.
- Thread-lifetime callbacks are compiled/advertised only for glibc: `native/urprotect-runtime/host_adapter.c:248-285` and `:479-503`; release joins workers before unload at `:361-385`.
- The native README states that the first TLS slice is initial-exec, while dynamic TLS and musl/bionic threaded claims remain outside the contract: `native/urprotect-runtime/README.md:25-45`.
- The compatibility spec makes the same boundary and identifies the glibc worker fixture as a separate adapter row, not transformed TLS support: `.trellis/spec/backend/runtime-compatibility.md:322-341`.

## Evidence That Exists

1. **Promoted control row.** `scripts/run-tls-host-context-rehydration-e2e.sh:23-41` requires native AArch64 and invokes the HostContext rehydrator with `--runtime glibc`, the GCC TLSIE fixture, and entry status 43. The retained tree `.artifacts/protected-image/tls/tls.initial-exec.glibc.host-context-entry/` includes source/protected/native images, `stage.json`, handoff/rehydration records, baseline/transformed streams, `behavior-comparison.json`, `tls-readelf.txt`, `tls-template.bin`, rollback evidence, and a closed `SHA256SUMS`.
2. **60-row projection.** `.artifacts/tls-runtime/pr/matrix.json` and its closed manifest exist. `scripts/check-tls-runtime-matrix-evidence.py:156-226` validates row identity, hashes, PT_TLS arithmetic, common native preflight, and the invariant that only the control row is accepted. Its `not-applicable` branch does not require a transformed artifact, baseline comparison, loader handoff, or lifecycle trace.
3. **Prerequisite probes.** `.artifacts/tls-prerequisites/pr/android-packed-tags.json` has eight canonical Android packed-tag rejection rows; `pt-tls-predicate-parity.json` has six PT_TLS cases. The producer/checker are `scripts/run-tls-prerequisite-probes.py:161-248` and `scripts/check-tls-prerequisite-evidence.py:62-111`. These are rejection/layer-boundary evidence, not transformed TLS support.
4. **Six-cell runtime covering set.** `fixtures/runtime-matrix.json` remains loader/environment coverage. The archived design says it is not the TLS promotion matrix at `.trellis/tasks/archive/2026-10/10-06-tls-relocation-runtime-matrix/design.md:242-268`.

## Environment-Unavailable Classification

`scripts/run-tls-runtime-matrix.py:281-344` classifies rows in this order:

1. `outer-execveat x registered-worker` is always `not-applicable` with `firstFailureStage=scope`.
2. Every other registered-worker row is `not-applicable` with `firstFailureStage=scope`, before runtime availability is checked.
3. A current-thread musl row is `environment-unavailable` only when `shutil.which("musl-gcc")` is false.
4. A current-thread bionic row is `environment-unavailable` only when `shutil.which(BIONIC_CONTAINER_RUNTIME)` is false; default is the `docker` executable.
5. If those binaries exist, the producer still returns `not-applicable` because no independent transformed musl/bionic oracle is registered.
6. A glibc current-thread non-control row is `not-applicable` with `firstFailureStage=semantic`, even though native glibc is available, because no transformed runtime oracle is registered.

Local facts are native `aarch64`, 4096-byte pages, no `musl-gcc`, no Docker, and no Podman. Thus the 20 current-thread musl/bionic rows are valid local capability observations. They do not prove product capability in a capable CI lane. The script does not invoke the pinned musl installer/toolchain or the Termux/bionic transformed lane; with those tools present, rows become scope N/A rather than executed rows.

The worker ordering also conflates absent runtime capability with absent transformed lifecycle oracle. The archived PRD requires explicit worker capability boundaries at `.trellis/tasks/archive/2026-10/10-06-tls-relocation-runtime-matrix/prd.md:39-57`; the producer currently short-circuits all worker rows to N/A.

There are also two distinct `environment-unavailable` contracts that must stay named:

- Matrix rows require no protected/native hashes, `publicationResult=not-published`, and `firstFailureStage=environment`: `check-tls-runtime-matrix-evidence.py:210-218`.
- Standalone `tlsEvidence` on a Protected Image stage requires a completely published stage and uses `publicationResult=published`: `check-protected-image-evidence.py:198-225` and `:280-284`.

The shared vocabulary is fine, but these projections must not be treated as interchangeable evidence.

## Exact Remaining Work

| Rows | Classification | Work needed to promote | Honest retention if deferred |
|---|---|---|---|
| Control row | Complete | Keep the existing producer, rehydration, native handoff, and evidence checkers green. | Keep `accepted-and-runs`; never generalize it. |
| 9 other glibc current-thread rows | Code/evidence gap, not environment | Add model/profile-specific fixtures and a row-aware runner that performs baseline, selected-function transform, shared materialization/rehydration, loader handoff, behavior comparison, PT_TLS facts, and hashes. The current runner is hard-coded to glibc/TLSIE/HostContext at `run-tls-host-context-rehydration-e2e.sh:32-41`. | Keep `not-applicable` with `firstFailureStage=scope` or `semantic`; do not call it runtime support. |
| 10 musl current-thread rows | Local environment plus missing runner | Use the pinned musl toolchain and loader artifacts from `fixtures/runtime-matrix.json:69-98`, build each model fixture, execute baseline and transformed images through the pinned musl loader, and retain independent row artifacts. Extend the producer beyond a `musl-gcc` presence check. | Keep `environment-unavailable` only for a genuinely missing lane, with environment identity/reason and no runtime hashes. In a capable lane with no oracle, use `not-applicable`. |
| 10 bionic current-thread rows | Local environment plus native/product gap | Run on the locked native ARM64 Termux lane using `/system/bin/linker64` and sectioned images; add transformed fixtures/runners per model. For LD/GD/TLSDESC, extend or replace the HostContext native relocation contract because current native validation admits only TLS_TPREL64. | Keep local `environment-unavailable` only when Termux/container capability is missing. With the lane available but no oracle, use `not-applicable`. |
| 15 HostContext registered-worker rows | Transformed lifecycle code/evidence gap; native capability is glibc-only | Add transformed worker fixtures/runners retaining creation/join, per-thread values, constructors/destructors, TLS-key teardown, release/image destruction order, and baseline/transformed comparison. Existing glibc worker artifacts are adapter/baseline evidence only. | Keep N/A for absent transformed oracle; use row-local environment-unavailable only where the runtime lacks the required worker capability. |
| 15 outer-execveat registered-worker rows | Profile boundary | No worker lifecycle is applicable to the execveat process handoff. | Retain N/A with the explicit profile reason. |

Every promoted row needs source, protected/native image or outer execution
artifact, PT_TLS template, managed plan/snapshot, native preflight, baseline and
transformed status/streams, behavior comparison, loader/toolchain identity,
per-thread/zero-fill observations, lifecycle trace where applicable,
first-failure/rollback record, and a closed `SHA256SUMS`. The existing control
row is the concrete artifact model.

Useful current validation commands:

```sh
python3 scripts/check-tls-prerequisite-evidence.py .artifacts/tls-prerequisites/pr
python3 scripts/check-tls-runtime-matrix-evidence.py \
  .artifacts/tls-runtime/pr --registry fixtures/tls-runtime-matrix.json
python3 scripts/check-protected-image-evidence.py \
  .artifacts/protected-image/tls/tls.initial-exec.glibc.host-context-entry \
  --tier pr --runtime glibc --unit tls.initial-exec.glibc.host-context-entry
python3 scripts/check-rehydration-evidence.py \
  .artifacts/protected-image/tls/tls.initial-exec.glibc.host-context-entry \
  --tier pr --runtime glibc --unit tls.initial-exec.glibc.host-context-entry
```

The first two validate classification/prerequisite artifacts. The latter two
validate actual transformed publication and handoff. New model/profile/runtime/
lifecycle runners need equivalent row-specific commands and retained paths;
current scripts have no transformed arguments for musl, bionic, outer-execveat,
or worker lifecycle.

## Acceptance and Documentation Risks

- **Parent is honest.** R5 remains unchecked at `.trellis/tasks/10-06-unify-elf-protection-infrastructure/prd.md:86-93`, and its status correction says not to archive until transformed TLS gaps are completed or scope is explicitly revised.
- **Archived child status is easy to overread.** `task.json:6` says completed, while its goal says “prove each model independently on glibc, musl, and bionic” at `archive/.../prd.md:3-16`. The checked item at `archive/.../prd.md:99` saying all five models have rewrite/materialization paths is defensible only as bounded managed semantic/layout coverage, not runtime support.
- **Archived implementation overstates row-local proof.** `archive/.../implement.md:233-242` says every unpromoted tuple has a row-local semantic gate and native preflight. The artifact has row-local files, but the producer runs one global filtered managed test and one common initial-exec native preflight for all rows. Describe this as row-local classification plus common prerequisites, not row-local transformed evidence.
- **Manifest status needs a qualifier.** `fixtures/manifest.json:410-428` marks the matrix feature `validated`; its constraints correctly say only the control row is promoted, but `validated` must not be read as R5 runtime support complete.
- **Stale historical contradiction.** The archived runtime-difference audit calls the Android packed-tag mismatch high severity at `archive/.../research/runtime-difference-audit.md:31-46`, then calls it resolved with eight-row evidence at `:261-278`. Current prerequisite artifacts support the latter; the opening should be labeled historical/pre-fix if retained.

## Audit Result

R5 currently proves a bounded managed five-model semantic/layout surface, one
native glibc initial-exec HostContext transformed row, the native glibc worker
baseline, and prerequisite rejection/layer-boundary probes. It does not prove
transformed runtime behavior for the other 59 tuples.

The missing rows divide into:

1. **Unavailable environment:** local musl and bionic current-thread lanes,
   evidenced by missing `musl-gcc` and Docker/Podman.
2. **Missing product/evidence capability:** all non-control glibc rows, all
   transformed worker rows, all outer-profile transformed rows, and dynamic TLS
   HostContext rows because native validation currently accepts only the
   TLSIE TPREL64 symbolic relocation subset.

Those categories should remain separate in the parent: environment evidence is
not support, and a complete 60-row classification is not 60 transformed runtime
proofs.
