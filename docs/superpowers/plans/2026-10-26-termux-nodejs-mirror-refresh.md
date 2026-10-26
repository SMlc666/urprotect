# Verified Termux Node.js Archive Mirror Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore PR CI acquisition of the locked Termux Node.js 26.4.0-1 sample by switching only its source archive URL to a listed Termux mirror that serves the exact locked bytes.

**Architecture:** Keep the existing package identity, archive path, version, size, SHA-256, install repository, execution policy, runtime status, and compatibility claims unchanged. Update the single canonical expected URL and its current registry owners, then refresh only derived lock/manifest metadata digests and the metadata-only aggregate.

**Tech Stack:** Python unittest and registry validators; JSON registries; bounded HTTPS download for the local archive verification.

**Spec:** PR #30 (`fix/superpowers-migration-pr`) adds `docs/engineering/specs/backend/runtime-compatibility.md`, Scenario: Real-sample archive identity refresh and registry digest chain. This spec is not yet present on `origin/main`; the follow-up PR will remain based on `main` so the mirror repair can unblock PR #30.

## Global Constraints

- The exact locked archive remains `nodejs_26.4.0-1_aarch64.deb`, 10,349,280 bytes, SHA-256 `eaf3ed8a6e4b72ebaa8c2cb3bad778c577cdf9ea87ca91761213d8a3940fc090`.
- A different mirror is acceptable only after the existing size and SHA-256 match; do not refresh archive identity from bytes returned by a new URL.
- Keep the Termux package installation repository `https://packages-cf.termux.dev/apt/termux-main` unchanged; only source-archive acquisition provenance changes.
- Keep the 100 project identities, Node.js identity/fingerprint, expected statuses, runtime claims, and all execution policies unchanged.
- Keep raw archives and extracted binaries in private temporary storage; do not check them in or upload them.
- Regenerate the checked-in aggregate only with the registry-only renderer; do not update frozen product evidence.

## Review Focus

- The alternate source URL is listed by Termux and actually serves the exact locked bytes; the test and private download independently pin this.
- The source URL agrees across the canonical lock validator, reviewed lock, selected manifest, and candidate ledger.
- Runtime-closure lock digest and the compatibility-corpus manifest digest match their current files.
- The metadata-only aggregate is regenerated without changing runtime classifications or statuses.
- The package installation repository, package row, dependencies, project identity, and runtime policy do not change.

---

### Task 1: Refresh the verified source mirror without changing archive identity

**Files:**
- Modify: `tests/test_bionic_node_runtime_lock.py`
- Modify: `scripts/bionic_node_lock.py`
- Modify: `fixtures/real-samples/bionic-node-runtime-lock.json`
- Modify: `fixtures/real-samples/manifest.json`
- Modify: `fixtures/real-samples/candidates.json`
- Modify: `fixtures/real-samples/runtime-closures.json` (derived Node.js lock digest only)
- Modify: `fixtures/evaluator/compatibility-corpus.json` (derived real-sample manifest digest only)
- Regenerate if required by the renderer: `fixtures/real-samples/baseline-aggregate.json` and `.md`

- [x] **Step 1: Write the failing URL synchronization regression.** Update the literal expected source URL in `test_node_source_archive_url_is_synchronized_without_changing_package_identity` to `https://mirror.iscas.ac.cn/termux/apt/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb`; retain assertions for exact version, size, SHA-256, install repository, and unchanged runtime policy.
- [x] **Step 2: Verify RED.** Run `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bionic_node_runtime_lock.BionicNodeRuntimeLockTests.test_node_source_archive_url_is_synchronized_without_changing_package_identity`; it must fail because the current canonical URL/registry owners still point at TUNA.
- [x] **Step 3: Apply the URL-only change.** Set the canonical `NODE_SOURCE_URL` and source-archive URL owners to the verified ISCAS mirror. Leave all package bytes/metadata and runtime outcomes untouched; recompute the bionic Node.js lock SHA-256 and selected-manifest SHA-256 owners. Regenerate the metadata-only aggregate only with `python3 scripts/render-real-sample-report.py fixtures/real-samples/manifest.json --tier pr --registry-only --artifact-root fixtures/real-samples --output-json fixtures/real-samples/baseline-aggregate.json --output-markdown fixtures/real-samples/baseline-aggregate.md` if the output depends on the manifest URL.
- [x] **Step 4: Verify GREEN and registry closure. Focused registry tests: 106/106; full Python suite: 471 passed, 2 skipped. Both registry validators passed; Release build had 0 warnings/errors. Registry-only rendering produced no aggregate diff.** Run the focused lock test, `tests.test_real_sample_manifest`, `tests.test_real_sample_fingerprint`, `tests.test_real_sample_evidence`, `tests.test_real_sample_aggregate`, and `tests.test_runtime_closures`; run the real-sample and runtime-closure validators with `PYTHONPATH` unset. Build Release assemblies if required by runtime-matrix tests, then run `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'`. Confirm the 100-identity count and that only source URL and derived metadata digests changed.
- [x] **Step 5: Review and commit.** `git diff --check` passed; the restricted diff was reviewed and will be committed as `fix: use verified Termux mirror for locked Node.js archive`. Run `git diff --check`, inspect every changed JSON field and digest owner, and commit as `fix: use verified Termux mirror for locked Node.js archive`.
