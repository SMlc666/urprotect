# Parent handoff: follow-on child for positive immutable compatibility baseline-v2

This file is the complete draft bundle requested by the analysis task. It is research-only; the child task has not been created here because task creation and task-file writes belong to the parent orchestrator.

## Exact parent command

```sh
python3 ./.trellis/scripts/task.py create \
  "Freeze positive immutable compatibility baseline v2" \
  --slug freeze-positive-immutable-baseline-v2 \
  --parent .trellis/tasks/10-05-100x-compatibility-protection-benchmark \
  --priority P0 --no-start
```

After creation, copy the five draft sections below into the child as `prd.md`, `design.md`, `implement.md`, `implement.jsonl`, and `check.jsonl`. Keep the child in planning until the parent reviews the package freshness blockers.

---

## Draft `prd.md`

```markdown
# Freeze positive immutable compatibility baseline v2

## Goal

Freeze the first positive immutable strict-chain compatibility denominator from a fresh, hash-closed evaluator run. Preserve the historical `compatibility-1x-baseline-zero` object, preserve the exact parent 100x compatibility rule, and leave Scheme-A independently `baseline-not-calibrated` with no strength claim.

## Authoritative starting evidence

The analysis child verified one retained strict unit at:

- evaluator tier: `.artifacts/evaluator/pr`;
- unit: `compat.protection-symbolized-fixture.glibc.outer-execveat`;
- retained evaluator evidence commit: `042a7d6d4e2d5f1c5ffe91d026d624ca995ad0bd`;
- checked-out commit at analysis time: `9574bca7fd5d11f8c998033603e7a0659b611b9d`;
- unit JSON SHA: `9fe0d3881021d32a1885d7c6e1ecfc47e6161014d345478d07ded8ef719c62b4`;
- unit raw manifest SHA: `f98745a844a78040c4b0c47bc9adfae353bfe05c185a6f33cc213142d9a75a49`;
- product-chain/product-evidence manifest SHA: `77726071141a04f945444d8045f7fac86b415fbd9ade05113228cdfa96bbfee5`;
- Protected Image SHA/size: `2e59a4472f11626a0a9465d049c8be0363c95189525b22cf66229114b276ba62` / `393`;
- Native Image SHA/size: `ede64f3fcc2c9651c8c92e3686bcd206f04ad783b72afdb415ef836de4505fff` / `73764`;
- loader: `kernel.execveat-at-empty-path`, handoff SHA `cb8475c4e8fe834555e03317adf27cb52f6f21193d717e3418a97f1b4b643850`;
- behavior comparison SHA: `179a03ec7a6e41f513ce74f7602434c238b52604c5d8f1d30371ef982672bcbf`;
- oracle: `fixture.process-oracle.v1`;
- historical zero-baseline object SHA: `3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2`.

The retained package has two blockers that require a fresh run before publication: its root manifest currently hashes to `111d39a69da8f4447a2553e618e00139995a1df8380d734c9f80909c81d4b588` while gate fields declare `27806fe7669d88dad9d510457e8d9623a9b51326a39aa7592aed698c63df2a63`, and its recorded commit `042a7d6...` does not equal the checkout `9574bca...`.

## Requirements

1. Rerun the compatibility strict-chain evaluator at one exact checked-out commit and retain a closed evaluator/product evidence tree.
2. Require evaluator root, unit raw, product-chain, and product-evidence manifest entry checks to pass; require the root manifest's observed SHA to equal both gate manifest fields.
3. Require the compatibility-scope environment to provide native AArch64, the pinned `glibc.current.native-arm64` cell, the Protected Image producer, the rehydrator, the locked SDK/toolchain, network-disabled inputs, and declared isolation. Scheme-A attack tooling is independent and may remain unavailable.
4. Verify exactly one fixed corpus row with all six stages passed for the same source image, profile, runtime cell, oracle, and run. Require distinct Protected Image and Native Image bytes and exact producer/rehydrator/native/loader/oracle links.
5. Publish a new content-addressed compatibility baseline payload and reference with one complete unit. Never overwrite or edit `compatibility-1x-baseline-zero`.
6. Preserve `compat-corpus-v1`, `evaluator-v1`, all corpus/protocol/oracle/runtime/fixture digests, and the parent 100x rule. Do not add a factor to the baseline-freeze result.
7. Record Scheme-A as `baseline-not-calibrated`, retain all six required families and `scheme-a-v1`, and emit no Scheme-A claim.
8. Retain a nearest-negative materialization/handoff witness showing that a failed stage publishes no Native Image/loader marker, or record the missing negative as a blocking local-gate result.

## Acceptance criteria

- [ ] `git rev-parse HEAD`, evaluator gate commit, and environment commit are equal for the run being frozen.
- [ ] Existing `compatibility-1x-baseline-zero` bytes and SHA `3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2` remain unchanged.
- [ ] The fresh evaluator root manifest is closed and its observed SHA equals both gate manifest digest fields; the independent evaluator checker passes.
- [ ] Exactly one complete strict unit passes all six stages with the expected hash links, distinct Protected/Native Image hashes, native loader status `0`, and frozen behavior comparison.
- [ ] `compatibility-1x-v2.json` and its reference are immutable/content-addressed/never-overwrite, and the reference digest equals the payload bytes.
- [ ] The local output `positive-baseline-v2-gate.json` is `pass`, records `completeUnits: 1`, and binds the producer, rehydrator, Native Image, loader, oracle, raw manifests, gate, and protocol/corpus identities.
- [ ] Scheme-A remains `baseline-not-calibrated` with null factors and all six required families; no `claimable=true` result is emitted.
- [ ] A failed check publishes no new baseline/reference and retains the prior zero-baseline fallback and raw failure evidence.

## Out of scope

- Product code, Protected Image encoding, rehydration semantics, loader behavior, or fixture redesign.
- Changing 100x, Scheme-A family membership, budgets, thresholds, oracle rules, corpus identity, or CI policy.
- Treating the one-unit baseline freeze as a 100x claim.
```

---

## Draft `design.md`

```markdown
# Positive immutable compatibility baseline-v2 design

## 1. Boundary

The child owns baseline-v2 evidence assembly and a read-only local gate over a fresh evaluator tree. The evaluator remains the source of stage status; this child does not infer stage success or implement loader semantics. Product, corpus, protocol, oracle, Scheme-A, and CI policy contracts remain owned by their existing layers.

The historical baseline object is immutable input:

```text
fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json
SHA-256: 3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2
```

New outputs are additive:

```text
fixtures/evaluator/baselines/compatibility-1x-v2.json
fixtures/evaluator/baselines/compatibility-1x-v2-reference.json
.artifacts/evaluator/pr/positive-baseline-v2-gate.json
```

## 2. Data flow

```text
fresh checkout/runtime
  -> strict evaluator
  -> closed evaluator/product evidence tree
  -> manifest + commit + capability checks
  -> six-stage/hash/oracle checks
  -> baseline-v2 payload
  -> content-addressed reference
  -> positive-baseline-v2 local gate
```

A failed precondition stops publication. The previous zero baseline remains the only active fallback; direct protected-ELF evidence remains auxiliary for strict-chain counting.

## 3. Baseline payload contract

The payload retains the existing compatibility baseline kind and records:

- `schemaVersion: 1`;
- a new reviewed `baselineVersion` such as `compatibility-1x-v2`;
- exact evaluator/product commit and environment identity;
- corpus/protocol/runtime/fixture/oracle/toolchain digests;
- `fixedCorpusRows: 1`, `completeUnits: 1`, and one exact `completeUnitId`;
- unit JSON/raw/product manifest hashes;
- source image, producer ID/build hash, Protected Image ABI/version/size/hash;
- rehydrator consumer/build hash and rehydration record hash;
- Native Image ABI/version/size/hash;
- target-loader ID, handoff/evidence hash, status, signal;
- behavior oracle ID/comparison hash and passed comparisons;
- `schemeAStatus: baseline-not-calibrated`, the Scheme-A manifest/policy digest, and `schemeAClaimable: false`;
- `immutable: true`, `contentAddressed: true`, `neverOverwrite: true`.

The reference is the non-circular content address:

```json
{
  "schemaVersion": 1,
  "kind": "evaluator-baseline-reference",
  "baselineArtifactId": "compatibility-1x-v2",
  "baselineArtifactPath": "fixtures/evaluator/baselines/compatibility-1x-v2.json",
  "baselineArtifactSha256": "SHA256_OF_PAYLOAD_BYTES",
  "corpusVersion": "compat-corpus-v1",
  "protocolVersion": "evaluator-v1",
  "completeUnits": 1,
  "baselineStatus": "measured",
  "strengthStatus": "baseline-not-calibrated",
  "immutable": true,
  "contentAddressed": true,
  "neverOverwrite": true
}
```

## 4. Local gate algorithm

The checker must fail closed in this order:

1. Compare checkout, evaluator gate, and environment commits.
2. Verify all root/nested manifest entries and compare the actual root manifest SHA with both gate digest fields.
3. Verify compatibility-scope capabilities and native runtime identity. Keep Scheme-A capability/status separate.
4. Verify corpus/protocol/oracle/runtime/fixture identities and duplicate-free fixed rows.
5. Verify one unit with exactly six required stage keys, all `passed`, no first failure, native results captured, and same unit/source/profile/runtime/oracle binding.
6. Recompute Protected Image, Native Image, source-image, and retained manifest hashes; require Protected and Native Image hashes to differ.
7. Verify target-loader process evidence and behavioral oracle equality.
8. Verify old zero baseline digest and bytes are unchanged.
9. Build the new payload/reference once and verify reference SHA against payload bytes.
10. Verify Scheme-A remains six-family `baseline-not-calibrated` with null factors and no claim.
11. Emit a deterministic gate record with `status: pass`; otherwise emit `status: blocked` without publishing the baseline/reference.

The gate is a local compatibility-baseline gate. Once the payload is frozen, the parent evaluator still computes:

```text
candidateGrowthCompleteUnits >= 100 * frozenBaselineCompleteUnits
```

so the new denominator of one implies a future growth target of 100. The baseline freeze itself does not satisfy that target.

## 5. Rollback

- Before publication: delete no historical artifacts; retain the failed evaluator tree and emit blocked diagnostics only.
- After publication: never overwrite v2. Disable only the v2 strict-chain baseline/profile selection on regression and use the prior passing reference while retaining v2 evidence.
- Any changed corpus, protocol, oracle, budget, toolchain, runtime, or threat model receives a new content-addressed baseline version.
- A failed Protected Image/rehydration stage has no direct-ELF fallback for a strict row.
- Scheme-A remains independently gated and is never promoted by this child.
```

---

## Draft `implement.md`

```markdown
# Positive immutable compatibility baseline-v2 implementation plan

## Execution rules

- Keep this child in planning until parent review approves the package freshness and environment prerequisites.
- Do not edit product code or Scheme-A policy.
- Do not mutate `compatibility-1x-baseline-zero`; all outputs are additive and content-addressed.
- Retain failed/unavailable evidence with `if: always()`-style artifact retention in the eventual CI integration; this child itself only defines the local gate.

## Step 1 — Preflight and exact evidence commit

1. Resolve the active child task and record parent/spec hashes.
2. Run `git rev-parse HEAD` and require the evaluator run to be produced from that exact commit.
3. Confirm the frozen zero-baseline object/reference SHA before any new publication.
4. Provision the declared native AArch64 glibc cell with network-disabled inputs, producer, rehydrator, locked SDK/toolchain, and evaluator isolation.

**Rollback:** stop before writing any baseline-v2 file if the commit or capability precondition fails.

## Step 2 — Fresh evaluator run and closure

Run the existing protocol/evaluator at the exact checkout:

```sh
python3 scripts/validate-evaluator-manifests.py fixtures/evaluator/...
./scripts/run-independent-evaluator.sh --tier pr
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
```

Verify:

```sh
(cd .artifacts/evaluator/pr && sha256sum -c SHA256SUMS)
(cd .artifacts/evaluator/pr/compatibility/compat.protection-symbolized-fixture.glibc.outer-execveat/raw && sha256sum -c SHA256SUMS)
(cd .artifacts/protected-image/pr/glibc/compat.protection-symbolized-fixture.glibc.outer-execveat && sha256sum -c SHA256SUMS)
```

Require the root `SHA256SUMS` observed hash to equal both `gate.json` manifest fields. Record the exact fresh gate, analysis-input, unit, nested manifests, product manifest, protocol, corpus, oracle, and environment hashes.

**Rollback:** preserve the failed tree and do not publish a baseline/reference.

## Step 3 — Implement the local checker and deterministic payload projection

Add the smallest machine-checkable checker in the evaluator/control-plane ownership area (no product path changes):

```sh
python3 scripts/check-positive-immutable-baseline-v2.py \
  --evaluator-root .artifacts/evaluator/pr \
  --product-root .artifacts/protected-image/pr/glibc/compat.protection-symbolized-fixture.glibc.outer-execveat \
  --previous-baseline fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json \
  --output .artifacts/evaluator/pr/positive-baseline-v2-gate.json
```

The checker must read only the declared inputs, reject traversal/symlink/unclosed paths, verify all conditions in `design.md`, and emit `blocked` without baseline publication on any failure.

The payload projection must use deterministic JSON serialization and an external reference SHA. It must include exact stage and artifact hashes rather than only status flags.

## Step 4 — Freeze the positive baseline/reference

After the checker passes on the fresh tree:

1. Write `compatibility-1x-v2.json` once.
2. Compute its SHA-256 from the retained bytes.
3. Write `compatibility-1x-v2-reference.json` with that SHA and immutable/content-addressed/never-overwrite flags.
4. Re-run the checker against the written payload/reference.
5. Verify the old zero-baseline object/reference hashes remain unchanged.

The output must say compatibility baseline frozen, not claimable. Scheme-A remains `baseline-not-calibrated`.

## Step 5 — Focused validation and review

Run:

```sh
python3 scripts/check-positive-immutable-baseline-v2.py \
  --evaluator-root .artifacts/evaluator/pr \
  --product-root .artifacts/protected-image/pr/glibc/compat.protection-symbolized-fixture.glibc.outer-execveat \
  --previous-baseline fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json \
  --baseline fixtures/evaluator/baselines/compatibility-1x-v2.json \
  --baseline-reference fixtures/evaluator/baselines/compatibility-1x-v2-reference.json \
  --output .artifacts/evaluator/pr/positive-baseline-v2-gate.json
python3 tests/test_compatibility_evaluator.py
python3 tests/test_scheme_a_evaluator.py
```

The compatibility test must assert the one-unit denominator and exact hash links; the Scheme-A test must assert unchanged six-family `baseline-not-calibrated` semantics. Add a nearest-negative materialization/handoff evidence check if the product child exposes it; missing negative evidence remains a visible blocker rather than a silent pass.

## Step 6 — Parent review and rollback point

Parent review confirms:

- old zero baseline unchanged;
- fresh commit/root-manifest closure passed;
- exactly one complete strict unit and exact role/hash links;
- new baseline/reference content address and immutable flags;
- Scheme-A remains independent and non-claimable;
- no 100x result is reported.

If review fails, retain all evidence, remove only the new local baseline/profile selection, and return to the historical zero-baseline reference. Never overwrite v2 or weaken the parent growth rule.
```

---

## Draft `implement.jsonl`

```jsonl
{"id":"preflight-fresh-commit","title":"Require evaluator evidence and checkout commit identity","inputs":[".artifacts/evaluator/pr/environment.json",".artifacts/evaluator/pr/gate.json"],"expected":"environment.commit == gate.commit == git rev-parse HEAD","rollback":"publish no baseline/reference"}
{"id":"close-evaluator-manifests","title":"Verify evaluator, strict-unit, product-chain, and product-evidence manifests","inputs":[".artifacts/evaluator/pr/SHA256SUMS","compatibility/.../raw/SHA256SUMS","compatibility/.../raw/product-chain/SHA256SUMS",".artifacts/protected-image/pr/glibc/.../SHA256SUMS"],"expected":"all entries pass and actual root manifest SHA equals both gate manifest fields","rollback":"retain failed evaluator tree; publish no baseline/reference"}
{"id":"strict-unit-projection","title":"Verify one complete six-stage unit and exact artifact links","inputs":["compatibility/.../unit.json","compatibility/.../raw/product-chain/*.json","compatibility/.../raw/*.bin"],"expected":"six stages passed, source/profile/runtime/oracle consistent, Protected Image and Native Image hashes distinct, target status 0, oracle equal","rollback":"return blocked status; preserve historical baseline-zero"}
{"id":"baseline-v2-payload","title":"Emit immutable one-unit baseline-v2 payload and external reference","inputs":["fresh evaluator gate","fresh unit/raw/product manifests","previous baseline reference"],"expected":"payload completeUnits=1; reference SHA equals payload bytes; old zero baseline hash unchanged","rollback":"do not publish on failure; never overwrite v2"}
{"id":"scheme-a-independent-status","title":"Keep Scheme-A policy and status independent","inputs":["scheme-a-manifest.json","scheme-a-gate.json"],"expected":"six required families remain; status baseline-not-calibrated; factors null; no Scheme-A claim","rollback":"reject any policy/status drift"}
{"id":"local-gate-output","title":"Emit positive-baseline-v2 local gate","inputs":["baseline-v2 payload/reference","fresh evaluator evidence"],"expected":"positive-baseline-v2-gate.json status=pass with exact source and stage hashes","rollback":"status=blocked and no new baseline/reference"}
```

---

## Draft `check.jsonl`

```jsonl
{"id":"old-baseline-immutable","command":"sha256sum fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json","expected":"3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2","failure":"block publication"}
{"id":"fresh-commit-binding","command":"python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr","expected":"pass; environment/gate commit equals checkout","failure":"retain evidence and block publication"}
{"id":"root-manifest-closure","command":"(cd .artifacts/evaluator/pr && sha256sum -c SHA256SUMS)","expected":"all entries OK; observed SHA256SUMS SHA equals gate.artifactManifestSha256 and gate.rawEvidenceManifestSha256","failure":"block publication"}
{"id":"nested-manifest-closure","command":"sha256sum -c compatibility/.../raw/SHA256SUMS && sha256sum -c compatibility/.../raw/product-chain/SHA256SUMS","expected":"all entries OK and parent hashes agree","failure":"block publication"}
{"id":"one-strict-unit","command":"python3 scripts/check-positive-immutable-baseline-v2.py --evaluator-root .artifacts/evaluator/pr --product-root .artifacts/protected-image/pr/glibc/compat.protection-symbolized-fixture.glibc.outer-execveat --previous-baseline fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json --output .artifacts/evaluator/pr/positive-baseline-v2-gate.json","expected":"status=pass; fixedRows=1; completeUnits=1; all six stages passed; distinct Protected/Native Image hashes; loader/oracle passed","failure":"status=blocked; no baseline/reference"}
{"id":"baseline-reference-binding","command":"sha256sum fixtures/evaluator/baselines/compatibility-1x-v2.json","expected":"equals compatibility-1x-v2-reference.json:baselineArtifactSha256; immutable/contentAddressed/neverOverwrite=true","failure":"block publication"}
{"id":"scheme-a-no-claim","command":"python3 tests/test_scheme_a_evaluator.py","expected":"six required families unchanged; baseline-not-calibrated; null factors; no claim","failure":"reject policy/status drift"}
{"id":"rollback-publication","command":"python3 scripts/check-positive-immutable-baseline-v2.py --help","expected":"implementation documents blocked/no-publication behavior and prior zero-baseline fallback","failure":"parent review blocker"}
```

## Required review decision

Approve this child only after the parent acknowledges that the current retained package is useful strict-unit evidence but is not yet a publishable baseline-v2 input because of the root-manifest digest mismatch and evaluator-vs-checkout commit mismatch. 
