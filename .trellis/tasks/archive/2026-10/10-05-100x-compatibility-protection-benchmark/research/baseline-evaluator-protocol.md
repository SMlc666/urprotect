# 100x compatibility and Scheme-A evaluator research report

**Role:** independent planning/methodology review only.
**Repository:** `/root/urprotect`
**Active task:** `.trellis/tasks/10-05-100x-compatibility-protection-benchmark`
**Exact report path:** `.trellis/tasks/10-05-100x-compatibility-protection-benchmark/research/baseline-evaluator-protocol.md`

## Executive conclusion

The repository already has strong, bounded evidence for AArch64 parsing,
no-op/copy behavior, outer `execveat` packaging, HostContext handoff,
constructor/destructor/TLS/dependency negative boundaries, fixture/runtime
matrices, fuzzing, and CI evidence hygiene. It does **not** currently expose a
product-declared Protected Image stage, a rehydrator-to-Native-Image record, an
independent Scheme-A attack manifest, or frozen per-family attack baselines.

Therefore the evaluator must freeze the current checkout as a **1x snapshot of
what is actually measured**, while returning `baseline-zero`/`not-ready` for the
new strict chain and Scheme-A vector. Existing wrapper, frame, parser,
HostContext, and function-protection results remain retained auxiliary evidence;
none may be counted as a complete compatibility unit or 100x strength result.
This is the only way to satisfy the PRD's requirement that compatibility count
only `Protector -> Protected Image -> rehydration -> Native Image -> target
native loader -> behavioral oracle` and that every Scheme-A family independently
meet its own gate.

The concrete schemas, stage rules, formulas, attack protocols, budgets, and CI
artifact contracts are in the companion reports:

* [`repository-facts.md`](repository-facts.md) — measured repository inventory,
  current gaps, hashes, and command results;
* [`compatibility-protocol.md`](compatibility-protocol.md) — strict six-stage
  compatibility protocol and baseline/count rules;
* [`scheme-a-protocol.md`](scheme-a-protocol.md) — independent attack-family
  protocol, finite cost/lower-bound formula, raw evidence, and anti-gaming;
* [`ci-evidence-contract.md`](ci-evidence-contract.md) — evaluator boundary,
  artifact tree, environment statuses, CI graph, benchmark/fuzz retention, and
  analysis handoff.

## Measured current facts versus proposed rules

### Measured current facts

1. **Current implementation shape.** `FunctionProtectionService` rewrites
   selected functions directly into an ELF byte array. `PayloadFrameCodec`
   compresses a complete source image with Deflate and stores source/encoded
   SHA-256. `ElfPackService` appends the frame to a profile-matched launcher,
   round-trips it to source bytes, and publishes atomically. The current native
   outer launcher writes recovered source bytes to memfd and invokes
   `execveat`; the HostContext adapter seals an image memfd and delegates
   loading to the host's native `dlopen`/`dlsym` path.
2. **No strict Protected Image stage exists in the checkout.** A repository-wide
   search found no Protected Image, Scheme-A, red-team, dump/reassembly, or
   evaluator-vector protocol. Existing complete-source frames and direct
   protected ELF outputs must not be relabeled as the required stage.
3. **Protection E2E.** `run-protection-e2e.sh` exercises four explicit recipes
   over `fixtures/samples/protection`, compares protected/direct process status,
   stdout, and stderr, and retains report/readelf/hash evidence. It does not
   emit Protected Image/rehydration/Native Image records or attack work.
4. **Current wrapper evidence.** A retained generated pack report for
   `c-gcc-glibc-pie` records source size 70,392 bytes, Deflate encoded size
   2,757 bytes, frame v3, `outer-execveat`, and wrapper SHA-256. A retained
   HostContext report records frame v3, `host-context-entry`, and entry status
   23. These are observed artifacts from ignored generated state, not a new
   immutable baseline for this checkout.
5. **Corpus/matrix.** `fixtures/manifest.json` has 38 features and 13 cases
   (25 validated, 7 proven, 6 rejected feature rows). The real-sample registry
   has 100 public identities (78 glibc, 21 musl, one bionic); its checked-in
   aggregate is explicitly `registry-baseline` metadata. The runtime registry
   has six named cells and distinguishes native 16-KiB unavailability from a
   claim.
6. **Tests/fuzz/benchmarks/CI.** Existing tests cover parser, malformed ELF,
   frame/ABI, pack/launcher, HostContext, explicit protection, concurrency,
   large input, and golden reports. Fuzzing has only `elf` and `payload-frame`
   modes. The benchmark measures parse/validation/no-op operations on a
   synthetic ELF. CI has many separate evidence gates but no independent dual
   evaluator or immutable 1x/attack-vector baseline.
7. **Local validation.** Static manifest, fixture, regression, runtime-matrix,
   protection-policy, real-sample metadata/security, and coverage checks passed.
   The newest retained coverage report is overall line `0.7166`, branch
   `0.4102`; UrProtect.Core line `0.6930`, branch `0.6227`. The local runner is
   native AArch64 with 4-KiB pages and GCC 15.2/Clang 21.1/binutils 2.46, but
   `dotnet` is absent and the local kernel is Android-derived, so native product
   E2E was not re-run and no local runtime result was treated as current.

### Proposed evaluator rules

1. Freeze commit, PRD, corpus, runtime, attack, tool, environment, oracle, and
   raw-evidence hashes into one immutable baseline object. Never revise its
   denominator or threat model.
2. Count a compatibility unit only when all six named stages pass for the same
   source/profile/runtime/oracle and the target loader actually runs the exact
   Native Image bytes. Preserve every failed and unavailable row with a first
   failure layer.
3. Count unique, pre-registered provenance identities only. Keep a fixed view
   for non-regression and an append-only growth view for coverage improvement.
   Define `C = distinct complete unit IDs`; require exact integer
   `candidateGrowthC >= 100 * frozenBaselineC`, with no weighting or averaging.
4. If the current implementation yields no complete Protected Image-chain unit,
   record `baselineStatus=baseline-zero`; do not divide by zero or manufacture
   1x. A progress floor of one unit may be reported diagnostically but does not
   satisfy the claim until a positive baseline is frozen.
5. Run each required Scheme-A family with the same three replicas, attack recipe,
   seed, pinned toolset, native runtime, and fixed budget for baseline/candidate.
   Use CPU nanoseconds to first independently verified success; candidate
   failures that fully exhaust budget are censored lower bounds. Require finite
   baseline cost and conservative factor >=100 for each family independently.
6. Treat `environment-unavailable`, missing tools/capabilities, mixed replica
   outcomes, missing raw evidence, changed oracle, skipped family, or manual
   intervention as non-passing. `not-applicable` is valid only when pre-registered
   for a profile.
7. Keep raw attempt inputs/outputs, commands, resource counters, status/trace,
   crash/timeout records, and exact hashes. Sanitization may remove private
   paths/bytes only after hash and deterministic regeneration evidence is bound.
8. Leave current samples, negative fixtures, fuzz corpus, benchmark and CI jobs
   intact. Add chain/attack jobs and schemas alongside them; never let a new
   evaluator replace existing narrower evidence.

## Machine-checkable protocol summary

### Compatibility result

Each `compatibility/<unit-id>/unit.json` must include `sourceSha256`,
`unitId`, corpus/protocol/oracle/runtime hashes, six stage records, target-loader
identity, native-image hash, behavioral comparison hash, first failure layer,
and raw manifest hash. A stage record without an exact input/output artifact
hash is incomplete. `complete=true` is derived only by the evaluator, never
trusted from product output.

The Protected Image role manifest must identify a product-owned ABI/version,
producer build, source hash, exact artifact hash/size, and declared rehydrator
consumer. The rehydration record must bind that Protected Image hash to a
separate Native Image hash. The evaluator does not prescribe encoding,
relocation, or loading semantics and does not create a generic loader.

### Scheme-A result

Each `strength/<family>/replica-N/attempt.json` must include family/profile,
baseline/candidate role, unit/source/published hashes, attack/tool recipe hashes,
all resource budgets, classification, objective success result, CPU/wall/RSS
measurements, manual-step count, blue oracle evidence, recovered/modified
artifact hash, and raw manifest. `scheme-a-gate.json` records every required
family factor and passes only if all are >=100 with complete evidence.

Required families and objective success predicates are:

| Family | Objective success predicate |
| --- | --- |
| `runtime_dump_reassembly` | Reassembled artifact is accepted by target native loader and passes the frozen behavior oracle; partial dump does not count. |
| `patch_repack` | Pre-registered behavior mutation survives patch/repack, target loader accepts it, and the changed oracle is observed. |
| `function_logic_recovery` | Machine-readable recovered logic meets frozen function-vector/CFG/constant thresholds with zero manual steps and independent scoring. |
| `static_decomposition` | Pinned static toolchain recovers frozen segment/code/data/function/CFG inventory thresholds; complexity/hash/size alone does not count. |
| `dynamic_instrumentation` | Frozen internal trace/state threshold is recovered or a valid target accepts a pre-registered unauthorized replacement; missing ptrace/backend is unavailable, not failure/pass. |
| `integrity_handoff` | A tampered/replayed/repacked artifact reaches behavior or forbidden loader/entry marker, or bypasses a required pre-handoff rejection. Clean zero-handle fail-closed evidence is attack failure. |

## Baseline capture sequence

The future implementation/evaluator work should capture 1x in this order:

1. Validate and hash the append-only compatibility and Scheme-A manifests.
2. Build the exact current commit with the locked SDK/toolchains and record the
   runner/runtime facts. If required native tooling is absent, retain an
   environment-unavailable report instead of substituting local artifacts.
3. Run existing fixture, packed, HostContext, runtime, fuzz, stress, and
   protection E2E jobs as auxiliary evidence; retain their existing schemas.
4. Run the strict compatibility evaluator. For current code, it should expose
   the missing Protected Image/rehydration stages and freeze a zero/ not-ready
   result, not reinterpret outer wrappers.
5. Run the six attack recipes against the frozen current outputs. If any family
   lacks a reproducible finite attack baseline/tool capability, freeze
   `baseline-not-calibrated` rather than an arbitrary factor.
6. Close and hash all raw/normalized artifacts. Store the baseline under a
   content-addressed immutable ID and record its digest in CI configuration or
   an equally reviewable lock.

## CI claim rule and residual blockers

The independent evaluator emits a single machine-readable gate but keeps the
compatibility and Scheme-A decisions independent. A release/pre-merge claim is
allowed only when:

```text
antiGamingChecks == all-pass
and compatibility.status == measured
and compatibility fixed-view non-regression passes
and compatibility growth count >= 100 * frozen positive baseline count
and schemeA.status == pass
and every required family factor >= 100
```

Current residual blockers are concrete:

* no product-declared Protected Image ABI/rehydrator stage, so strict
  compatibility has no positive baseline denominator;
* no pinned attack-tool suite or machine-checkable logic-recovery/dynamic-
  instrumentation runner, so Scheme-A baselines are not calibrated;
* current benchmark/fuzz/CI evidence does not observe the new stages/families;
* local `dotnet` absence and the Android-derived local kernel prevent a fresh
  native product run in this inspection; ignored generated artifacts are not
  promoted to immutable current-commit evidence;
* the exact Scheme-A budget/replica manifest must be frozen before measuring,
  because changing it after baseline would move the 100x denominator.

These blockers should become explicit Trellis child-task gates rather than
being hidden by a weighted score, a sample reduction, a weaker oracle, or a
loader model not implemented by the repository.
