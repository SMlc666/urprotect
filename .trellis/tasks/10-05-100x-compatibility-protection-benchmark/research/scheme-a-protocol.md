# Proposed Scheme A protection-strength evaluator

This protocol measures a versioned attack vector. It does not infer resistance
from compressed size, a hash, a parser diagnostic, or visual complexity. The
blue behavior/oracle run is performed first; an attack result is meaningful
only when it identifies whether a target artifact still behaves correctly and
whether an unauthorized modification was accepted.

## 1. Vector, profiles, and frozen threat model

The required vector is:

```text
StrengthVector = {
  runtime_dump_reassembly,
  patch_repack,
  function_logic_recovery,
  static_decomposition,
  dynamic_instrumentation,
  integrity_handoff
}
```

The evaluator owns a versioned `scheme-a-manifest.json` containing:

* exact required family IDs and family/profile applicability;
* fixture IDs and source/protected artifact hashes;
* attack recipe and toolchain digests;
* objective success predicates and ground-truth hashes;
* replica count and resource budget;
* baseline artifact ID and its immutable digest; and
* the threat-model statement (attacker may read/execute the published artifact,
  may use only listed tools, may not modify the evaluator or oracle, and has no
  secret blue-team input).

The initial required profile should be the native AArch64 glibc Scheme-A
fixture because the checked-in protection fixture, current native launcher, and
managed HostContext lifecycle oracles are all already centered on that lane.
A musl or bionic family row is added only when its profile manifest declares the
family applicable and has a real native oracle. If a family is pre-registered
as required for a profile, missing tools/capabilities are
`environment-unavailable`, not a reason to delete that row.

Current code has no Scheme-A manifest or attack runner. Therefore the first
snapshot must be `strengthStatus=baseline-not-calibrated` until the attack
recipes below have finite, reproducible baseline observations. This is an
explicit protocol state, not a claimed strength result.

## 2. Cost and 100x rule

Each family runs exactly `R=3` deterministic replicas for baseline and
candidate with identical source digest, random seed, command sequence, tool
versions, target runtime, and resource budget. The default proposed budget,
to be frozen before baseline capture, is:

```text
wall time per replica:       60 seconds
attacker CPU time:           45 seconds
peak RSS:                    1 GiB
processes/threads:           32
captured output:             16 MiB
raw dump/recovered artifact: 256 MiB
manual steps:                0
network:                     disabled
```

A pilot may calibrate these numbers before `scheme-a-baseline-v1` is frozen;
after that, changing them creates a new scheme/version and baseline. The same
limits apply to baseline and candidate. `timeout`, RSS, process-limit, and
sandbox evidence are retained rather than inferred from a process exit code.

Primary work is total CPU nanoseconds consumed by the attack process tree up to
the first independently verified success. This avoids counting attacker sleep
or arbitrary wall-clock delay. A fixed 1 ms floor is used only in the ratio
to avoid division by zero:

```text
baselineCost_f = max(successCpuNs over the 3 successful baseline replicas)
candidateCost_f = min(successCpuNs over the 3 successful candidate replicas)
```

For a candidate that was fully attempted and did not achieve the success
predicate in any replica, `candidateCost_f` is the frozen CPU budget and
`censored=true`; this is a lower bound, not an infinite cost. A candidate that
succeeds in some replicas and fails in others is `unknown`/protocol failure,
not a favorable average. A baseline family must have three reproducible,
finite successes; otherwise its frozen baseline is `baseline-not-calibrated`
and Scheme A is not claimable.

The family factor is the conservative lower bound:

```text
factor_f = candidateCost_f / max(baselineCost_f, 1 ms)
```

A family passes only when `factor_f >= 100.0`, the candidate behavior/oracle
remains valid, all raw evidence and budget checks pass, and its baseline is
finite and immutable. If a candidate attack succeeds, it may still pass only
if its verified cost is at least 100x the frozen baseline. If it does not
succeed within the fixed budget, the budget must itself be at least 100x the
frozen baseline; otherwise the result is `bounded-below-100`, not a pass.

The Scheme-A gate is a conjunction, never an average:

```text
schemeA_pass = every required family has status=pass and factor >= 100.0
```

The report may include `minFactor` as a diagnostic, but one family must not
compensate for another. Historical family rows, recipes, baselines, and threat
models are append-only. A new family is first measured and frozen as its own
baseline before it becomes required.

## 3. Common attempt record and raw evidence

Every replica produces `attempt.json`:

```json
{
  "schemaVersion": 1,
  "familyId": "runtime_dump_reassembly",
  "profile": "scheme-a-glibc-v1",
  "replica": 1,
  "role": "baseline-or-candidate",
  "unitId": "compat.protection-symbolized-fixture.glibc",
  "sourceSha256": "SOURCE_SHA256",
  "publishedArtifactSha256": "ARTIFACT_SHA256",
  "attackRecipeSha256": "ATTACK_RECIPE_SHA256",
  "toolchain": {
    "name": "PINNED_ATTACK_TOOLSET",
    "version": "PINNED_VERSION",
    "binarySha256": "TOOL_BINARY_SHA256"
  },
  "budget": {
    "wallSeconds": 60,
    "cpuSeconds": 45,
    "rssBytes": 1073741824,
    "processLimit": 32,
    "outputBytes": 16777216,
    "rawArtifactBytes": 268435456,
    "manualSteps": 0
  },
  "classification": "attack-success",
  "goalAchieved": true,
  "successCpuNs": 123456789,
  "censored": false,
  "blueOracle": {"status": "passed", "evidenceSha256": "..."},
  "recoveredArtifactSha256": "RECOVERED_SHA256",
  "recoveredArtifactSize": 1234,
  "resourceEvidence": "raw/resources.json",
  "stdout": "raw/attack.stdout",
  "stderr": "raw/attack.stderr",
  "commandLog": "raw/command.log",
  "manualStepsObserved": 0,
  "rawEvidenceManifest": "raw/SHA256SUMS"
}
```

Allowed classifications are `attack-success`, `attack-failed`,
`environment-unavailable`, `tool-not-applicable`, `unknown`, and
`protocol-failure`. The required gate accepts only a fully measured
`attack-success` baseline and a candidate measured as a verified
`attack-success` at >=100x or a verified, budget-exhausted failure with the
same lower bound. `environment-unavailable`, missing raw files, tool crashes,
oracle mismatch, mixed replica outcomes, and manual intervention does not pass.
`tool-not-applicable` is allowed only for an explicitly non-required profile
row and remains visible in the vector.

Raw evidence is created before normalization: original attack input, command
and environment transcript, tool output, dump/recovery/patch bytes, target
loader status, oracle output, resource counters, crash/timeout artifacts, and
all intermediate hashes. CI may sanitize private paths or remove raw binaries
from an uploaded public artifact only after recording their exact hash, size,
producer command, and `rawPresentDuringEvaluation=true`. A required raw hash
without raw evidence/derivation is not a measured pass. No symlinks, unbounded
logs, or post-gate mutable paths are accepted.

## 4. Family protocols

### A. Runtime dump and reassembly (`runtime_dump_reassembly`)

**Existing evidence:** the outer launcher reads its own wrapper and recovers a
complete source ELF; the current frame has source/encoded SHA-256 and Deflate;
the native handoff uses memfd/execveat. This supplies a deterministic fixture
and integrity oracle, but no red-team dump measurement.

**Fixed recipe:** run the published protected artifact in the declared runtime
with a pre-registered trigger/checkpoint. Capture only observations allowed by
the Scheme-A threat model (mapped executable/data ranges, process metadata,
loader-visible file descriptor state, and declared runtime trace). Reassemble
an artifact without using product private state; record missing ranges,
permissions, relocations/metadata copied, command steps, CPU/resource counts,
and all bytes/hashes.

**Success:** the reassembled output is accepted by the target native loader and
passes the frozen behavioral oracle. A memory dump, byte-identical fragment,
partial code image, parser result, or a process trace alone is not success.
The successful output and the exact reassembly recipe are raw evidence.

### B. Patch and repack (`patch_repack`)

**Existing evidence:** `native/urprotect-launcher/test_launcher.sh` already
mutates frame version/flags/architecture/name/offset/length, source size,
Deflate, source digest, interpreter, and truncation. HostContext tests also
exercise sealed images, loader-environment gates, and rollback. These are
negative integrity tests, not a measured attack vector.

**Fixed recipe:** select one pre-registered behavior-bearing mutation in the
protection fixture (for example a target function result or entry decision),
patch the recovered/intermediate bytes, and repack using only listed attacker
operations. Recompute fields that are intentionally public, but do not use
blue-team private keys or evaluator files. Run the exact target loader and
oracle.

**Success:** the modified behavior is observed by the oracle in an artifact
accepted by the target loader, while the attack did not invoke a product
source/build step. A rejected patch, a malformed artifact, or a changed file
that never reaches execution is an attack failure with raw proof.

### C. Function-logic recovery (`function_logic_recovery`)

**Existing evidence:** AsmStone is vendored behind a project adapter;
`Aarch64Analyzer`, `FunctionProtectionTests`, and the protection fixture have
symbol-bounded functions and a CFG-sensitive branch target. The repository has
no recovery scorer or attacker tool.

**Fixed recipe:** the challenge manifest provides a ground-truth set of
function IDs, input vectors, output values, basic-block/edge labels, call
relations, and key constants generated from the committed fixture source and
verified before publication. The attacker writes a bounded machine-readable
`recovered-logic.json` and runs it through an independent evaluator, not a
human reviewer.

**Success:** all required semantic vectors and the registered structural
threshold are recovered with no manual steps; the scorer records exact
precision/recall and false-positive counts. Structural discovery alone is not
logic recovery, and a guessed answer that fails the independent behavior
vectors is not success. Keep the quality threshold frozen and separate from
static decomposition so the two families do not double-count the same output.

### D. Static decomposition (`static_decomposition`)

**Existing evidence:** `readelf`, the managed ELF parser/validator, real-sample
fingerprints, AsmStone, and malformed corpus are already used in CI. No fixed
attacker command or cost baseline currently exists.

**Fixed recipe:** use the pinned static toolset directly on the published
artifact with no runtime observation. Produce `static-inventory.json` with
segment/file ranges, code/data partition, symbols/debug leakage, function
boundaries, and CFG skeleton for the pre-registered challenge targets. The
independent scorer compares it with the fixture ground truth.

**Success:** the frozen structural thresholds are met (for example exact
executable-range recovery and the required function/edge inventory) with raw
tool output and resource evidence. Hashes, compressed size, a parser pass, or
an assertion that the image “looks complex” are never success criteria.

### E. Dynamic instrumentation (`dynamic_instrumentation`)

**Existing evidence:** HostContext has lifecycle/entry oracles and the native
launcher has handoff mutations, but CI does not currently lock a ptrace,
tracing, or instrumentation framework. `strace` availability on one local
machine is not a repository capability.

**Fixed recipe:** the evaluator image pins one declared instrumentation backend
and capability check. The challenge fixture registers a fixed set of internal
state/edge labels and an optional controlled replacement target. The attacker
runs the same observation/injection recipe for baseline and candidate and
records attach status, event trace, breakpoints/hooks, replacement bytes, and
resource limits.

**Success:** either the required trace/state set is recovered to the frozen
threshold, or the attacker causes the pre-registered unauthorized behavior
while the target is otherwise valid. A missing ptrace/seccomp/kernel feature is
`environment-unavailable`, not an attack failure and not a pass. A trace of
only startup syscalls is not an internal-logic success.

### F. Integrity and handoff (`integrity_handoff`)

**Existing evidence:** frame SHA-256 checks, launcher mutation tests, sealed
HostContext memfds, profile/ABI mismatch rejection, fake-loader environment
rejection, and loader rollback are already present. This family should extend
those exact mutation fixtures rather than inventing a second integrity model.

**Fixed recipe:** run the append-only matrix of truncation, replacement, replay,
version/profile mismatch, individual header/length/hash mutations, recomputed
public digest, delayed post-write mutation, fake-loader/path influence, and
final Native Image handoff tampering. Record the earliest rejection layer,
status/diagnostic, whether any image handle was published, seal state,
loader/entry markers, and descriptor counts before/after.

**Success:** any tampered/replayed/repacked artifact reaches the target
behavioral oracle or a forbidden loader/entry marker, or bypasses a required
pre-handoff rejection while preserving attacker-controlled behavior. A clean
fail-closed rejection with zero handle/no entry marker is an attack failure.
The test's own success must still pass the blue baseline oracle; an unrelated
crash is `unknown` until classified.

## 5. Anti-gaming invariants

The independent evaluator enforces all of these before evaluating the vector:

1. Baseline and candidate use the exact same corpus, fixture bytes, runtime cell,
   oracle ID, attack recipe hash, tool binary hashes, seed, replicas, and
   budgets. The candidate must not ship a modified evaluator, fixture, oracle, or
   attack recipe.
2. A family result must reference every required replica and every raw command,
   including failed, timed-out, crashed, and environment checks. Missing or
   early-omitted attempts are protocol failures.
3. A candidate must not improve by deleting a family, reclassifying a required
   row as not-applicable, reducing the oracle, changing threat-model rights,
   changing the target loader, reducing the corpus, or suppressing negative
   evidence. Historic rows are append-only.
4. A complete compatibility unit requires all six product stages; parser-only,
   pack-only, frame-only, HostContext-only, no-op-copy, handoff-only, and
   static-only results remain diagnostic evidence.
5. A successful attack must produce a loader-accepted artifact/trace and an
   independent behavior or modification oracle. Raw extraction, disassembly,
   compression ratio, hash presence, or “more instructions” does not stand alone.
6. CPU cost includes all child processes and stops at first independently
   verified success. Sleep, retries outside the recipe, human work, and
   unbounded output do not inflate resistance. Manual steps are zero for a
   required machine gate.
7. The baseline is immutable and content-addressed. A family whose baseline is
   already unattackable is not silently assigned zero cost or infinity; it is
   `baseline-not-calibrated` until a finite protocol exists.
8. The evaluator runs independently of product code changes and never writes
   source, manifests, product config, task state, or baseline artifacts.

## 6. Vector result

`scheme-a-gate.json` has this shape:

```json
{
  "schemaVersion": 1,
  "scheme": "A",
  "protocolVersion": "scheme-a-v1",
  "baselineArtifactId": "scheme-a-baseline-BASELINE_DIGEST",
  "requiredFamilies": [
    "runtime_dump_reassembly",
    "patch_repack",
    "function_logic_recovery",
    "static_decomposition",
    "dynamic_instrumentation",
    "integrity_handoff"
  ],
  "families": {
    "runtime_dump_reassembly": {
      "status": "pass",
      "baselineCostCpuNs": 1000000,
      "candidateCostLowerBoundCpuNs": 100000000,
      "factorLowerBound": 100.0,
      "censored": true,
      "evidenceSha256": "..."
    }
  },
  "schemeAStatus": "not-ready",
  "minimumFactorDiagnostic": null,
  "rawEvidenceManifest": "SHA256SUMS"
}
```

`schemeAStatus=pass` is emitted only when every required family is `pass` and
its independent factor is >=100. `not-ready`, `environment-unavailable`,
`baseline-not-calibrated`, `unknown`, and `protocol-failure` are retained and
block a claim. There is no weighted strength score.
