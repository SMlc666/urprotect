# TLS Measured Runtime Evidence Contract

## 1. Scope / Trigger

Apply this contract when changing TLS evidence producers, wrapper callers, matrix
checkers, runtime identity records, or nested rehydration consumers. It augments
[runtime compatibility](./runtime-compatibility.md); it does not promote managed
semantic support into native execution or close the parent task's open scope.

## 2. Signatures

```sh
bash scripts/run-tls-host-context-rehydration-e2e.sh \
  --tier TIER --model MODEL --profile host-context-entry --runtime glibc \
  --lifecycle current-thread --unit UNIT --source ELF \
  --function-id TABLE:INDEX --entry-status 43 --producer-id PRODUCER
python3 scripts/run-tls-runtime-matrix.py --tier TIER --artifact-root NEW_ROOT
python3 scripts/check-tls-runtime-matrix-evidence.py ARTIFACT_ROOT
```

`scripts/tls_runtime_identity.py` owns:

```text
identify_native_glibc() -> measured identity with identitySha256
verify_identity(value, verify_current_process=True) -> producer-local validation
verify_artifact_identity(value) -> portable retained-fact validation
```

`TLS_EVIDENCE_ARTIFACT_ROOT` selects the wrapper artifact parent; normalize a
relative value before invoking downstream producers. CI and the matrix caller
must use the same explicit wrapper contract; test the actual invocation tokens.

## 3. Contracts

- The wrapper requires every argument above. Its closed registry/selector
  contract binds model, source fixture, function table/index/name, producer,
  expected entry status, unit, runtime, profile, and lifecycle before publication.
  Do not supply initial-exec defaults for a different model.
- Canonical promotion is exactly the registry's `promotedRows`. Currently four
  models (`initial-exec`, `local-dynamic`, `general-dynamic`, `tlsdesc`) have
  native AArch64 glibc HostContext current-thread evidence. Other tuples remain
  unpromoted, including local-exec, workers, outer TLS, musl, and bionic.
- Each accepted row binds `stage.json` `tlsEvidence` model/runtime/profile/
  lifecycle, `expectedEntryStatus`, source/protected/native paths and hashes,
  runtime identity, and the corresponding matrix row. Paths stay within the
  retained root and its closed checksum inventory. Model fixtures are distinct.
- Execute both source ELF and transformed Native Image through the same
  `host-context-image-handoff` tool and `urp_entry` contract. Retain
  `source-handoff.json`, `handoff.json`, actual helper process exit codes,
  baseline/target stdout and stderr, `behavior-comparison.json`, and
  `behavioral-oracle.json`. Recompute equality from observations and bytes;
  flags alone are not an oracle. Entry 43 and process exit 43 are valid expected
  results for this helper, not generic process-success zero.
- Producer runtime identity measures native architecture, executing glibc
  version, uniquely mapped libc/loader, ELF64 little-endian AArch64 facts, and
  actual file hashes. Its canonical digest excludes `identitySha256` itself.
  Consumer validation checks bounded schema, canonical digest, recorded facts,
  hashes and row bindings without opening producer paths or measuring consumer
  libc. Portable metadata validation is not proof of another runtime execution,
  nor a promise that every standalone evidence directory is relocatable.
- Zero-fill is `not-applicable` without a tail and `not-run` for an unobserved
  tail. `observed` requires a retained read/assertion oracle. Current-thread
  `teardown` observes image release, not a TLS destructor or worker lifecycle.
- Unavailable rows claim no native/runtime execution identity or lifecycle
  observation. Pre-loader runtime-failure evidence may omit execution inputs;
  target-loader failure requires measured identity and Native Image inputs.
  A failed producer is not a published runtime-failure result.
- Wrappers adding files after generic rehydration must close and validate the
  positive child's `SHA256SUMS` after their additions, then close and validate
  the outer inventory. Do not mutate a historical root into passing evidence.

## 4. Validation & Error Matrix

| Condition | Required behavior |
| --- | --- |
| missing tuple/source/selector or mismatched model ownership | wrapper exits 2 before publication |
| stage relabeled, path/hash or runtime identity binding differs | evidence checker rejects |
| baseline missing, status/stream differs despite true equality flags | reject even after checksum regeneration |
| no-tail or unobserved zero-fill marked observed | reject unsupported observation |
| unavailable row invents native execution | reject |
| intact producer identity names files absent on consumer host | portable identity validation accepts |
| identity schema, ELF facts or canonical digest inconsistent | reject |
| wrapper adds child files after child inventory closes | finalized generic child checker rejects |

## 5. Good / Base / Bad Cases

- Good: four independently executed fixture rows bind measured outcomes and
  identities, and both child and outer evidence inventories verify.
- Base: a runtime or lifecycle tuple lacks transformed execution; retain its
  explicit unpromoted classification without borrowing the control artifact.
- Bad: fabricate empty baseline streams, infer success from literal flags, use
  one source for all models, or compare retained identity to the consumer libc.

## 6. Tests Required

- `tests/test_tls_runtime_matrix.py`: actual CI argument tuple and setup order;
  omitted non-IE inputs, wrong source/selector reject before publication.
- `tests/test_tls_runtime_evidence_oracle.py`: model/runtime/profile/lifecycle
  mismatch; changed baseline status/stream; missing streams/oracle; false
  equality; portable identity and tampered schema/digest/ELF/row bindings.
- `tests/test_protected_image_evidence.py`: conditional unavailable, accepted,
  and runtime-failure inputs; zero-fill and bounded PT_TLS facts.
- `tests/test_rehydration_evidence.py`: child inventory closure order. Run both
  generic positive-child and outer indirect-control checkers after production.
- Semantic negative tests must still reject after refreshing checksum manifests;
  a checksum mismatch alone does not exercise the semantic comparison gate.

## 7. Wrong vs Correct

```text
Wrong: baselineStatus = 0; stdoutEqual = true; label every row initial-exec.
Correct: execute source and transformed inputs, retain status/streams, bind the
         explicit row identity, and independently recompute comparisons.

Wrong: verify producer runtime by opening its absolute paths on the consumer.
Correct: measure mapped files in the producer, then validate canonical retained
         facts and row bindings portably without claiming a new execution.
```
