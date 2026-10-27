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
- A TLSDESC BLR is TLS-owned only after rehydration rechecks the source static
  relocation carriers, module/symbol, dynamically projected descriptor owner,
  and the complete decoded source instruction/register sequence against the
  canonical snapshot. An R_AARCH64_TLSDESC_CALL label alone is insufficient.
  Ordinary indirect-call owner completeness still applies to every other BLR.
  Source function matching accepts the planner's exact
  `Table:TableIndex:0xVA` identity plus its source VA/size; existing name-based
  identities still require the exact source VA/size. Neither lookup may select
  a nearest symbol or ignore the source function range.
- On a failed promoted-row subprocess, `run-tls-runtime-matrix.py` writes
  `failures/ROW/runner-result.json` with failed status, actual process status,
  nullable firstFailureStage and retained diagnostics; it preserves both runner
  streams and an allowlist of stage files before temporary-work cleanup.
  `retainedSha256` binds retained bytes; each file is capped at 1 MiB and every
  capped file is named in `truncatedFiles`. Skip symlink stage files, reject
  row path escape and existing failure directories. These are failure
  diagnostics, not a successful matrix or published runtime-failure row; no
  successful matrix inventory is manufactured.
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
  In the TLS matrix, generate each promoted child directly under the durable
  aggregate root, retain its complete original publication tree and paths, add
  the matrix facts, and run both Protected Image and rehydration checkers after
  re-closing the child inventory. Retain the child's `SHA256SUMS` in its
  `evidencePaths` and the outer inventory. Copying only stage/behavior facts
  from a disposable runner directory is not a self-contained publication row.

## 4. Validation & Error Matrix

| Condition | Required behavior |
| --- | --- |
| missing tuple/source/selector or mismatched model ownership | wrapper exits 2 before publication |
| missing/forged TLS call marker, descriptor owner, source chain or function identity | reject before Native Image; other BLRs require their ordinary owner |
| promoted producer exits nonzero with empty stderr | preserve process status, both streams and stage diagnostics outside temporary work; matrix fails |
| source ownership passes but output-word layout is invalid | preserve the independent layout rejection; source ownership is not publication approval |
| stage relabeled, path/hash or runtime identity binding differs | evidence checker rejects |
| baseline missing, status/stream differs despite true equality flags | reject even after checksum regeneration |
| no-tail or unobserved zero-fill marked observed | reject unsupported observation |
| unavailable row invents native execution | reject |
| intact producer identity names files absent on consumer host | portable identity validation accepts |
| identity schema, ELF facts or canonical digest inconsistent | reject |
| wrapper adds child files after child inventory closes | finalized generic child checker rejects |
| aggregate child loses roles/streams or points into deleted work | do not accept as a self-contained publication row; retain the original durable tree and validate both child gates |

## 5. Good / Base / Bad Cases

- Good: four independently executed fixture rows bind measured outcomes and
  identities, and both child and outer evidence inventories verify.
- Base: a runtime or lifecycle tuple lacks transformed execution; retain its
  explicit unpromoted classification without borrowing the control artifact.
- Bad: fabricate empty baseline streams, infer success from literal flags, use
  one source for all models, or compare retained identity to the consumer libc.

## 6. Tests Required

- `tests/test_tls_runtime_matrix.py`: actual CI argument tuple and setup order;
  omitted non-IE inputs, wrong source/selector reject before publication; mocked
  empty-stderr/nonzero producer retains stage and both streams after temp
  cleanup, bounded truncation, symlink exclusion, path escape and overwrite refusal;
  finalization retains original role/stream/stage bytes, hashes matrix additions
  before both child gates, and propagates a failing gate instead of publishing
  a successful aggregate.
- `TlsLocalExecWorkflowTests`: composite function identity reaches TLS layout,
  while the minimal eight-word synthetic fixture retains its existing
  `TlsLayoutMismatch` rejection; missing bindings, forged identities, refreshed
  source call markers/descriptor relocations/register chains publish no Native
  Image. The real-linker native glibc TLSDESC row is the end-to-end positive.
  Keep static-callback and dynamic-import owner omission regressions green.
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
