# Test infrastructure and regression coverage design

## Design objective

Build a layered verification system around the existing managed, native, and
fixture boundaries. The design keeps product behavior stable: this task adds
test seams, named contract values, runners, evidence, and documentation; it
does not broaden the accepted ELF or HostContext contract.

## Workstream topology

The parent owns the contract map, shared CI/evidence integration, and final
cross-stream review. The implementation streams are:

1. `09-24-constants-and-assertions` — contract-value inventory, named owners,
   cross-language layout checks, and managed assertion helpers.
2. `09-24-coverage-guided-fuzzing` — SharpFuzz/libFuzzer targets, corpora,
   minimization, budgets, and fuzz evidence.
3. `09-24-concurrency-large-inputs` — deterministic concurrent-use and
   boundary/large-input suites with resource budgets.
4. `09-24-end-to-end-regression` — CLI/native/runtime scenarios and the
   machine-readable regression matrix across CI tiers.

The child artifacts state their integration ordering explicitly. The tree
itself is not treated as a dependency mechanism.

## Contract and constant architecture

### Ownership rules

- `ElfConstants` remains the managed owner of ELF values used by the parser and
  validator. `PayloadFrameCodec`, `HostContextContract`, and
  `LauncherContract` remain the managed owners of their public format/ABI
  values.
- The native runtime header remains the owner of the native HostContext and
  frame constants consumed by `runtime.c`; the launcher will consume shared
  named frame definitions rather than repeating header/trailer offsets.
- Test builders expose intentional sample values (for example, a synthetic
  program-header offset) through names tied to the fixture contract. Raw byte
  arrays remain raw only when their byte-level shape is the subject of the
  test.
- A cross-language contract probe/check compares the managed constants and
  native layout output for frame sizes, field offsets, ABI versions, and
  argument/context structure sizes. It detects drift without making a second
  implementation silently authoritative.

### Assertion architecture

The managed suite keeps xUnit and direct `Assert` calls. A focused test helper
layer covers only repeated domain semantics such as:

- asserting a diagnostic code and severity;
- asserting a successful/failed frame result while including all diagnostics;
- asserting byte identity and publication absence.

Helpers accept an explicit context label and input description so a parallel
or fuzz-derived failure remains actionable. Native C checks and Python
`unittest` stay idiomatic; shared contract IDs and evidence names provide the
cross-language consistency rather than forcing one assertion API onto every
language.

## Fuzz architecture

The first coverage-guided implementation uses SharpFuzz `2.3.0` with its
libFuzzer bridge, built or supplied from a pinned `libfuzzer-dotnet` source
revision. The source and package licenses are retained in the existing
provenance/third-party evidence path. The target is a separate .NET console
project so fuzz execution does not change the normal xUnit process.

Two target modes have separate corpora and coverage runs:

- `elf`: invoke `ElfParser.Parse` on bounded input and treat returned
  diagnostics as normal results; unexpected exceptions are crash findings.
- `payload-frame`: invoke frame/wrapper decoding with a deliberately bounded
  `PayloadFrameLimits` instance and exercise encode/decode invariants for
  inputs that reach the encoder. Malformed data remains a normal decode result;
  unexpected exceptions, timeouts, and excessive resource use are findings.

The runner instruments only project-owned assemblies, applies `-max_len`,
`-rss_limit_mb`, `-timeout`, `-runs`/`-max_total_time`, a fixed seed for smoke
mode, and an artifact prefix. A PR run uses a short deterministic corpus
smoke; nightly runs merge/minimize the corpus and use a longer wall-clock
budget. A missing compiler, bridge, or instrumented assembly is an explicit
failed fuzz capability, not a green skip. Existing deterministic random and
mutation tests remain as cheap no-throw regressions.

Corpus layout is stable and reviewable:

```text
tests/FuzzCorpus/elf/{seed,malformed}/...
tests/FuzzCorpus/payload-frame/{valid,invalid}/...
.artifacts/fuzz/<target>/{logs,crashes,timeouts,corpus,environment}/
```

Any crash or timeout promoted to the repository gets a named regression test
and a small minimized input. Generated exploratory corpus files stay in CI
artifacts unless they are intentionally promoted.

## Concurrency and large-input architecture

Managed tests are tagged `Concurrency` and `LargeInput` and use fixed worker
and iteration counts in PR mode. Shared inputs are immutable; each operation
gets independent output storage. The suite compares diagnostics, model shape,
encoded bytes, and copy identity against a serial oracle. It does not assert
thread safety for stateful objects without a documented reusable contract.

Boundary tests use the smallest custom `PayloadFrameLimits` that exercises an
exact limit and limit-plus-one rejection. Selected multi-megabyte parser and
frame cases run under a process timeout and a documented memory ceiling; the
nightly profile amplifies workers, iterations, and sizes. The test harness
records seed, worker count, input size, profile, elapsed time, and allocation
observations. It avoids brittle per-machine microbenchmark thresholds.

Filesystem/process cases use per-test temporary directories and verify no
partial output after failure. Process-level timeouts are enforced by scripts;
library-level tests assert deterministic results and stable diagnostics.

## End-to-end and evidence architecture

Existing scripts remain the execution authority for native and platform paths.
The new regression matrix is a small machine-readable map (separate from the
compatibility manifest) with, for each case, its command, tier, platform
requirement, budget, expected status, and artifact paths. A validator rejects
missing rows, unsupported tier names, and claims that lack an execution
witness.

The matrix covers:

- managed CLI validation, JSON, exit codes, no-op identity, and publication
  failure;
- native packed launcher and managed anonymous handoff behavior;
- HostContext native self-test and rejected-boundary checks;
- existing glibc fixture, packed fixture, musl, bionic, and optional Android
  native-bridge commands.

PR runs the managed and native smoke rows available on the runner. Nightly
runs add full fuzz, stress, and fixture rows. Release runs repeat the existing
compatibility/package evidence. Optional Android capability remains explicitly
unavailable when prerequisites are absent; it is never converted into a
native ARM64 support claim.

## CI and rollback shape

- The PR build keeps deterministic unit/property tests, coverage floor checks,
  fuzz smoke, small concurrency/large-input smoke, and existing required
  evidence.
- Nightly owns long fuzz exploration, corpus minimization, stress amplification,
  and slow platform rows. Release retains packaging and compatibility evidence
  and may reuse the nightly artifacts where the workflow already does so.
- All new jobs upload logs and manifests with `if: always()`. Failure artifacts
  remain available even when a capability check fails.
- Each stream is independently revertible: removing its job or runner leaves
  the current production and legacy compatibility paths unchanged. The final
  integration check prevents partial matrix entries from being presented as
  complete coverage.
<!-- End of task artifact. -->
