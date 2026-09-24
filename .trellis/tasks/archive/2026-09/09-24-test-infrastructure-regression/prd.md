# Build test infrastructure and regression coverage

## Goal

Make the repository's test system a deliberate regression net for binary-format
and runtime-boundary changes: remove duplicated protocol/layout magic numbers,
make assertions consistent and diagnostic, add reproducible coverage-guided
fuzzing, exercise concurrency and large inputs within explicit resource
budgets, and verify the real CLI/native/runtime paths end to end.

The value is not merely a higher percentage. A failure must identify the
contract it violated, be reproducible from retained input and seed data, and
run at an appropriate PR, nightly, or release tier.

## Confirmed repository facts

- The managed test project is xUnit on .NET 8 and already references
  `coverlet.collector`; the current tests use xUnit `Assert` calls with several
  repeated diagnostic idioms.
- Protocol and ELF constants already have partial owners in
  `src/UrProtect.Core/Elf/ElfTypes.cs`, `Pack/PayloadFrame.cs`, and
  `Pack/HostContextContract.cs`, while tests, scripts, and native self-tests
  also contain independent offsets, sizes, tags, and sentinels.
- `tests/UrProtect.Core.Tests/ElfParserFuzzTests.cs` currently provides fixed
  seed random and mutation loops. `scripts/run-parser-fuzz.sh` runs that target
  with environment-controlled iteration counts and a wall-clock timeout, but
  it is not coverage-guided and does not retain a minimized corpus contract.
- CI already has separate PR, nightly, release, native ARM64 glibc/musl,
  bionic, packed-launcher, HostContext, and optional Android native-bridge
  paths. The new tests must fit those tiers rather than making slow or
  architecture-specific work a mandatory PR gate without an explicit budget.
- Existing end-to-end entry points include the fixture matrix, packed fixture
  matrix, native launcher scripts, managed anonymous handoff script, and
  native HostContext self-test. The production managed HostContext pack path
  remains an explicitly documented unknown and must not be silently promoted
  by test-only scaffolding.
- The native tests use local C check helpers and compile-time assertions; the
  Python matrix tests use `unittest`. The initial assertion-style target is
  therefore the managed xUnit suite, with cross-language helpers changed only
  when a concrete duplicated contract justifies it.

## Requirements

### R1. Constants and contract ownership

- Inventory numeric literals that encode ELF, payload-frame, HostContext,
  launcher, ABI, fixture, or test-harness contracts across C#, C, Python, and
  shell code.
- Establish one authoritative owner for each cross-file contract and named
  test/fixture constants for intentional wire-format examples. Replace
  duplicated production/test layout values with named constants or builders
  without hiding meaningful sample data behind opaque helpers.
- Add a consistency check where a C# and native ABI/layout contract must stay
  byte-compatible. Preserve legacy frame behavior and existing compatibility
  boundaries.

### R2. Assertion convention

- Keep xUnit as the managed test framework and standardize managed tests on
  direct `Assert` forms with failure messages that identify the relevant
  contract, input, and expected boundary.
- Introduce a small number of domain-specific assertion/building helpers only
  for repeated semantics (for example, diagnostic-code or frame-result
  checks); do not create a second assertion framework or blanket wrappers
  around every xUnit call.
- Keep native and Python conventions explicit and idiomatic for their
  languages, while sharing names and contract identifiers where tests cross
  language boundaries.

### R3. Coverage-guided fuzzing

- Select and document a coverage-guided fuzzing approach compatible with the
  pinned .NET 8 toolchain and repository licensing/build constraints. The
  first targets are bounded ELF parsing/validation and payload-frame
  decode/encode boundaries; additional targets require a demonstrated signal
  or bug class.
- Seed the fuzzer with valid minimal ELF, malformed corpus, and valid/invalid
  payload-frame cases. Enforce input-size, execution-time, memory, and total
  run budgets.
- Retain crash, timeout, and minimized regression inputs as repository-owned
  corpus artifacts or a deterministic generated-corpus format. Every promoted
  finding becomes a normal regression test.
- Keep a fast deterministic smoke target for PRs and a longer corpus/coverage
  target for nightly or release rehearsal. Do not label fixed random mutation
  loops as coverage-guided.

### R4. Concurrency and large-input regressions

- Test concurrent use of stateless parser, validator, frame codec, and no-op
  pipeline APIs with shared immutable inputs and independent mutable outputs.
- Add cancellation/timeout and failure-isolation checks where the API exposes
  filesystem or process boundaries; do not invent thread safety guarantees for
  stateful objects that are not documented as reusable.
- Exercise inputs near configured limits and selected multi-megabyte/large
  cases for parser, frame, copy, and report paths. Verify bounded allocation,
  no integer overflow, deterministic results, and no partial publication.
- Define CI-safe time and memory budgets, with stress amplification reserved
  for nightly jobs. Failed stress runs must retain enough seed/configuration
  information to reproduce locally.

### R5. End-to-end regression matrix

- Cover the observable CLI contract: validation success/failure, stable exit
  codes, JSON output, no-op byte identity, output publication failure, and
  pack rejection boundaries.
- Cover the real native launcher and managed handoff where the host supports
  AArch64, including payload integrity, `argv[0]`, stdout/stderr, exit status,
  signal status, repeated deterministic packing, and no executable temporary
  pathname.
- Exercise existing fixture-matrix, packed-fixture, HostContext, musl, bionic,
  and optional Android native-bridge paths through their existing evidence
  scripts. Distinguish unavailable environments from skipped assertions and
  keep the documented compatibility statuses unchanged unless the required
  oracle is genuinely present.
- Publish a machine-readable test/evidence summary mapping each regression
  class to its test, tier, platform, budget, and retained artifact.

### R6. CI and maintenance contract

- Keep PR checks deterministic and bounded; place coverage-guided exploration,
  high-volume concurrency, large stress cases, and slow platform paths in
  nightly/release tiers unless a small smoke variant is appropriate.
- Make failures actionable: preserve fuzz seed/corpus, stress parameters,
  platform manifest, logs, and native artifacts on failure.
- Update test/spec documentation and the relevant Trellis backend quality
  guidance when a new reusable testing convention is established.

The agreed CI policy is deterministic smoke plus a small fuzz/concurrency
budget on PR; full corpus exploration, concurrency amplification, and the
largest inputs nightly; and release runs that repeat compatibility and
packaging evidence without adding nondeterministic exploration gates.

## Acceptance Criteria

- [x] A checked-in inventory and reviewable diff show that contract-encoding
      magic numbers have named owners or explicit fixture/sample annotations;
      no legacy frame or ABI behavior changes unintentionally.
- [x] Managed tests use the agreed xUnit assertion convention, repeated
      contract checks use focused helpers, and failures include useful
      diagnostics without introducing a parallel assertion library.
- [x] A real coverage-guided fuzz target runs against at least ELF parsing and
      payload-frame decoding, has deterministic PR smoke and longer-tier modes,
      enforces budgets, and retains/promotes minimized failures as regressions.
- [x] Concurrent and large-input suites verify deterministic, bounded,
      byte-preserving behavior and publication safety at documented boundary
      sizes; stress settings and observed budgets are recorded.
- [x] CLI, packed-launcher, managed handoff, HostContext, fixture-matrix, and
      applicable native runtime E2E checks pass in their supported tiers, with
      unavailable optional environments reported explicitly.
- [x] CI uploads the new reports and failure artifacts, and a matrix maps each
      requirement to commands, tiers, and evidence.
- [x] `dotnet test --configuration Release`, Python regression tests, native
      self-tests available on the current host, and the repository's relevant
      lint/coverage/evidence checks pass.

## Scope boundaries and deferred items

- This task improves verification and test infrastructure; it does not claim
  new runtime compatibility, implement the production HostContext v2 pack
  migration, or change the supported ELF/payload contract merely to make a
  test pass.
- Fuzzing is not an excuse to remove deterministic regression cases or to make
  every PR run unbounded exploration.
- Broad performance benchmarking, sanitizer/toolchain upgrades, and physical
  Android-device testing are follow-ups unless planning research shows they are
  required to satisfy one of the acceptance criteria.

## Notes

- Keep `prd.md` focused on requirements, constraints, and acceptance criteria.
- This is a complex parent task; finalize `design.md` and `implement.md` before
  activation, then create independently verifiable child tasks for the four
  implementation streams.
