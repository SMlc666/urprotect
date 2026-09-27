# Design: AArch64 compatibility expansion and architecture modernization

## 1. Design objective

Expand useful AArch64 ELF support using real software evidence while making the
codebase easier to extend safely. Compatibility growth and architecture quality
are coupled: each new feature should enter through a coherent owner boundary,
not as another condition in a monolithic parser, codec, CLI, adapter, or script.

The program follows this loop:

```text
locked public samples
  -> normalized ELF/runtime fingerprint
  -> feature-frequency and failure-layer report
  -> prioritized feature contract
  -> owner-boundary refactor + characterization tests
  -> positive and nearest-negative fixtures
  -> profile-specific native/runtime oracle
  -> evidence gate and compatibility claim
  -> updated real-sample classification
```

The supported claim stays layered:

```text
observed -> modeled -> statically accepted -> execution-validated -> released
```

Parser recognition, validator acceptance, outer-wrapper execution,
HostContext entry dispatch, and runtime-specific release claims remain distinct.
Existing `proven` / `validated` / `rejected` / `unknown` matrix statuses must
not be reinterpreted as equivalent to every maturity stage; if a schema change
is useful, it must explicitly represent both feature maturity and the layer
the evidence covers.

## 2. Baseline architecture and refactoring approach

### Current ownership map

| Area | Current principal owner | Refactoring risk / design direction |
|---|---|---|
| ELF parsing/model | `src/UrProtect.Core/Elf/ElfParser.cs`, `ElfTypes.cs`, `BoundedReader.cs`, `LoadMap.cs` | `ElfParser` is a 1397-line mixed orchestrator/table-parser/feature-parser. Preserve a small parse facade and move format-specific table readers into cohesive internal units that share one checked parse context and address mapper. |
| Frame wire format | `src/UrProtect.Core/Pack/PayloadFrame.cs`, `native/urprotect-runtime/include/urp/payload_frame.h` | Large managed codec contains layout and encode/decode behavior; managed/native layouts must remain byte-identical. Make layout and stage ownership explicit and retain `ContractLayoutTests`, `ContractInventory.md`, and native `contract-probe` as drift gates. |
| CLI | `src/UrProtect.Cli/CliApplication.cs`, `ProductReport.cs` | Command selection, argument parsing, input/output, reporting, and embedded handoff share one large type. Separate command option parsing, command orchestration, presentation, atomic report output, and Linux handoff without moving console ownership into Core. |
| HostContext native adapter | `native/urprotect-runtime/host_adapter.c`, `runtime.c`, public headers | Keep the public ABI stable at the boundary; separate metadata preflight, sealed-memfd ownership, loader handoff, symbol dispatch, and release into auditable internal units where useful. Preserve status and output-handle invariants. |
| Native tests | `host_context_self_test.c`, fixture C files, Makefile | Separate fixture construction/mutation helpers from assertions by contract family. Keep each mutation local, paired with an unchanged positive fixture, and retain pre-handoff assertions. |
| Evidence tooling | `scripts/validate-real-samples.py`, `check-real-sample-evidence.py`, `check-evidence.py`, runner and report scripts | Factor repeated schema, path, hash, and evidence validation behind shared owners. Avoid a generic framework: share only logic with real repeated contract ownership. |

### Refactoring rule

Use a characterization-first, slice-by-slice migration. Before changing an
owner, capture its existing observable contract: report JSON/golden output,
diagnostic code/order, frame bytes and offsets, output identity/publication,
native statuses/streams/dispatch order, manifest classifications, and
performance baseline where relevant. Then extract one responsibility, run the
full owning tests, and only afterward add or widen a feature.

File length alone is not a defect threshold. A hotspot is refactored when an
audit identifies mixed responsibilities, duplicated contract ownership,
change coupling, unsafe complexity, or inability to test a boundary
independently. Do not replace current code with a speculative generic
framework, a second active implementation, or a whole-repository rewrite.

### Cross-language contract ownership

The same ABI must be expressed in both C# and C, but it must have one
authoritative contract definition and a reliable drift check. The architecture
foundation evaluates a compact declarative layout source/code-generation option
against the existing managed constants + native header + probe approach. It
chooses the simplest maintainable owner; code generation is not mandatory.
Until a replacement is proven, existing layout tests, literal inventory, and
native contract probe remain mandatory.

## 3. Compatibility evidence architecture

### Real-sample identity and fingerprint

The registry counts distinct `projectId`/upstream identity, not variants. Each
fingerprinted artifact records a normalized value or explicit unknown for:

- ELF class, endianness, machine, type, interpreter, program/load layout,
  sectionless/stripped shape, page-size assumptions, and producer facts;
- `DT_NEEDED` graph and path-search metadata;
- RELA, RELR, PLT/GOT, relocation type/symbol index, dynamic binding flags;
- symbol table, symbol version requirements/definitions, TLS program header and
  model, GNU property, RELRO, GNU_STACK, and other selected hardening facts;
- oracle layer, expected and actual result, stable diagnostic, runtime/loader,
  and CI environment identity.

Raw artifacts remain CI-only, hash-locked, isolated, and removed. Fingerprint
output is normalized and bounded; the repository stores registry metadata and
reviewable aggregate evidence, never acquired executable samples.

### Frequency and failure taxonomy

For each feature cluster, count distinct project identities with a confirmed
observation. Variants of one project do not add weight. A cluster observed in
at least 5% of the approved corpus triggers explicit roadmap disposition and
priority review. The result can be:

- support candidate with named layer and proof plan;
- deliberate rejection with user/product rationale and stable boundary;
- deferred work with a named dependency or semantic blocker.

The threshold is a prioritization signal, not an acceptance criterion. A
lower-frequency feature may be selected for product importance, security,
contract completeness, or to unblock a common feature family; record why.

Each failure report names the first failing layer (`acquisition`, `fingerprint`,
`parse/model`, `static validation`, `outer`, `HostContext`, or `environment`),
diagnostic/result vocabulary, feature cluster, sample identity, runtime, and
artifact path. Environment-unavailable is not merged with product rejection.

## 4. Feature and profile architecture

### Feature owner contract

Each expanded feature has one owner and declares:

1. observed ELF facts and exact subset;
2. typed model/parser representation;
3. static validator rules and diagnostic behavior;
4. profile applicability (`outer-execveat`, `host-context-entry`, or both);
5. runtime and lifecycle semantics, including what is delegated to the system
   loader;
6. positive toolchain fixture and nearest-negative/malformed fixture;
7. real-sample impact identities and an execution oracle where applicable;
8. evidence row, constraints, and explicit unsupported combinations.

Relocation and dynamic-symbol work uses shared typed ELF records and checked
address mapping. Consumers must not reimplement dynamic table parsing or target
arithmetic. The HostContext adapter validates the profile contract before
system-loader handoff; successful loader acceptance alone cannot establish
support.

Dependency support is added only after an explicit policy defines graph
ownership, allowed roots, RPATH/RUNPATH and `$ORIGIN` behavior, environment
influence, symbol scope, rollback, and release order. TLS and lifecycle
expansion requires defined ownership for thread initialization, constructors,
entry dispatch, destructors, reentrancy, and image release.

### `outer-execveat`

The outer profile keeps the OS kernel and declared interpreter responsible for
loading source ELF bytes. Its oracle compares baseline and packed execution for
status, stdout/stderr, arguments/`argv[0]`, environment, cwd, inherited file
descriptors, signals, declared file observations, and stable loader failures.
Input class (dynamic PIE, static PIE, ET_EXEC, shared object, interpreter) is
declared independently; parseability does not imply launchability. A newly
accepted class must have a complete invocation contract and native execution
oracle.

### `host-context-entry`

HostContext supports declared `ET_DYN` entry images through explicit
capabilities and a profile-matched launcher. For each capability, specify
relocation/symbol scope, dependency policy, memory protections, TLS and
lifecycle ownership, failure behavior, and release order. Keep the sealed
anonymous image handoff and exactly-once entry/release contract. New behavior
must reject unsupported combinations before loader handoff or entry side
effects.

Neither profile implicitly falls back to the other. Their results and matrix
rows remain independent.

## 5. Runtime environment matrix

Use an explicit covering array to select high-value interactions between:

- runtime/loader: representative older and current glibc, at least two musl
  baselines, and a locked native AArch64 bionic baseline;
- kernel/page size: 4K and 16K evidence;
- producer: observed GCC/GNU ld, GCC/lld, Clang, Rust, Go, Zig, NativeAOT, and
  Android/Termux producers as applicable;
- artifact features: executable class, dependency shape, relocation family,
  symbol versions, TLS, hardening, stripping, and GNU properties.

The exact cells are selected after the corpus fingerprint. Do not create a
blind Cartesian product or infer unsupported combinations from untested
cells. Each row stores runner architecture, kernel, page size, runtime/loader
identity, container/image digest, packages/toolchain locks, isolation mode, and
retained evidence.

PR, nightly, and release tiers use the same registry and oracle semantics. PR
gates cover every selected contract witness and the required real-sample suite;
nightly expands repeatability and runtime cells; release validates every
environment claimed by that release. Missing capabilities stay `unknown` or
fail the declared lane; they never become compatibility passes.

## 6. Target architecture and cross-layer flow

```text
fixtures/real-samples registry
  -> isolated acquisition/hash verification
  -> static inspector + bounded fingerprint
  -> sample/layer oracle runners
  -> normalized result records
  -> evidence validator + feature/failure aggregator
  -> fixtures/manifest.json + rendered compatibility report
  -> feature child selection
  -> managed ELF model/parser + validator
  -> profile-specific packer/launcher/native adapter
  -> native glibc/musl/bionic oracle
  -> final evidence and docs
```

Ownership boundaries:

| Contract | Canonical owner and drift mechanism |
|---|---|
| ELF bytes/address mapping | `BoundedReader`, typed address values, `LoadMap`, and cohesive parser feature readers |
| ELF feature taxonomy | normalized fingerprint schema plus fixture feature IDs, validated against the compatibility manifest |
| Frame/HostContext ABI | selected canonical layout source, synchronized managed/native declarations, `ContractLayoutTests`, `ContractInventory.md`, and native `contract-probe` |
| CLI exit/report contract | CLI command boundary, typed report projections, golden JSON and exit-code tests |
| Sample result vocabulary and paths | shared evidence schema/validator used by acquisition, runners, aggregator, and CI postcondition |
| Runtime compatibility claims | `fixtures/manifest.json`, `COMPATIBILITY.md`, rendered report, evidence artifacts, and specs |

CI report generation must consume retained results instead of independently
recomputing compatibility semantics in multiple scripts.

## 7. Quality gates

Every refactor or feature change must pass the owning unit/contract tests and
relevant cross-layer gates. Quality review checks:

- single ownership of binary offsets, address conversion, feature/result
  vocabulary, and evidence rules;
- bounded arithmetic and parsing; no duplicate parser/loader/evidence logic;
- cohesive modules with dependencies pointing toward stable contracts;
- no new feature branch in an identified monolith without its planned
  extraction;
- stable diagnostics, reports, frame bytes, CLI behavior, and status mapping;
- negative tests, fuzz regressions, and runtime evidence on the correct layer;
- benchmark comparison for parse, validation, frame, and wrapper paths where
  affected; regressions are measured and explained rather than silently
  accepted;
- CI artifact completeness and source/runtime provenance.

No arbitrary line-count threshold substitutes for this review. New code should
remain analyzable by responsibility and testable without invoking unrelated
subsystems.

## 8. Rollout, dependencies, and rollback

1. Establish current behavior baselines and architecture/contract map.
2. Complete the first characterization and ownership-boundary refactors. This
   is the gate before broad feature implementation.
3. Extend sample fingerprinting and failure aggregation; grow the sample corpus
   toward 100 identities in reviewed increments.
4. Select features using the 5% identity-frequency trigger, product value,
   semantic risk, and dependencies.
5. Expand outer profile and HostContext feature contracts in separate slices.
6. Extend runtime covering-array rows as feature oracles require them.
7. Reconcile support claims, release evidence, docs, and specs.

Rollback is per slice. A failed refactor restores the old implementation while
keeping characterization tests. A failed feature slice removes or disables
only its new feature row and acceptance path; earlier validated capabilities
remain unchanged. Never publish a `validated` or `released` claim without its
positive/negative witnesses and retained oracle output.

## 9. Deferred decisions

The architecture foundation may determine whether code generation is the
simplest ABI single-source approach and which monolith to extract first after
characterization. The first corpus histogram chooses exact high-frequency ELF
features and the concrete runtime covering cells. These are implementation
decisions within the approved boundaries, not blockers to the program goal.
