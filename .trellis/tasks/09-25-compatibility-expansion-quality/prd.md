# Expand AArch64 compatibility and refactor architecture

## Goal

Turn UrProtect into a substantially broader, evidence-backed AArch64 ELF
compatibility platform without sacrificing engineering quality. Expand the
real-sample ecology, common ELF feature support, outer and HostContext profile
coverage, and runtime environment matrix while treating architectural
modernization and legacy-code refactoring as first-class deliverables.

The outcome is not a larger whitelist. It is a coherent set of reusable
contracts, typed models, feature owners, runtime oracles, and evidence gates
that makes ordinary AArch64 software increasingly usable while keeping
unsupported combinations explicit and fail-closed.

## Background and confirmed repository facts

- The repository is an AArch64/ARM64-only .NET 8, native C, fixture, and CI
  product. This parent task does not add x86_64, RISC-V, ARM32, or another
  architecture backend.
- The completed compatibility roadmap already established current v3 packaging
  with explicit `outer-execveat` and `host-context-entry` profiles, bounded
  RELATIVE/RELR and GLOB_DAT slices, a bounded dependency/lifecycle slice,
  initial-exec TLS, GNU property evidence, and native glibc/musl/bionic facts.
- `fixtures/manifest.json` currently has 30 feature rows: 20 `validated`, 6
  `rejected`, and 4 `proven`. The rejected rows include unsupported
  interpreters, dynamic path search, text relocations, unsupported relocation
  tables, Android packed relocations, and symbol versions.
- `fixtures/real-samples/` currently contains a locked public corpus of 20
  upstream project identities. It is acquired only in CI and does not place
  raw binaries in the repository.
- The repository already requires bounded binary reads, typed address domains,
  stable diagnostics, byte-preserving output, profile-matched launchers,
  retained evidence, and no silent architecture/runtime fallback.
- Likely refactoring hotspots include the 1397-line
  `src/UrProtect.Core/Elf/ElfParser.cs`, 1034-line
  `src/UrProtect.Core/Pack/PayloadFrame.cs`, 871-line
  `src/UrProtect.Cli/CliApplication.cs`, 1174-line native
  `native/urprotect-runtime/host_adapter.c`, 1668-line native self-test, and
  several 250+ line evidence scripts. These are investigation anchors, not a
  license for a speculative rewrite; each refactor must be justified by a
  boundary, duplication, coupling, or testability problem.

## Product and scope decisions

1. **AArch64-first compatibility expansion.** Compatibility expansion remains
   inside AArch64 ELF and its Linux/glibc/musl/bionic runtime facts. A new
   architecture backend requires a separate product decision and task.
2. **Compatibility is layered.** Static observation, parser/model support,
   validator acceptance, outer execution, HostContext dispatch, and
   runtime-specific release claims remain separate statuses. A loader accepting
   an image does not by itself create a HostContext support claim.
3. **Profiles remain explicit.** `outer-execveat` and `host-context-entry` may
   expand independently because they have different process, loader, lifetime,
   and release semantics. No implicit profile or launcher fallback is allowed.
4. **Quality before breadth.** A feature is not complete when it merely passes
   one fixture. It needs an owned model rule, stable diagnostics, focused
   positive and nearest-negative tests, a runtime oracle where applicable,
   retained evidence, and maintainable code boundaries.
5. **Breaking-first 0.x evolution.** Frame, HostContext, CLI, report, fixture,
   and evidence contracts may change when a coherent current design requires
   it. Every producer, consumer, test, document, and evidence gate changes in
   the same contract update; obsolete production paths are not preserved by
   accidental adapters.
6. **Data-driven prioritization.** The first feature waves are selected from
   real-sample frequency, user value, semantic risk, and implementation cost.
   Rare features remain explicit `rejected` or `unknown` until their semantics
   are defined.
7. **Measured initial scale.** The program targets 100 distinct public
   upstream project identities, reached in quality-gated increments. The
   initial prioritization trigger is a feature present in at least 5% of
   distinct sample identities. Crossing that trigger requires explicit
   disposition and prioritization; it does not automatically authorize
   acceptance. Product-critical or contract-blocking features may be selected
   below the threshold with a documented rationale.
8. **Refactoring is a prerequisite, not deferred cleanup.** Complete the
   architecture/data-flow audit, add behavior characterization, and establish
   the first clear module/contract ownership boundaries before broad feature
   implementation starts. Feature slices then refactor the legacy hotspot they
   touch rather than stacking new logic into it.

## Requirements

### R1 — Establish an architecture and quality baseline

- Map the current managed, native, script, fixture, CI, and evidence data flow
  before feature implementation.
- Add characterization tests or contract probes for behavior that a refactor
  must preserve, including diagnostics, report schema, frame bytes, output
  identity, native status/stream behavior, and evidence classifications.
- Refactor legacy code only behind explicit ownership boundaries. Candidate
  boundaries include ELF table parsing and feature observation, frame layout /
  encode/decode, CLI option/command/output handling, native adapter preflight /
  loader/lifetime handling, self-test fixture mutation, and shared evidence
  tooling.
- Establish one source of truth for frame offsets, ELF address conversions,
  dynamic-tag interpretation, feature identifiers, result vocabulary, and
  evidence path validation. New code must reuse these owners.
- Preserve the current fail-closed behavior during each refactor. A structural
  refactor must not silently broaden acceptance or change a public diagnostic.
- Raise review quality: cohesive modules, explicit contracts, limited
  coupling, no copy-pasted feature logic, no giant new orchestration methods,
  no unchecked binary arithmetic, and focused tests for each changed boundary.

### R2 — Expand the public real-sample ecology

- Grow the locked public corpus in stages beyond the current 20 identities;
  the planning target is a substantially larger ecology with distinct project
  identities, producer/toolchain classes, runtime families, dependency shapes,
  hardening modes, TLS/symbol metadata, and rejected boundaries.
- Keep project identity separate from build/runtime variants. Variants are
  comparison attributes and must not inflate the identity count.
- Extend the fingerprint to expose observed ELF facts needed to prioritize
  compatibility work: relocations, PLT/GOT, dependency graph, symbol
  versions, TLS model, GNU properties, hardening, stripping, interpreter,
  page size, producer, and loader.
- Add an aggregate failure/feature report that maps each result to its first
  failing layer, diagnostic, feature cluster, runtime, and sample identity.
- Keep CI-only acquisition, hash/provenance checks, isolation, cleanup, and
  the existing distinction between `not-applicable`, expected outcomes,
  unexpected outcomes, runtime failures, and unavailable environments.

### R3 — Expand common ELF feature support

- Prioritize features from the real-sample histogram, beginning with common
  AArch64 relocation and symbol forms, PLT/GOT behavior, symbol versions,
  multi-entry dependency graphs, deterministic search policy, and TLS/lifecycle
  semantics.
- Separate `observed`, `modeled`, `accepted`, `validated`, and `released`
  states so parser recognition does not promote runtime compatibility.
- For every newly accepted feature, provide a real-toolchain positive fixture,
  a nearest-negative or malformed fixture, stable diagnostic behavior, and a
  runtime oracle when the feature affects loading, relocation, entry dispatch,
  memory protection, or release.
- Define dependency/path policy before accepting RPATH/RUNPATH, `$ORIGIN`,
  environment influence, filters, auxiliary dependencies, or broader search
  roots. Payload-controlled search must not become an accidental behavior.
- Define lifecycle ownership before expanding dynamic TLS, new-thread
  initialization, reentrancy, or release with live thread users.
- Keep unsupported forms rejected before loader handoff or execution side
  effects when their semantics are not defined.

### R4 — Expand the outer and HostContext profiles independently

- Outer profile: broaden AArch64 executable coverage where the native kernel /
  interpreter can execute the original bytes, and compare baseline versus
  wrapped behavior across status, streams, arguments, environment, cwd,
  descriptors, signals, and declared file observations.
- HostContext profile: broaden only declared entry images with explicit
  capability requirements, relocation/symbol/dependency/TLS/lifecycle
  semantics, and image ownership rules.
- Define separate support boundaries for dynamic PIE, static PIE, ET_EXEC,
  shared objects, sectionless images, stripped images, and interpreter forms;
  parseability must not imply launchability.
- Keep current v3/profile validation, stale-version rejection, launcher marker
  checks, sealed memfd handoff, and exactly-once entry/release guarantees.

### R5 — Expand the runtime environment matrix

- Build a covering array rather than an unbounded Cartesian product across
  glibc, musl, bionic, loader versions, kernel/page size, producer/toolchain,
  and ELF shape.
- Add representative older/current glibc and musl environments, a locked
  native bionic baseline, 4K and 16K page-size evidence, and the producer
  classes exposed by the real-sample corpus.
- Record host architecture, kernel, libc/loader identity, page size, toolchain,
  container/image digest, package locks, and isolation facts for every runtime
  claim.
- Keep PR, nightly, and release tiers semantically aligned. A missing runtime
  capability is explicit evidence failure, not a compatibility pass.

### R6 — Maintain engineering quality while expanding

- Every child deliverable must include an impact map across Core, CLI, native
  headers/runtime, fixtures, scripts, CI, reports, specs, and release evidence.
- Every refactor must state the preserved contract, the new owner boundary,
  migration order, rollback point, and validation commands.
- Refactoring may simplify or replace obsolete 0.x production paths, but it
  must not leave duplicate active implementations or compatibility shims with
  unclear ownership.
- Promote minimized fuzz findings into deterministic regression tests and keep
  malformed/negative coverage beside every newly accepted positive path.
- Update `.trellis/spec/backend/runtime-compatibility.md`,
  `.trellis/spec/backend/quality-guidelines.md`, and related directory/error
  contracts when the durable architecture changes.

## Proposed compatibility scale

The first expansion program uses staged targets rather than one vague
"support everything" milestone:

- **Ecology target:** grow from the current 20 to 100 distinct public project
  identities in reviewable increments. Each increment must preserve provenance,
  source/hash quality, ecosystem diversity, and CI isolation.
- **Feature target:** every feature cluster found in at least 5% of distinct
  project identities receives an explicit roadmap disposition and priority.
  New support still requires its own contracts and proof; frequency alone does
  not force acceptance.
- **Outer target:** every declared executable class has baseline/wrapper
  equivalence evidence on each claimed runtime family.
- **HostContext target:** common entry-image combinations have explicit
  capability, dependency, relocation, TLS, and lifecycle semantics; arbitrary
  shared-object support is not implied.
- **Runtime target:** representative current/older glibc and musl, a locked
  bionic baseline, and 4K/16K page-size facts are covered by retained oracles.

The 100-identity target and 5% trigger are approved planning baselines. The
first architecture audit and corpus histogram may recommend a recorded
revision, but changing either baseline requires an explicit parent-task review.

## Out of scope

- x86_64, RISC-V, ARM32, or another architecture backend.
- Universal Android device, OEM, SELinux, physical-device, or arbitrary-kernel
  compatibility claims.
- A general-purpose custom in-process loader without a separately approved
  HostContext contract, threat model, and lifecycle design.
- Payload encryption, anti-debugging, code virtualization, or a general code
  protection transformation.
- Accepting an ELF feature solely because a system loader happens to accept it.
- A repository-wide rewrite without characterization tests, an owner boundary,
  and a rollback path.

## Acceptance Criteria

- [ ] A baseline architecture/data-flow audit identifies legacy hotspots,
      duplicated contract owners, coupling, missing characterization tests,
      and the refactor order; no broad feature child starts before its required
      boundary is owned.
- [ ] Current managed, native, fixture, fuzz/stress, and evidence gates pass
      or have a documented environment-specific result before each expansion
      wave is judged.
- [ ] The real-sample corpus grows in approved increments, remains public,
      hash-locked, CI-only, and produces an aggregate feature/failure report.
- [ ] Each accepted ELF feature has a model owner, stable diagnostics, focused
      positive and nearest-negative tests, a runtime oracle where applicable,
      and retained matrix evidence.
- [ ] Outer and HostContext claims are reported separately and never promoted
      by loader acceptance alone; profile/launcher mismatch and stale frame
      versions fail clearly.
- [ ] Runtime claims are tied to recorded native AArch64 environments,
      covering-array selection, and non-empty evidence; unavailable runtime
      capabilities never become passes.
- [ ] Legacy code touched by this program is either refactored behind a clear
      owner boundary or explicitly documented with a follow-up task and
      containment rule. New feature logic does not accumulate in a known
      monolith without an extraction plan.
- [ ] No duplicate active parser/codec/feature/evidence implementation remains
      after each child is integrated; contract literals and address arithmetic
      have one owner.
- [ ] Full cross-layer validation, spec updates, and final compatibility report
      pass for every completed child; unresolved regressions keep the relevant
      child and parent open.

## Child-task map

The parent owns the source requirements, architecture-quality bar, target
calibration, cross-child integration, and final compatibility claim. Independently
verifiable children should be created during planning:

1. **Architecture audit and refactoring foundation** — characterize current
   behavior, define owners, extract shared evidence/contract utilities, and
   refactor the first legacy hotspots without changing claims.
2. **Real-sample expansion and failure taxonomy** — extend the public corpus,
   fingerprint, aggregation, and CI evidence model.
3. **ELF model/parser and common-feature expansion** — refactor parser/model
   boundaries and add the first frequency-driven relocation/symbol features.
4. **Outer profile compatibility expansion** — broaden executable classes and
   baseline/wrapper equivalence oracles.
5. **HostContext relocation/symbol/dependency expansion** — add capability
   semantics and runtime-backed entry-image support in dependency order.
6. **TLS/lifecycle and runtime matrix expansion** — define ownership/thread
   semantics and extend glibc/musl/bionic/page-size evidence.
7. **Final integration and release claim reconciliation** — synchronize matrix,
   reports, docs, specs, release smoke, and regression baselines.

Child ordering is expressed in each child's planning artifacts rather than by
assuming task-tree order: the architecture foundation precedes feature work;
sample/fingerprint work precedes frequency-driven support; outer profile work
can proceed before HostContext expansion; dependency semantics precede broader
TLS/lifecycle claims; final integration waits for all selected child gates.

## Confirmed planning decisions

- AArch64-only compatibility scope; other architectures remain separate work.
- Target 100 distinct upstream sample identities, staged by quality gates.
- Prioritize and explicitly disposition feature clusters present in at least
  5% of distinct identities; frequency never bypasses semantic proof.
- Architecture audit, characterization, and first ownership-boundary
  refactoring precede broad feature implementation; refactoring continues
  alongside each feature slice.
