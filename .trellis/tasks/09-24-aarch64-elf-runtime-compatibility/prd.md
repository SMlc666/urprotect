# Expand AArch64 ELF Compatibility and Runtime Semantics

## Goal

Make UrProtect a coherent ARM64/AArch64-only ELF validation, packaging, and
runtime-handoff product whose compatibility grows through explicit, reproducible
evidence rather than through an unbounded whitelist. The parent task covers the
full P0-P4 roadmap and coordinates independently verifiable child deliverables.

The project intentionally does not pursue x86_64 or any other architecture.
"ARM64" in product language refers to the existing AArch64 ELF/ABI target; it
does not imply Android framework or physical-device support unless a matrix row
proves that narrower claim.

## Background and confirmed repository facts

- The codebase currently targets AArch64 ELF64 and has separate managed, native
  launcher, native runtime, fixture-matrix, and compatibility-evidence layers.
- `PayloadFrameCodec` currently defines legacy frame format v1 and HostContext
  frame format v2. The native HostContext ABI is currently version 1.
- Native HostContext v2 frame dispatch and the narrow memfd/system-loader
  adapter have validated evidence, including glibc, musl, and bionic slices.
- The production managed pack path intentionally emits v1 to the legacy
  launcher, while `runtime.host-context.production-pack` remains `unknown` in
  `fixtures/manifest.json` and `COMPATIBILITY.md`.
- The project is in 0.x rapid development. Breaking changes are acceptable and
  preferred over carrying legacy production paths when the current contract is
  replaced coherently.
- Existing evidence distinguishes parser/model support, wrapper execution
  support, HostContext adapter support, and runtime-specific claims. New work
  must preserve that distinction.

## Product decisions

1. **ARM64-only scope.** No new architecture backend is part of this parent
   task. AArch64 ELF rules, relocations, launchers, fixtures, and runtimes are
   the scope.
2. **Breaking-first 0.x policy.** The current frame, HostContext, launcher, CLI,
   report, and fixture contracts may change. A contract change must update all
   producers, consumers, tests, documentation, and evidence together. Old
   production paths do not need compatibility adapters.
3. **Single current packaging contract with explicit profiles.** The roadmap
   must converge on one current versioned frame and packaging contract. It may
   expose explicit execution profiles because standalone PIE execution and
   HostContext entry-image dispatch have different image-lifetime semantics:
   `outer-execveat` and `host-context-entry`. Legacy v1 may be retained only as
   historical evidence during transition and must not be selected implicitly.
4. **Evidence before claims.** A feature is not supported merely because a
   system loader accepts it. Each accepted feature needs a model rule, positive
   fixture, negative boundary, execution oracle where relevant, and retained
   evidence.
5. **Layered compatibility.** The roadmap expands outer wrapper compatibility
   before expanding in-process HostContext ELF semantics. Shared objects,
   static images, dependencies, constructors, TLS, and GNU properties each need
   explicit execution semantics before acceptance.

## Documentation ownership

- Durable project rules belong in
  `.trellis/spec/backend/runtime-compatibility.md`: AArch64-only scope,
  breaking-first 0.x evolution, one current packaging contract with explicit
  profiles, layered claims, and the evidence rule.
- This parent PRD owns the P0-P4 roadmap, cross-phase acceptance criteria, and
  child-task map. It is the planning source for the compatibility expansion,
  not a substitute for the executable runtime contract.
- `COMPATIBILITY.md` and `fixtures/manifest.json` own the current product
  claim and retained evidence status. They must describe observed support rather
  than future intent.
- Each child task owns its concrete feature subset, signatures, error matrix,
  fixtures, validation commands, and rollback point in its own planning
  artifacts.

## Scope: P0-P4 phases

### P0 — Converge the current ARM64 contract

- Select and document one current frame format and packaging contract with
  explicit `outer-execveat` and `host-context-entry` dispatch profiles.
- Connect managed pack and the matching profile-specific launcher/adapter into
  complete managed end-to-end oracles: the outer profile recovers the original
  executable through `execveat`, while the HostContext profile loads an entry
  image, resolves `urp_entry`, dispatches once, and releases the image.
- Remove or archive legacy production branches that are no longer part of the
  current contract; stale v1 behavior or profile/launcher mismatches must fail
  with a clear version/status result rather than being silently selected.
- Update the compatibility matrix, reports, fixtures, and documentation so the
  former production-pack `unknown` row is either validated by the new oracle or
  explicitly re-scoped to a later phase.

### P1 — Expand outer AArch64 ELF wrapper compatibility

- Broaden accepted AArch64 ELF64 inputs where the kernel/native interpreter can
  execute them without requiring HostContext to interpret new in-process
  semantics.
- Cover sectionless and stripped images, realistic PT_LOAD layouts and
  alignments, GNU RELRO/STACK/PROPERTY variants where the declared outer
  execution path can preserve their behavior, and representative GCC, Clang,
  Rust, Go, Zig, musl, glibc, bionic, and NativeAOT outputs already relevant to
  the repository.
- Define support separately for dynamic PIE, static PIE, static ET_EXEC, and
  shared objects; do not infer launchability from parseability.
- For each accepted class, compare baseline and wrapped behavior including exit
  status, stdout, stderr, arguments, environment, signals, and relevant file
  observations.

### P2 — Expand AArch64 relocation and symbol semantics

- Define and implement the next prioritized AArch64 relocation and symbol forms
  beyond the current checked RELATIVE/RELR slice.
- Specify symbol lookup scope, visibility, binding timing, weak symbols,
  symbol conflicts, and writable-target/protection rules before accepting forms.
- Keep unsupported relocation-table, Android-packed-relocation, and
  symbol-version forms as explicit rejected boundaries until their semantics are
  implemented and evidenced.
- Add real toolchain fixtures and mutation-based negative tests for every newly
  accepted or rejected family.

### P3 — Define dependency, path-search, and image lifecycle semantics

- Define the HostContext contract for DT_NEEDED, dependency graphs, search
  roots, RPATH/RUNPATH precedence, environment influence, symbol scope,
  dependency sharing, failure rollback, and release ownership.
- Define constructor/destructor ordering, failure behavior, reentrancy, and the
  relationship between lifecycle callbacks and `urp_entry`/`release_image`.
- Implement only the subset that can be made deterministic and reproducible;
  reject all other forms before loader handoff.
- Add dependency-bearing and lifecycle-bearing positive fixtures plus paired
  rejection and teardown oracles.

### P4 — Add TLS and GNU property semantics

- Define TLS module allocation, current-thread and new-thread initialization,
  TLS relocation models, thread/reentrancy behavior, unload safety, and teardown
  relative to image release before accepting PT_TLS.
- Define GNU property negotiation, including relevant BTI/PAC/instruction-state
  obligations and memory-protection responsibilities, before accepting
  PT_GNU_PROPERTY forms.
- Implement and validate only a deliberately bounded ARM64 subset; retain
  fail-closed rejection for unspecified combinations.
- Add concurrent/threaded fixtures and property-bearing fixtures with retained
  runtime evidence for every supported runtime claim.

## Out of scope

- x86_64, RISC-V, ARM32, or any other architecture backend.
- A claim of universal Android device, OEM, SELinux, kernel, or physical-device
  compatibility.
- Payload encryption, anti-debugging, code virtualization, or a general-purpose
  anti-reversing transformation unless separately approved as a new product
  direction.
- Treating arbitrary shared objects as executable programs without a declared
  entry/lifecycle contract.
- Enabling an ELF feature solely because glibc, musl, bionic, or `dlopen`
  happens to accept it.

## Cross-phase acceptance criteria

- [ ] The parent has a reviewed P0-P4 design, implementation order, child-task
      map, and explicit dependencies.
- [ ] The project has one documented current packaging contract with explicit
      execution profiles, and stale versions or profile/launcher mismatches are
      rejected clearly.
- [ ] Every accepted compatibility feature has an owner, model rule, positive
      witness, negative boundary, execution oracle where applicable, and retained
      matrix evidence.
- [ ] Every unsupported or deferred feature remains fail-closed and is labeled
      `rejected` or `unknown`; unknown rows never count as support.
- [ ] The ARM64 compatibility matrix distinguishes outer-wrapper, HostContext,
      and runtime-specific claims.
- [ ] Full managed, native, fixture, fuzz, and matrix validation passes for each
      completed phase; no phase is marked complete with unresolved regressions.
- [ ] The final documentation states the supported ARM64 boundary and the
      intentionally excluded architecture/platform claims.

## Child-task map

The parent owns roadmap requirements, cross-phase contracts, integration review,
and final matrix/doc reconciliation. Independently verifiable implementation
deliverables should be created as children during planning:

1. P0 — converge current ARM64 production contract.
2. P1 — expand outer AArch64 ELF wrapper coverage.
3. P2 — expand AArch64 relocation and symbol semantics.
4. P3 — define and implement dependency/path/lifecycle semantics.
5. P4-A — define and implement AArch64 TLS semantics.
6. P4-B — define and implement GNU property / BTI / PAC semantics.

The children are ordered by dependency even though the task tree itself is not a
dependency mechanism: P1 depends on the P0 current contract, P2 depends on the
P0/P1 evidence shape, P3 depends on the P2 symbol model, and P4 depends on the
P3 lifecycle and ownership semantics. P4-A and P4-B may be designed in
parallel after P3, but each remains independently gated by its own runtime
oracle. The exact MVP slice for each child is a planning decision recorded in
that child's artifacts.

## Blocking open questions

None. The parent is ARM64/AArch64-only, the current packaging model uses one
versioned contract with explicit `outer-execveat` and `host-context-entry`
profiles, and the child PRDs define the first independently verifiable slices.
P0 owns the exact current frame field layout; that implementation detail is a
child-level design gate rather than a blocker for the parent roadmap.
