# Design: architecture audit and quality foundation

## Objective

Create verified boundaries for future compatibility work while preserving the
currently released AArch64 support claims and observable behavior. This child
is an architecture foundation, not an opportunity to redesign every subsystem.

## Audit method

Trace four end-to-end flows:

1. ELF input -> bounded reader -> model/parser -> validator -> diagnostics and
   JSON/human report.
2. Input + launcher -> profile validation -> managed frame -> native frame
   parser -> outer execveat or HostContext dispatch -> status/evidence.
3. Public sample registry -> acquisition -> extraction/fingerprint -> isolated
   oracle -> evidence validation -> aggregate report.
4. Source changes -> unit/contract/fuzz/native fixtures -> CI tiers -> release
   artifacts and compatibility claim.

For each flow, record source-of-truth contracts, producers/consumers, duplicate
logic, error ownership, test coverage, and CI postconditions.

## Initial ownership boundaries to evaluate

- **ELF parser facade and parse context:** Keep `ElfParser.Parse` as the stable
  public entry point. Candidate internal components separate ELF header and
  program/section tables, notes, PT_DYNAMIC-derived records, relocation tables,
  symbol metadata, and semantic validation. Shared checked arithmetic and
  `LoadMap` remain canonical. Extraction is driven by testability/coupling,
  not by a desired class/file count.
- **Payload frame layout and codec stages:** Keep one layout owner per language
  and the existing managed/native drift gates. Separate header/version/profile
  validation, encoding, decoding, wrapper discovery, and decompression only
  where it creates clear contract/test boundaries. Avoid a second codec.
- **CLI boundary:** Preserve `CliApplication.Run`, stable exit codes, single
  JSON document behavior, and console ownership. Separate parse options,
  validate/pack command orchestration, report/human presentation, atomic report
  write, and Linux native handoff by responsibility.
- **Native HostContext adapter:** Preserve public HostContext ABI and native
  status values. Consider separate bounded metadata preflight, sealed-memfd
  resource ownership, system-loader adapter, exact symbol dispatch, and image
  release units. Keep handles cleared on every failed load and release exactly
  once on completed dispatch.
- **Native self-test helpers:** Put fixture creation and mutation utilities
  beside the self-test or in a dedicated test-only helper; group assertions by
  contract family. Production adapter logic must not become entangled with
  mutation code.
- **Evidence tooling:** Factor shared result-schema, hash, path-containment, and
  non-empty artifact checks only after identifying repeated semantics. Keep
  acquisition, execution, aggregation, and post-run gate responsibilities
  separable; do not build a generic script framework.

## Contract and characterization strategy

Before a selected extraction, capture:

- stable diagnostic code, severity, order, offsets, and representative message;
- golden report JSON and human/JSON stdout/stderr behavior;
- frame bytes, offsets, digests, name constraints, profile/version rejection;
- no-op/copy/pack output byte identity, atomic publish, and file modes;
- native status, handle zeroing, entry-at-most-once, release ordering, and
  launcher argv/env/cwd/fd/signal/stream behavior;
- manifest schema, result vocabulary, feature IDs, artifact path validation,
  and local no-network sample behavior;
- parse/validation/frame performance baselines for changed hot paths.

Use the existing test suites and extend them with the smallest characterization
test needed. Snapshot tests assert contract semantics rather than incidental
formatting or unstable addresses.

## Migration sequence

1. Finish the flow/contract inventory and run baseline tests.
2. Select the highest-value boundary using coupling, duplicate-owner,
   correctness-risk, and testability evidence.
3. Add missing characterization tests for that boundary.
4. Extract one responsibility while keeping public facades and behavior
   stable.
5. Run focused tests, full managed/native contract tests, script tests, and
   relevant fuzz/performance checks.
6. Delete the old implementation path once the new owner is proven; do not
   retain two production implementations.
7. Update durable specs and record remaining hotspots with owner and trigger
   for a later extraction.

## Source-of-truth decisions

The audit must decide, with a minimal migration, how to avoid drift among
managed C# frame constants and native C layout. Candidate choices are (a)
retain C# + C owners and strengthen generated/probe drift checks, or (b) use a
small declarative layout source to generate both sides and checks. Choose only
if generation reduces maintenance overall; code generation is not a goal by
itself.

Likewise, feature identifiers and result vocabulary should be single-owner
schemas only if a shared source can be consumed without duplicating validation
logic. The first step is inventorying current contracts, not creating a new
framework.

## Rollback

Each extraction is an independent change with characterization coverage. If
the new owner changes contract output, performance unexpectedly regresses, or
requires a parallel compatibility path, revert that extraction and retain its
audit findings. The AArch64 support matrix remains unchanged throughout this
child.
