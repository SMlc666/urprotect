# Technical Design

## 1. Product Boundary

The product exposes one packaged AArch64 ELF runtime contract. It does not
expose operating-system profiles, vendor modes, or a choice between Linux and
Android implementations.

The packaged artifact is an AArch64 ELF64 ET_DYN runtime image containing:

1. a position-independent native runtime core;
2. a versioned payload frame and integrity metadata;
3. a payload image that conforms to the explicit HostContext entry ABI.

The host's ordinary native loader may load the outer runtime image. The
recovered payload must not be written as an executable temporary pathname and
must not be launched through a synthesized process-startup environment.

Existing arbitrary standalone PIE programs remain useful as parser and
compatibility inputs, but they are not automatically HostContext images. A
runtime compatibility claim requires an explicit entry adapter or a build that
exports the HostContext ABI.

## 2. Data Flow

Source ELF -> bounded parser and feature classification -> HostContext entry
validation -> deterministic frame encoder and integrity digests -> outer ET_DYN
runtime plus frame -> host loader maps outer runtime -> runtime discovers and
verifies its embedded frame -> runtime decodes payload into bounded memory or a
host-backed immutable object -> Host Contract maps/resolves the payload without
an executable pathname -> runtime resolves the versioned entry symbol -> runtime
calls urp_entry(HostContext, LaunchArgs).

The C# layer remains the policy and publication owner. Native runtime code owns
only frame discovery, bounded decoding, integrity checks, host handoff, and
entry dispatch. ELF address arithmetic remains owned by the shared LoadMap and
address types in Core.

## 3. HostContext ABI

The first ABI is a C-compatible, fixed-width, versioned structure:

- a version and structure-size prefix;
- capability bits and opaque host userdata;
- function pointers for bounded memory allocation/mapping, protection changes,
  dependency/image loading, symbol lookup, diagnostics, and lifecycle cleanup;
- explicit ownership and lifetime rules for every returned pointer or handle;
- no C++ objects, language-runtime exceptions, host allocator ownership, or
  platform-specific structs across the boundary.

The payload entry has the conceptual form:

    int32_t urp_entry(const urp_host_context_v1 *host,
                      const urp_launch_args_v1 *args);

The exact public names and field layout are frozen in the child runtime design
before implementation. Structures use size/version negotiation so a new host
can reject an older or truncated table without reading beyond the declared
size. Entry invocation is single-owner by default; reentrancy, thread
creation, TLS, and callback-after-return behavior are explicit contract fields
rather than accidental consequences of a libc startup path.

The runtime core must not emulate ELF process startup, construct a kernel
initial stack, or call an arbitrary payload main function. A payload that needs
those semantics requires a separately declared adapter and is not implicitly
covered.

## 4. No-Temporary-Path Handoff

The Host Contract has one abstract immutable-image handoff operation. A
concrete host may implement it with an anonymous file descriptor, an FD-backed
linker extension, or an anonymous memory mapping, but the contract must
guarantee:

- no payload-controlled path is used;
- no executable temporary pathname is required;
- decoded bytes remain immutable after integrity verification;
- the mapped image lifetime extends through entry execution;
- all writable-to-executable transitions are explicit and bounded;
- failure occurs before entry invocation and returns a stable diagnostic.

The first design should prefer an existing platform loader through a host
adapter over reimplementing every system dependency resolver. A custom
in-process ELF loader is a separate escalation point: it is required only if
the Host Contract cannot provide the needed immutable-image loading semantics.
The matrix must mark that escalation as unknown until relocation, TLS,
constructors, symbol resolution, RELRO, and instruction-property behavior are
specified.

## 5. ELF Compatibility Model

The accepted input language is factorized into independent feature rows:

- ELF identity and header invariants;
- program-header and load-map shape;
- section-table presence or absence;
- interpreter and dynamic dependency metadata;
- relocation encodings and supported AArch64 relocation kinds;
- TLS, GNU stack/RELRO/property notes, and BTI/PAC declarations;
- dynamic symbol/version data;
- entry/lifecycle behavior required by HostContext;
- compiler/toolchain and optimization cases.

Program headers and LoadMap are authoritative for runtime mapping. Section
headers enrich reports but are not required for a valid runtime image unless a
specific HostContext feature explicitly needs one.

Each row is assigned one of:

- proven: static/model invariants and implementation obligations are complete;
- validated: deterministic execution evidence exists but the proof is
  conditional on an unformalized host behavior;
- rejected: the runtime intentionally fails closed;
- unknown: no compatibility claim is allowed.

The matrix uses feature interactions and a documented covering strategy instead
of a blind compiler-by-feature Cartesian product.

## 6. Matrix and Naming Migration

The existing fixture manifest uses a project-owned top-level profiles array and
scripts accept --profile. The new schema calls records matrix cases. PR,
nightly, release, and manual selection are run tiers; glibc and musl are
runtime facts or package variants; Android image details are host/environment
facts. Cargo's external profile.release syntax is not changed.

Bionic is the same kind of runtime fact as glibc and musl. Its native evidence
case uses the Termux Docker AArch64 source commit
7033c7639eb86107a4fdf8b72bd6388c07b1284a and image digest
sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4.
The case records the bionic linker, kernel, page size, and no-fallback checks
as host facts. It does not claim Android framework or device behavior.

The matrix manifest is the single source of truth for:

- case and feature identifiers;
- toolchain, runtime, and artifact facts;
- HostContext contract version;
- proof status and obligations;
- positive and negative fixtures and oracles;
- retained evidence paths.

Validation rejects duplicate IDs, missing evidence fields, contradictory
statuses, unsupported combinations, and claims with only an unclassified
runtime pass.

## 7. Compatibility and Migration

Wrapper frame v1 and the current temporary-extraction launcher are retained as
legacy regression baselines while the new runtime ABI is introduced. A new
frame/runtime version is used if HostContext metadata cannot be represented
without ambiguity in the existing v1 header; this is a format migration, not a
platform profile.

The packer must reject an ordinary standalone PIE that lacks the HostContext
entry contract instead of silently treating its _start or main as equivalent.
The compatibility matrix records the distinction between:

- format/parser compatible;
- HostContext runtime compatible;
- legacy wrapper baseline only;
- rejected or unknown.

Migration is staged so a failed new runtime path can be disabled without
removing the existing validator and legacy wrapper evidence.

## 8. Proof and Test Boundaries

The proof obligations are layered:

1. frame and payload byte identity;
2. ELF structural and address-range invariants;
3. image mapping, relocation, and lifecycle semantics under Host Contract;
4. entry-call observational equivalence for HostContext payloads;
5. deterministic matrix status and evidence publication.

Device or emulator runs are witnesses for a host implementation. They do not
upgrade an unknown row to proven. Reports distinguish model/proof checks,
deterministic native execution, and optional translated or emulated execution.
Bionic Termux userspace execution is deterministic native implementation
evidence for the bionic linker boundary, but it remains narrower than Android
framework/device evidence and cannot upgrade those rows.

Failures use existing stable DiagnosticCode categories where possible. New
categories are added only when callers need to distinguish ABI mismatch,
host-capability absence, image-load failure, or entry-contract failure. Core
returns structured diagnostics; CLI and native boundaries own output.

## 9. Rollback

The migration is reversible at three boundaries:

- matrix schema migration can retain a compatibility reader for old fixture
  manifests until all scripts and CI use matrix cases;
- packer selection can continue producing legacy v1 wrappers while the new
  runtime is gated behind an explicit HostContext input;
- a failed runtime feature row is moved to unknown or rejected without
  weakening already-proven rows.

No partial runtime implementation is allowed to silently replace the legacy
path or change the existing validator's acceptance results.
