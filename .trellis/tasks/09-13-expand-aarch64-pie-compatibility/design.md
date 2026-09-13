# Technical Design

## Compatibility Layers

The child separates three claims that the current validator conflates:

1. format compatibility: the parser can model the input safely;
2. runtime-image compatibility: the image satisfies HostContext mapping and
   entry obligations;
3. behavior compatibility: the HostContext entry behaves equivalently under
   the declared host contract.

An ordinary executable with a valid _start or main is not runtime-compatible
merely because it is ET_DYN. It must expose the explicit entry contract or be
adapted before the runtime claim is made.

## Feature Inventory

The inventory is grouped by proof obligation rather than operating system:

- identity: ELF64, little endian, AArch64, ET_DYN, version, flags;
- layout: program-header bounds, PT_LOAD ordering, alignment, file/memory
  sizes, entry mapping, sectionless operation;
- image metadata: PT_DYNAMIC, PT_INTERP, PT_TLS, PT_GNU_STACK,
  PT_GNU_RELRO, PT_GNU_PROPERTY, notes, and dynamic strings;
- relocation: RELA forms, RELR forms, Android packed forms, addends, target
  ranges, and supported AArch64 relocation classes;
- symbols: hash data, dynamic symbols, symbol versions, undefined dependencies;
- lifecycle: constructors, destructors, TLS, unwind/property requirements, and
  HostContext entry behavior;
- producers: the existing GCC, Clang, Rust, Go, Zig, NativeAOT, and Android
  NDK cases, selected only when they exercise a distinct feature.

Each feature identifies the owning parser/model, runtime obligation, positive
case, negative case, and deterministic oracle.

## Validator and Model Changes

The existing BoundedReader, LoadMap, address-domain types, and parser
diagnostic model remain the single owners of binary range handling. New
features extend those owners rather than duplicating arithmetic in the runtime
or fixture scripts.

ElfValidator gains explicit distinctions for:

- structurally malformed data;
- structurally valid but unknown data;
- parser-model compatible data;
- HostContext runtime-compatible data.

Unknown relocation kinds, unsupported GNU properties, unresolved dependency
forms, or lifecycle requirements without a Host Contract semantic remain
warnings/errors according to the existing diagnostic policy and cannot be
classified as proven.

## Fixture Strategy

The existing compiler cases are retained as format and behavior baselines.
New HostContext cases use a small common entry adapter so the test exercises
the selected ABI rather than relying on compiler-specific _start behavior.

Fixtures are chosen by feature coverage:

- one minimal image for each new segment/layout rule;
- one relocation/lifecycle image for each new runtime obligation;
- one malformed mutation nearest to each accepted case;
- one producer case only when it introduces a distinct ELF shape.

The matrix generator records the feature IDs exercised by each artifact. A
fixture that runs successfully but exercises no new feature does not expand the
compatibility claim.

## Proof and Oracles

Static/model checks prove ranges, address mappings, metadata consistency, and
required capability declarations. Runtime checks compare HostContext results,
return codes, declared output, memory/lifecycle events, and diagnostics against
the baseline oracle. Timing, ASLR addresses, host paths, and incidental loader
addresses are excluded.

Every feature status is determined by the strongest available evidence:

- proven requires the invariant and runtime obligation to be documented and
  checked;
- validated requires deterministic execution evidence with an explicit
  remaining host assumption;
- rejected requires a stable reason and no runtime entry;
- unknown means no claim.
