# Technical design: unified ELF protection rewriting infrastructure

## Design goal

Build one production pipeline that transforms selected AArch64 functions, relocates all declared semantic dependencies, plans a legal ELF layout without a PT_NULL prerequisite, regenerates runtime metadata, and publishes a behaviorally verified Native Image. `protect` is a facade; `protect-image` and `rehydrate-image` expose the same stages explicitly.

## Boundaries and data flow

```text
ElfParser / ElfValidator / LoadMap
  -> AArch64 semantic IR and source ownership model
  -> ProtectionRewritePlan
       - transformed instruction blocks
       - old/new address map
       - direct and indirect target sets
       - literals and jump tables
       - ELF/TLS relocation edits
       - CFI/unwind edits
  -> ElfLayoutPlan
       - program-header table
       - PT_LOAD/segment placements
       - veneers and pools
       - file/virtual address map
  -> NativeImageMaterializer
       - emit bytes and metadata
       - apply fixups
       - atomic publication
  -> parser/readelf/loader/behavior validators
```

`ProtectionRewritePlan` owns semantic movement. `ElfLayoutPlan` owns physical placement. The materializer consumes both; neither mutates the source model while planning.

## Semantic IR

Add project-owned records around the existing AsmStone adapter. Every instruction retains source address/file offset/raw encoding plus decoded operands, implicit register/flag effects, control-flow classification, PC-relative expression, literal reference, TLS reference, relocation binding, and unwind effect. The IR distinguishes exact targets, bounded target sets, runtime-resolved targets, and unresolved targets.

The address map covers source functions, basic blocks, literal pools, jump tables, veneers, relocation sites, and generated code. Passes operate on this model and produce semantic fixups rather than embedding final addresses early.

## Layout plan

The planner considers all legal placements through one API. A PT_NULL entry is merely an available resource, not a separate production path. Candidate strategies include:

1. extend a compatible executable PT_LOAD;
2. place code in a planned executable region with an existing legal mapping;
3. relocate/expand the program-header table and add a new RX PT_LOAD;
4. allocate near veneers and long-branch sequences when direct Branch26 range is insufficient.

The plan validates alignment congruence, file/virtual non-overlap, load ordering, PT_PHDR visibility, PT_INTERP/PT_DYNAMIC/PT_TLS/RELRO/STACK/PROPERTY/NOTE preservation, section-header movement, and bounded output size before emission.

## Semantic relocation

The first-class fixup model covers direct/conditional branches, BL/calls, ADR/ADRP pairs, literal loads, jump-table entries, GOT/PLT references, TLS models, and dynamic relocation records. Branch relaxation chooses Branch26, near veneer, or long-address sequence based on the planned address map. External targets preserve their PLT/GOT or declared runtime binding.

Indirect control flow is represented as exact targets, bounded sets, or runtime target translation. Jump tables carry base, entry width, encoding, bounds, default target, and target ownership. An unresolved target keeps the operation in a deterministic pre-publication failure state unless the declared runtime target map can preserve it.

## TLS and runtime matrix

TLS is modeled from PT_TLS, dynamic metadata, instruction sequences, GOT/TLSDESC records, and relocation types. The same semantic plan is exercised through separate native glibc, musl, and bionic lanes. Each lane retains compiler/linker/runtime identity, baseline/protected streams/status, per-thread values, zero-fill, lifecycle, and loader evidence.

The first complete milestone claims all three runtimes separately. A result on one runtime never promotes another runtime.

## CFI/unwind

Add bounded CIE/FDE and `.eh_frame_hdr` models. Source ranges map to trampoline and transformed ranges; generated code receives CFI derived from its prologue/epilogue, dispatcher, register permutation, and veneer effects. Recoverable malformed records are canonicalized; records whose semantics cannot be recovered follow a stable diagnostic or regeneration contract. Runtime fixtures exercise backtrace, exception, cancellation/signal unwind, and register/frame restoration.

## Artifact and CLI compatibility

Protected Image v1 remains historical migration evidence. The current producer artifact evolves to a versioned operation contract capable of carrying semantic fixups, address maps, relocation/TLS edits, veneer/pool placement, and CFI edits. `protect-image` publishes it with role/stage/checksum evidence. `rehydrate-image` consumes it. `protect` invokes the same Core workflow in one command and publishes only the final output unless an evidence directory is requested.

The old direct writer is removed from production behavior after the unified path passes migration oracles. It is not retained as a runtime fallback.

## Verification and safety

Every stage is bounded and immutable until the final writer. The output is reparsed by the project parser, checked with readelf where relevant, and run against an unprotected baseline. Tests compare status, stdout, stderr, signals, declared files, TLS observations, unwind/exception observations, and target-selection outcomes. No output or evidence set is published after a failed stage.

## Trade-offs

- Full PHDR/layout rewriting broadens ELF coverage but increases loader and file-offset risk; the planner therefore records an explicit strategy and rejects malformed or semantically ambiguous layouts before writing.
- Runtime target translation increases indirect-control-flow coverage but requires a declared runtime contract and additional native evidence.
- CFI repair can preserve more inputs than rejection, but only canonicalized rules with known semantics may be promoted.
- Three-runtime evidence increases CI cost; it is required by the selected scope and is kept as separate feature rows rather than a single blended compatibility claim.

## Dependency ordering

The semantic IR/address map and layout-plan contracts precede feature implementation. The semantic relocation child supplies the shared fixup model; the layout child supplies materialization; indirect/jump-table, TLS, and CFI children add their domains; the workflow child integrates all producers and runtime evidence. Child artifacts must repeat these ordering constraints because the task tree itself is not a dependency mechanism.
