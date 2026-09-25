# Design: ELF model/parser refactor and common feature expansion

## Objective

Make the managed ELF representation extensible and add the first common
AArch64 feature slices selected from the real-sample histogram, while retaining
bounded, non-repairing parse behavior.

## Boundaries

Keep `ElfParser.Parse` as the public facade returning `ElfParseResult`. A shared
checked parse context owns input memory, `BoundedReader`, `LoadMap`, diagnostics,
and checked file/virtual conversions. Cohesive internal readers may own:

- ELF header/program/section tables;
- notes and program properties;
- PT_DYNAMIC entries and string metadata;
- relocation tables and relocation classification;
- dynamic symbols and symbol versions;
- semantic validation.

`ElfTypes` remains the typed model owner. Consumers reuse model records and
`LoadMap`; they do not reparse dynamic bytes or duplicate address arithmetic.

## Feature selection

The first feature family is chosen from the Stage 1 histogram using:

1. distinct-identity frequency, with 5% as the initial review trigger;
2. product value for outer or HostContext compatibility;
3. semantic/protection/lifecycle risk;
4. dependency on prior model or contract work;
5. positive fixture and native oracle feasibility.

The first slice is likely to involve common relocation/symbol/PLT metadata, but
the histogram and architecture audit decide the exact family. The child must
not pre-accept a family merely because it appears often.

## Feature contract

For each selected family:

- model observed bytes with typed records and bounded unknown representation;
- define static parser/validator invariants and stable diagnostics;
- state whether the outer profile, HostContext profile, or only observation
  applies;
- add a real linker/toolchain positive fixture;
- add a nearest-negative/malformed mutation;
- add managed tests and native/profile oracle if runtime behavior changes;
- update manifest feature status, evidence, report, and docs together.

The parser can preserve a known-but-not-supported form as data while the
validator or adapter rejects its semantics. This keeps future work from
requiring another byte-level parser rewrite.

## Performance and safety

Use checked arithmetic and bounded table ranges before allocation or conversion.
Keep unknown data bounded and do not create unbounded per-entry diagnostics.
Benchmark parse/validation before and after extraction and feature support. A
material regression requires explanation or a design change; adding a cache is
not automatic because input immutability and concurrency behavior matter.

## Rollback

Parser extraction can roll back independently while retaining characterization
tests. A feature implementation can roll back its validator/adapter acceptance
and matrix row while keeping its model observation and negative tests. The last
validated feature rows remain unchanged.
