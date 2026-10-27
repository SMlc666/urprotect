# Code Reuse and Ownership Guide

> Search for the existing owner before introducing another implementation.

## Before writing code

1. Search for the same operation, data contract, diagnostic, or test fixture
   with `rg` before changing or adding it.
2. Identify the existing owner and ask whether the change belongs there. Prefer
   extending one parser, codec, semantic projection, address map, layout writer,
   report projector, or evidence checker over creating a parallel path.
3. Follow the project's layer boundaries. In particular, consumers must not
   duplicate ELF address arithmetic, binary bounds checks, AArch64 instruction
   encoding, semantic ownership validation, or evidence-root accounting.
4. When several readers consume a serialized field, give the field one typed
   decoder/projection and have all readers use it.

## Useful rules of thumb

- Reuse is most important when logic carries safety, ownership, or format
  semantics. A second implementation can disagree on overflow, missing data,
  diagnostics, or unknown values.
- Extract a shared helper when logic is repeated, complex, or has multiple
  consumers. Do not build abstractions for a one-off trivial operation when
  they add more complexity than they remove.
- Keep constants, schema ordinals, limits, and field offsets at their contract
  owner. Update all dependent producers, consumers, tests, and documentation
  together when a contract intentionally changes.
- Use exhaustive switches for enums and state machines. In C#, prefer a switch
  expression or explicit arms that make new values visible to analyzers and
  reviewers; avoid broad defaults that silently assign an old behavior to a new
  state.
- Prefer one deterministic planner/materializer over a feature-specific writer
  that applies its own bytes or layout decisions.

## After a batch change

1. Search for remaining references to the old name, format, or behavior.
2. Check every producer and consumer, including fixture manifests, generated
   artifacts, evidence checkers, and CI commands.
3. Add a regression that fails if one path is updated without the others.
4. Review whether the tests assert independent behavior or merely restate a
   success flag or compare two values produced by the same helper.

## Before commit

- [ ] Existing ownership boundary was searched and reused where appropriate.
- [ ] No parallel parser, codec, address calculation, or writer was added.
- [ ] Contract constants have one owner and all consumers are synchronized.
- [ ] New enum/state values are handled exhaustively.
- [ ] Tests cover the valid case and the nearest malformed/unsupported case.
- [ ] Cross-file and registry changes are covered by a regression.
