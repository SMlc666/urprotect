# Database Guidelines

## Current Scope

This project has no database. It is a local binary validator and packer that
reads ELF files, emits reports, and publishes files atomically. There are no
ORM packages, `DbContext` types, migrations, connection strings, repository
interfaces, or database integration tests in the repository.

The absence of a database is intentional, not an unfinished implementation.
Do not add an ORM or database layer to store parser models, frame metadata, CI
evidence, or release provenance. Those values are represented by immutable
records, JSON reports, plain-text provenance files, and retained CI artifacts.

## Persistence Boundary

- `src/UrProtect.Core/Pipeline/NoOpPipeline.cs` reads a source snapshot and
  publishes a byte-identical output through a destination-local temporary file.
- `src/UrProtect.Core/Pack/ElfPackService.cs` reads source and launcher bytes,
  verifies the generated wrapper, then atomically moves the temporary output.
- `src/UrProtect.Cli/ProductReport.cs` serializes report records as JSON; it does
  not persist them through a data-access abstraction.
- `scripts/package-release.sh` and CI upload release/provenance files as build
  artifacts rather than inserting them into a store.

## Future Changes

If a future product requirement introduces a database, create a separate task
before adding it. That task must define the storage owner, schema and migration
tool, transaction behavior, retention policy, offline/CI behavior, and tests.
Until then, a database-specific guideline is not applicable to production code.
