# Backend Development Guidelines

This repository is a .NET 8 command-line and binary-analysis product. The
backend layer is the production C# code under `src/UrProtect.Core/` plus the
CLI boundary under `src/UrProtect.Cli/`. It is not an HTTP service and it has
no database-backed application layer.

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Repository and namespace boundaries | Filled |
| [Database Guidelines](./database-guidelines.md) | Database scope and persistence boundary | Not applicable: no database |
| [Error Handling](./error-handling.md) | Diagnostics, failure propagation, and CLI exit codes | Filled |
| [Quality Guidelines](./quality-guidelines.md) | .NET, binary-safety, testing, and CI contracts | Filled |
| [Logging Guidelines](./logging-guidelines.md) | Diagnostics and stdout/stderr behavior | Filled; no logging framework |

## Package Boundaries

- `UrProtect.Core` owns binary reads, ELF models, AArch64 analysis, payload
  frames, pack validation, and the byte-preserving pipeline.
- `UrProtect.Cli` owns command parsing, stable product exit codes, human output,
  JSON report serialization, and the native `execve` handoff entry point.
- `tests/UrProtect.Core.Tests` owns unit, malformed-input, property, golden
  report, and pack integration tests.
- `native/`, `scripts/`, `fixtures/`, and `third_party/` are integration and
  supply-chain boundaries, not C# production namespaces.

All documents in this directory are written in English because they are loaded
by coding agents and reviewers as repository contracts.
