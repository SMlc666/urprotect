# Directory Structure

> How backend code is organized in this project.

---

## Overview

<!--
Document your project's backend directory structure here.

Questions to answer:
- How are modules/packages organized?
- Where does business logic live?
- Where are API endpoints defined?
- How are utilities and helpers organized?
-->

The repository is a .NET single-repository project. Production code is kept
under `src/`, tests under `tests/`, benchmark harnesses under `benchmarks/`,
small source fixtures and their manifest under `fixtures/`, and CI/helper
scripts under `scripts/` or `.github/`.

---

## Directory Layout

```
src/
├── UrProtect.Core/       # binary model, parser, validation, analysis
└── UrProtect.Cli/        # command-line boundary
tests/
└── UrProtect.Core.Tests/
benchmarks/
└── UrProtect.Benchmarks/
fixtures/
└── samples/             # deterministic source programs and Android fixture
scripts/
├── run-fixture-matrix.sh
├── install-native-toolchains.sh
├── run-android-avd.sh
└── validate-fixtures.py
third_party/
└── AsmStone/             # pinned upstream source and attribution
```

---

## Module Organization

<!-- How should new features/modules be organized? -->

Keep binary primitives, ELF parsing/modeling, architecture adapters, analysis,
and pipeline orchestration in separate namespaces/directories. Fixture
generation and external-tool invocation belong outside production parsing code.
The production project may reference the pinned AsmStone project, but the rest
of the codebase must depend on the project-owned AArch64 adapter rather than on
AsmStone types directly.

---

## Naming Conventions

<!-- File and folder naming rules -->

Use PascalCase for C# types and public members, camelCase for private fields and
locals, and names that identify address domains explicitly (`FileOffset`,
`VirtualAddress`, `RuntimeAddress`). Keep stable diagnostic codes in the
diagnostics module. Use one owner for shared range and mapping logic.

---

## Examples

<!-- Link to well-organized modules as examples -->

Use `src/UrProtect.Core/Elf/` for ELF models and parsing, and
`src/UrProtect.Core/Pipeline/NoOpPipeline.cs` for the current byte-preserving
orchestration boundary.
