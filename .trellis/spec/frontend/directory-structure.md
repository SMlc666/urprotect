# Frontend Directory Structure

## Scope

There is no frontend source tree in this repository. The product is a .NET
command-line application under `src/UrProtect.Cli/`; binary logic is under
`src/UrProtect.Core/`; scripts and native code are described by the backend and
repository layout guides.

There are no `components/`, `pages/`, `hooks/`, `stores/`, `assets/`, or browser
entry points to organize. Do not place CLI output, JSON report records, or ELF
models in a newly invented frontend directory.

## Future Frontend Work

Create a separate planning task before introducing a UI. Record the selected
framework and build tool, source root, route/page boundaries, shared modules,
generated API types, asset ownership, and test locations in this guide and its
companion documents. Keep a future UI's report/event decoding at a clear
boundary from the C# CLI contract.
