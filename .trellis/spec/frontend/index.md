# Frontend Development Guidelines

## Current Scope

This repository has no frontend application. It contains a native ARM64
command-line product and CI tooling; there are no React/Vue components, pages,
browser hooks, client-side state stores, or frontend build configuration.

The frontend spec directory is retained because Trellis initializes a fullstack
spec layout. Its files document the current non-applicability rather than
inventing conventions for a technology the repository does not use.

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Frontend scope boundary | Not applicable |
| [Component Guidelines](./component-guidelines.md) | UI component scope boundary | Not applicable |
| [Hook Guidelines](./hook-guidelines.md) | Client hook scope boundary | Not applicable |
| [State Management](./state-management.md) | Client state scope boundary | Not applicable |
| [Quality Guidelines](./quality-guidelines.md) | Frontend tooling scope boundary | Not applicable |
| [Type Safety](./type-safety.md) | Frontend type scope boundary | Not applicable |

If a frontend is added, create a dedicated task to choose its framework,
directory layout, runtime validation, state model, accessibility requirements,
and test tooling before filling these documents.
