# Frontend Quality Guidelines

## Scope

This repository has no frontend build, lint, browser test, component test, or
accessibility test suite. Its quality gates are the .NET tests, native launcher
tests, fixture matrices, and CI checks documented in
`../backend/quality-guidelines.md`.

Before frontend work begins, record the framework and directory decision,
then define linting, formatting, type-checking, unit/component tests, browser
E2E coverage, and accessibility checks. Do not mark a frontend quality
requirement as covered by the current CLI tests.
