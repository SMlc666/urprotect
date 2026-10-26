# Engineering Knowledge Base

This directory is the durable, project-owned source for implementation
contracts and cross-layer engineering guidance. It is not a task tracker or
evidence archive.

## Specs

- [Backend development guidelines](./specs/backend/index.md) — .NET, ELF,
  AArch64 semantics, safety, test, evidence, and runtime contracts.
- [Frontend development guidelines](./specs/frontend/index.md) — records that
  this repository currently has no frontend application and defines the gate
  before one is introduced.
- [Thinking guides](./specs/guides/index.md) — project-applicable code reuse
  and cross-layer reasoning checklists.

## Ownership and maintenance

- Product behavior, binary safety, evidence schemas, and runtime-compatibility
  requirements live in these specifications and their linked source contracts.
- Active work is tracked in [Superpowers plans](../superpowers/plans/), not in
  this directory.
- Archived task artifacts remain available in Git history; they are not
  current specifications or current acceptance state.
- When code changes a documented contract, update the owning specification,
  its tests and fixture/evidence consumers in the same change. Keep runtime
  classifications and unavailable evidence explicit; documentation or hosted
  checks alone do not promote product support.
