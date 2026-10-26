# Repository guidance

## Project workflow

This repository uses the project-local Superpowers package declared in
`.pi/settings.json`, pinned to the reviewed upstream commit. Follow its
brainstorming, writing-plans, executing-plans, test-driven-development,
systematic-debugging, and verification-before-completion skills where they fit
the work. Use the current project plan under `docs/superpowers/plans/` as the
source of task scope and progress; keep acceptance criteria explicit and do not
mark open work complete because a narrower test passed.

For substantial or ambiguous work, clarify the requirement and obtain approval
before implementation. Write or update a plan, then execute its steps in order.
Use test-first changes when practical, run focused tests after each change, and
run the relevant full checks before reporting completion. Do not commit, push,
or perform destructive repository operations unless the user has authorized
them.

## Durable engineering contracts

The maintained engineering specifications are indexed at
[`docs/engineering/specs/README.md`](docs/engineering/specs/README.md). Read the
relevant specifications before changing code. In particular:

- `docs/engineering/specs/backend/` defines ELF, AArch64, evidence, runtime,
  and quality contracts.
- `docs/engineering/specs/frontend/` defines frontend conventions.
- `docs/engineering/specs/guides/` contains shared design and review guidance.

Tests and evidence checkers are part of these contracts. Preserve bounded
parsing, fail-closed behavior, exact evidence provenance, and the distinction
between local test results, hosted observations, and promoted support claims.

## Delegation and repository safety

Use the installed Pi sub-agent facility only when the task or user authorizes
delegation; keep one writer per working tree and use isolated worktrees for
parallel writers. Review delegated changes independently before integration.
Do not overwrite unrelated working-tree changes. Preserve project-local settings
and keep machine-specific global paths out of committed configuration.
