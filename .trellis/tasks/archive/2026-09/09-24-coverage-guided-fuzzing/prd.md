# Add coverage-guided fuzzing

## Goal

Add a genuine, reproducible coverage-guided fuzz layer for ELF parsing and
payload-frame boundaries, with bounded PR smoke, deeper nightly exploration,
and retained minimized failures.

## Requirements

- Use a pinned, license-tracked .NET 8-compatible coverage-guided engine; the
  current recommendation is SharpFuzz 2.3.0 with its libFuzzer bridge.
- Add an isolated fuzz console project with separate ELF and payload-frame
  targets. Expected malformed-input results remain normal; unexpected
  exceptions, timeouts, and resource-limit violations are findings.
- Seed from valid minimal ELF, malformed corpus, and valid/invalid frame
  vectors. Enforce maximum input, timeout, RSS, and total-run budgets.
- Retain crash/timeout/minimized outputs and promote each accepted finding to a
  deterministic regression test.
- Keep existing deterministic random/mutation tests and make toolchain or
  bridge absence explicit in CI evidence.

## Ordering and integration notes

The target can be developed independently, but it should consume the contract
names and fixture builders published by `09-24-constants-and-assertions`
before final integration. It must not broaden parser or frame acceptance to
make fuzzing quieter.

## Acceptance Criteria

- [x] A real coverage-guided runner executes both target modes and records the
      engine, package/source revisions, compiler, seed, corpus, and budgets.
- [x] PR smoke is deterministic and bounded; nightly mode performs longer
      corpus exploration/minimization with failure artifacts.
- [x] Fuzz input size and process RSS/time limits are enforced, and unavailable
      prerequisites are reported as capability failures rather than green
      skips.
- [x] Promoted crashes/timeouts have minimized checked-in regressions; the
      existing deterministic fuzz suite still passes.
<!-- End of task artifact. -->
