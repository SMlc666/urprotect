# Evidence recovery checkpoint (2026-10-14)

The parent remains in progress. This checkpoint records bounded independent
reviews, not full-parent acceptance or new runtime/profile/lifecycle support.
No changes were committed or staged by these recovery lanes.

## Verified slices

- TLS measured oracle and integration: original per-row identity and fabricated
  baseline P1s corrected; actual CI caller, explicit wrapper inputs, portable
  runtime-identity consumers, and finalized indirect child checks independently
  PASS. Matrix root `.artifacts/tls-runtime/oracle-integration-final-20261014T092753Z/`
  has 60 classified rows and exactly four promoted models: initial-exec,
  local-dynamic, general-dynamic, TLSDESC, each glibc HostContext current-thread.
  Other tuples are not transformed-execution evidence.
- TLSDESC reserved-slot P2: actual three physical dynamic entries are checked,
  all-zero reservation required, byte preservation/atomic-failure tests pass.
  Independent private clean build matches source SHA-256
  `fa5fd0c9f9c0ce01262b9d2a9c0f16a50cb6dfbb5d1f94440eab669520cbbf5b`.
  Fresh E2E root `.artifacts/tls-runtime/tlsdesc-reserved-slots-e2e-20261014T101845Z/tlsdesc.host-context-entry.glibc.current-thread/`
  passes source/transformed status 43 and retained evidence gates.
- Bionic package-merge test isolation only: independently PASS. Test-owned
  stage inventory replaces global `/tmp` snapshots, real dropped-UID shell
  and security predicates retained, unrelated-stage and owned-leak tests pass.
  Production `scripts/bionic_node_runner.py` was unchanged by that slice.

## Validation limits and unresolved child failures

Writer's final full Python run: 339 tests PASS, log
`.artifacts/bionic/merge-isolation-python-full-20261014T104117Z.log`.
Reviewer independently reran six focused Bionic methods; the full run is
retained writer evidence, not an independently rerun suite.

These historical failures remain unexplained and must not be marked root-cause
closed by the isolated cleanup fix or by green repetitions:

1. Full337 regular-to-regular merge returned status 1 with empty stderr:
   `.artifacts/tls-runtime/validation-logs/tlsdesc-reserved-slots-python-full-20261014T101054Z.log`.
   Its global leak assertion did not fire; the child returned a CompletedProcess.
2. Intermediate parallel special-payload case returned nonzero without the
   expected diagnostic:
   `.artifacts/bionic/merge-isolation-parallel-2-20261014T103803Z.log`.

The initial Bionic review output accidentally repeated the earlier TLSDESC
review. It was rejected by the supervisor. The substantive corrected review is
`/root/.pi/agent/sessions/--root-urprotect--/subagent-artifacts/outputs/c3cb7e61-6424-4160-b704-26931d0fa243/reviews/bionic-merge-gate-isolation-review-1.6f945538.md`.

## Next parent acceptance work

- Genuine C++ exception throw/catch through a mapped transformed CFI frame;
  the current `exceptionBoundary` is C setjmp/longjmp, not C++ unwinding.
- Remaining TLS model/profile/runtime/lifecycle execution and lifecycle oracles.
- Full indirect-target/ambiguous-jump-table acceptance, beyond narrow passing
  jump-table consumer evidence.
- Bring compact-eight-word wording in `tls-rewrite.md` in sync with the
  implemented full-function versus descriptor-sequence ranges, without
  expanding support merely by changing documentation.
- Preserve the unresolved Bionic child-exit risk for later reproduction.
